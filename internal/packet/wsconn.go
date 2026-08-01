// WebSocket (RFC 6455) carrier for the TCP transport. A wsConn is a net.Conn that presents a plain byte
// STREAM while framing every write as a binary WebSocket frame and de-framing reads, so connFramer rides
// on top unchanged. The point is CDN-frontability: the client reaches a CDN edge over wss:// with an
// allowed domain's Host/SNI and the CDN proxies to our origin. The client masks, the server does not.
package packet

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// wsGUID is the RFC 6455 magic value mixed into Sec-WebSocket-Accept.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

var errNotWS = errors.New("ws: not a websocket upgrade")

// wsConn wraps a stream conn with WebSocket binary framing, presenting a byte
// stream. r is the buffered reader that already consumed the HTTP handshake, so
// any bytes read past it (an eager first frame) are not lost.
type wsConn struct {
	net.Conn
	r      *bufio.Reader
	client bool   // clients MUST mask outbound frames (RFC 6455 §5.3)
	rbuf   []byte // leftover payload from the current inbound frame
	wmu    sync.Mutex
}

// Read returns de-framed payload bytes as a stream. WebSocket control frames are
// handled transparently: a ping is answered with a pong, a pong is ignored, a close
// ends the stream. Data opcodes (binary/text/continuation) carry our bytes.
func (c *wsConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		payload, opcode, err := readWSFrame(c.r)
		if err != nil {
			return 0, err
		}
		// A control frame (close/ping/pong) MUST carry <=125 bytes (RFC 6455 §5.5); a larger one is a
		// malformed/hostile peer — drop the connection rather than echo a big pong or trust it.
		if opcode >= 0x8 && len(payload) > 125 {
			return 0, errDesync
		}
		switch opcode {
		case 0x0, 0x1, 0x2: // continuation / text / binary — data
			c.rbuf = payload
		case 0x8: // close
			return 0, io.EOF
		case 0x9: // ping -> pong
			_ = c.writeWSFrame(0xA, payload)
		case 0xA: // pong — ignore
		default: // reserved/unknown opcode (0x3-0x7, 0xB-0xF) — a conforming peer never sends these
			return 0, errDesync
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// Write sends p as a single binary WebSocket frame.
func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeWSFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeWSFrame emits one WebSocket frame (FIN set). The write lock keeps a control
// pong (sent from Read) from interleaving bytes with a data frame.
func (c *wsConn) writeWSFrame(opcode byte, payload []byte) error {
	n := len(payload)
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|opcode) // FIN + opcode
	var maskBit byte
	if c.client {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		hdr = append(hdr, maskBit|byte(n))
	case n < 65536:
		hdr = append(hdr, maskBit|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, maskBit|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	body := payload
	if c.client {
		var key [4]byte
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			return err
		}
		hdr = append(hdr, key[:]...)
		body = make([]byte, n)
		for i := 0; i < n; i++ {
			body[i] = payload[i] ^ key[i&3]
		}
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.Conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := c.Conn.Write(hdr); err != nil {
		return err
	}
	_, err := c.Conn.Write(body)
	return err
}

// readWSFrame reads a single WebSocket frame and returns its payload and opcode.
// Server-received frames must be masked (RFC 6455 §5.1); we unmask them. Frame
// size is bounded so a peer cannot force a huge allocation.
func readWSFrame(r *bufio.Reader) (payload []byte, opcode byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return nil, 0, err
	}
	opcode = h[0] & 0x0f
	masked := h[1]&0x80 != 0
	n := int(h[1] & 0x7f)
	switch n {
	case 126:
		var e [2]byte
		if _, err = io.ReadFull(r, e[:]); err != nil {
			return nil, 0, err
		}
		n = int(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err = io.ReadFull(r, e[:]); err != nil {
			return nil, 0, err
		}
		n = int(binary.BigEndian.Uint64(e[:]))
	}
	if n < 0 || n > maxFrame*2 {
		return nil, 0, errDesync
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return nil, 0, err
		}
	}
	buf := make([]byte, n)
	if _, err = io.ReadFull(r, buf); err != nil {
		return nil, 0, err
	}
	if masked {
		for i := 0; i < n; i++ {
			buf[i] ^= mask[i&3]
		}
	}
	return buf, opcode, nil
}

// wsAccept computes the Sec-WebSocket-Accept value for a client key.
func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsClientHandshake performs the HTTP Upgrade against host/path and returns the
// buffered reader (holding any post-handshake bytes) for the wsConn to frame from.
func wsClientHandshake(conn net.Conn, host, path string, deadline time.Time) (*bufio.Reader, error) {
	if path == "" {
		path = "/"
	}
	var kb [16]byte
	if _, err := io.ReadFull(rand.Reader, kb[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(kb[:])
	// Present the full header set (order and values) that Chrome sends for an in-page
	// WebSocket, so a CDN's bot/integrity checks (Cloudflare Browser Integrity Check,
	// Bot Fight Mode, managed WAF rules that block requests missing Accept-* headers)
	// pass it through to the 101 upgrade instead of answering with a 403/challenge.
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Pragma: no-cache\r\n" +
		"Cache-Control: no-cache\r\n" +
		"User-Agent: " + chromeUA + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Origin: https://" + host + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Accept-Encoding: " + chromeAcceptEncoding + "\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"
	conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(conn, readBufSize)
	resp, err := http.ReadResponse(r, &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	// Surface the status when the edge/CDN answers with something other than 101 (a 403/503
	// challenge, a 522 origin-unreachable, a 200 error page) so the log names the actual cause
	// instead of a vague "not a websocket upgrade".
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("ws: upgrade got HTTP %d (want 101 Switching Protocols)", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		return nil, errNotWS
	}
	// We advertise permessage-deflate to match Chrome's WS fingerprint, but wsConn does NOT implement
	// DEFLATE and readWSFrame ignores RSV1. If the edge actually negotiated it, inbound frames would be
	// de-framed as garbage — so fail the handshake rather than silently corrupt the stream.
	if exts := resp.Header.Get("Sec-WebSocket-Extensions"); strings.Contains(strings.ToLower(exts), "permessage-deflate") {
		return nil, fmt.Errorf("ws: server negotiated permessage-deflate (unsupported); refusing to read compressed frames")
	}
	var zero time.Time
	conn.SetDeadline(zero) // clear; the framer sets its own per-frame deadlines
	return r, nil
}

// wsNotFound is the single response every rejected request gets, whatever the reason. Keeping it
// byte-identical matters: a different status (or a different body) per rejection reason would just
// replace the old fingerprint with a finer one — a prober could then tell "wrong path on a tunnel"
// apart from "no such page on a web server", which is precisely what must stay indistinguishable.
const wsNotFound = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

// headerListContains reports whether a comma-separated list header carries tok (case-insensitively).
// Connection is a list header: our client sends exactly "Upgrade", but an intermediary is allowed to
// append its own tokens, so an equality test would reject a legitimately proxied upgrade.
func headerListContains(v, tok string) bool {
	for _, p := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(p), tok) {
			return true
		}
	}
	return false
}

// wsUpgradeForUs reports whether req is a well-formed RFC 6455 upgrade aimed at OUR path. Anything
// else is not ours to answer, whether it is hostile or merely lost.
func wsUpgradeForUs(req *http.Request, wantPath string) bool {
	if wantPath == "" {
		wantPath = "/" // matches config.applyDefaults, which resolves an omitted ws_path to "/"
	}
	if req.URL == nil || req.URL.Path != wantPath {
		return false
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") ||
		!headerListContains(req.Header.Get("Connection"), "upgrade") {
		return false
	}
	if req.Header.Get("Sec-WebSocket-Version") != "13" {
		return false
	}
	// RFC 6455 §4.1: the key is exactly 16 random bytes, base64-encoded. An ABSENT key used to hash
	// to a perfectly valid constant Accept, which the server then returned — so a request carrying no
	// key at all completed the upgrade.
	k, err := base64.StdEncoding.DecodeString(req.Header.Get("Sec-WebSocket-Key"))
	return err == nil && len(k) == 16
}

// wsServerHandshake reads the HTTP request and, if it is a WebSocket upgrade FOR US, answers 101 and
// returns the buffered reader for framing. Everything else — a probe, a scanner, a browser, a WebSocket
// client that found the port but not the path — gets a plausible 404 and errNotWS. wantPath is the
// operator's ws_path, which both ends carry, so it is a second thing a prober must know beyond the address.
func wsServerHandshake(conn net.Conn, wantPath string, deadline time.Time) (*bufio.Reader, error) {
	conn.SetDeadline(deadline)
	r := bufio.NewReaderSize(conn, readBufSize)
	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, err
	}
	if !wsUpgradeForUs(req, wantPath) {
		_, _ = conn.Write([]byte(wsNotFound))
		return nil, errNotWS
	}
	accept := wsAccept(req.Header.Get("Sec-WebSocket-Key"))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return nil, err
	}
	var zero time.Time
	conn.SetDeadline(zero)
	return r, nil
}
