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

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

var errNotWS = errors.New("ws: not a websocket upgrade")

type wsConn struct {
	net.Conn
	r      *bufio.Reader
	client bool
	rbuf   []byte
	wmu    sync.Mutex
}

func (c *wsConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		payload, opcode, err := readWSFrame(c.r)
		if err != nil {
			return 0, err
		}

		if opcode >= 0x8 && len(payload) > 125 {
			return 0, errDesync
		}
		switch opcode {
		case 0x0, 0x1, 0x2:
			c.rbuf = payload
		case 0x8:
			return 0, io.EOF
		case 0x9:
			_ = c.writeWSFrame(0xA, payload)
		case 0xA:
		default:
			return 0, errDesync
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeWSFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) writeWSFrame(opcode byte, payload []byte) error {
	n := len(payload)
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|opcode)
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

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func wsClientHandshake(conn net.Conn, host, path string, deadline time.Time) (*bufio.Reader, error) {
	if path == "" {
		path = "/"
	}
	var kb [16]byte
	if _, err := io.ReadFull(rand.Reader, kb[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(kb[:])

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

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("ws: upgrade got HTTP %d (want 101 Switching Protocols)", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		return nil, errNotWS
	}

	if exts := resp.Header.Get("Sec-WebSocket-Extensions"); strings.Contains(strings.ToLower(exts), "permessage-deflate") {
		return nil, fmt.Errorf("ws: server negotiated permessage-deflate (unsupported); refusing to read compressed frames")
	}
	var zero time.Time
	conn.SetDeadline(zero)
	return r, nil
}

func wsDateHeader() string {
	return "Date: " + time.Now().UTC().Format(http.TimeFormat) + "\r\n"
}

const wsServerName = "Server: nginx\r\n"

func wsNotFound() string {
	return "HTTP/1.1 404 Not Found\r\n" + wsDateHeader() + wsServerName +
		"Content-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
}

func headerListContains(v, tok string) bool {
	for _, p := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(p), tok) {
			return true
		}
	}
	return false
}

func wsUpgradeForUs(req *http.Request, wantPath string) bool {
	if wantPath == "" {
		wantPath = "/"
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

	k, err := base64.StdEncoding.DecodeString(req.Header.Get("Sec-WebSocket-Key"))
	return err == nil && len(k) == 16
}

func wsServerHandshake(conn net.Conn, wantPath string, deadline time.Time) (*bufio.Reader, error) {
	conn.SetDeadline(deadline)
	r := bufio.NewReaderSize(conn, readBufSize)
	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, err
	}
	if !wsUpgradeForUs(req, wantPath) {
		_, _ = conn.Write([]byte(wsNotFound()))
		return nil, errNotWS
	}
	accept := wsAccept(req.Header.Get("Sec-WebSocket-Key"))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		wsDateHeader() + wsServerName +
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
