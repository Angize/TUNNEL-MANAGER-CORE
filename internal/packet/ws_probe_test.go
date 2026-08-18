package packet

import (
	"net"
	"strings"
	"testing"
	"time"
)

type wsRawReq struct {
	path, upgrade, connection, version, key string
}

func ours(p string) wsRawReq {
	return wsRawReq{path: p, upgrade: "websocket", connection: "Upgrade", version: "13",
		key: "dGhlIHNhbXBsZSBub25jZQ=="}
}

func (r wsRawReq) String() string {
	lines := []string{"GET " + r.path + " HTTP/1.1", "Host: cdn.example.com"}
	for _, kv := range [][2]string{
		{"Connection", r.connection}, {"Upgrade", r.upgrade},
		{"Sec-WebSocket-Version", r.version}, {"Sec-WebSocket-Key", r.key},
	} {
		if kv[1] != "" {
			lines = append(lines, kv[0]+": "+kv[1])
		}
	}
	return strings.Join(lines, "\r\n") + "\r\n\r\n"
}

func wsProbe(t *testing.T, wantPath string, req wsRawReq) (raw string, hsErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			errCh <- aerr
			return
		}
		_, herr := wsServerHandshake(c, wantPath, time.Now().Add(2*time.Second))
		errCh <- herr
		time.Sleep(100 * time.Millisecond)
		c.Close()
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(req.String())); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var sb strings.Builder
	buf := make([]byte, 512)
	for !strings.Contains(sb.String(), "\r\n\r\n") {
		n, rerr := c.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	return sb.String(), <-errCh
}

func TestWSServerAnswers101OnlyForAWellFormedUpgradeOnItsOwnPath(t *testing.T) {
	const secret = "/media/stream"

	accept := []struct {
		name string
		path string
		req  wsRawReq
	}{
		{"our own client, exact path", secret, ours(secret)},
		{"default path when ws_path is unset", "", ours("/")},
		{"a query string an edge may append", secret, ours(secret + "?cb=91723")},
		{"Connection list header with an extra token", secret,
			func() wsRawReq { r := ours(secret); r.connection = "keep-alive, Upgrade"; return r }()},
		{"lower-case Upgrade value", secret,
			func() wsRawReq { r := ours(secret); r.upgrade = "WebSocket"; return r }()},
	}
	for _, c := range accept {
		raw, err := wsProbe(t, c.path, c.req)
		if err != nil || !strings.HasPrefix(raw, "HTTP/1.1 101 ") {
			t.Fatalf("%s: must still upgrade, got err=%v resp=%q", c.name, err, raw)
		}
	}

	reject := []struct {
		name string
		req  wsRawReq
	}{

		{"the one-line fingerprint: an Upgrade header and nothing else",
			wsRawReq{path: secret, upgrade: "websocket"}},
		{"right shape, wrong path", ours("/")},
		{"right shape, path guessed one character off", ours(secret + "x")},
		{"no Sec-WebSocket-Key (used to hash to a constant Accept)",
			func() wsRawReq { r := ours(secret); r.key = ""; return r }()},
		{"Sec-WebSocket-Key that is not 16 bytes",
			func() wsRawReq { r := ours(secret); r.key = "c2hvcnQ="; return r }()},
		{"Sec-WebSocket-Key that is not base64 at all",
			func() wsRawReq { r := ours(secret); r.key = "!!!!not-base64!!!!"; return r }()},
		{"an obsolete protocol version",
			func() wsRawReq { r := ours(secret); r.version = "8"; return r }()},
		{"no Connection: Upgrade",
			func() wsRawReq { r := ours(secret); r.connection = ""; return r }()},
		{"a plain browser GET", wsRawReq{path: secret}},
	}
	var seen string
	for _, c := range reject {
		raw, err := wsProbe(t, secret, c.req)
		if err != errNotWS {
			t.Fatalf("%s: want errNotWS, got %v", c.name, err)
		}
		if strings.Contains(raw, "101") {
			t.Fatalf("%s: the server UPGRADED for it — this request identifies the origin as a tunnel", c.name)
		}
		if !strings.HasPrefix(raw, "HTTP/1.1 404 ") {
			t.Fatalf("%s: want a plain 404, got %q", c.name, raw)
		}

		if seen == "" {
			seen = raw
		} else if raw != seen {
			t.Fatalf("%s: rejection response differs from the others (%q vs %q) — the reason is an oracle",
				c.name, raw, seen)
		}
	}
}
