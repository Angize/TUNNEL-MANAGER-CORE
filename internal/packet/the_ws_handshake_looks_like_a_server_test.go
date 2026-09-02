package packet

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A bare "HTTP/1.1 101 Switching Protocols" with three headers and no Date and no Server is not what any
// real fronting server sends -- nginx, Cloudflare and the rest always stamp a Date and name themselves. A
// single unsolicited probe to the carrier port used to fingerprint the origin in one shot. Both the 101 and
// the 404 now carry a Date and a Server line, so a probe sees an ordinary web server.
func readRawResponse(t *testing.T, path string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = wsServerHandshake(c, "/tunnel", time.Now().Add(2*time.Second))
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := "GET " + path + " HTTP/1.1\r\nHost: x\r\n"
	if path == "/tunnel" {
		req += "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" +
			"Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n"
	}
	req += "\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(c)
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		sb.WriteString(line)
		if line == "\r\n" || err != nil {
			break
		}
	}
	return sb.String()
}

func TestTheWSHandshakeLooksLikeAServer(t *testing.T) {
	for _, tc := range []struct {
		path, want string
	}{
		{"/tunnel", "101 Switching Protocols"},
		{"/nope", "404 Not Found"},
	} {
		resp := readRawResponse(t, tc.path)
		if !strings.Contains(resp, tc.want) {
			t.Fatalf("path %s: response is not %q:\n%s", tc.path, tc.want, resp)
		}
		if !strings.Contains(resp, "Date: ") {
			t.Errorf("path %s: no Date header:\n%s", tc.path, resp)
		}
		if !strings.Contains(resp, "Server: ") {
			t.Errorf("path %s: no Server header:\n%s", tc.path, resp)
		}
		date := headerValue(resp, "Date")
		if _, err := http.ParseTime(date); err != nil {
			t.Errorf("path %s: Date %q is not a valid HTTP date: %v", tc.path, date, err)
		}
	}
}

func headerValue(resp, name string) string {
	for _, line := range strings.Split(resp, "\r\n") {
		if strings.HasPrefix(line, name+": ") {
			return strings.TrimPrefix(line, name+": ")
		}
	}
	return ""
}
