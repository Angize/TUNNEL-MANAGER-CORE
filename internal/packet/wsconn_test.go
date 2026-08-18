package packet

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestWSConnRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvDone := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvDone <- nil
			return
		}
		defer c.Close()
		r, err := wsServerHandshake(c, "/tunnel", time.Now().Add(2*time.Second))
		if err != nil {
			srvDone <- nil
			return
		}
		ws := &wsConn{Conn: c, r: r, client: false}
		got := make([]byte, 5)
		if _, err := io.ReadFull(ws, got); err != nil {
			srvDone <- nil
			return
		}
		_, _ = ws.Write([]byte("PONG-back"))
		srvDone <- got
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := wsClientHandshake(c, "example.test", "/tunnel", time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	ws := &wsConn{Conn: c, r: r, client: true}
	if _, err := ws.Write([]byte("HELLO")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 9)
	if _, err := io.ReadFull(ws, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if got := <-srvDone; !bytes.Equal(got, []byte("HELLO")) {
		t.Fatalf("server got %q, want HELLO", got)
	}
	if !bytes.Equal(reply, []byte("PONG-back")) {
		t.Fatalf("client got %q, want PONG-back", reply)
	}
}

func TestWSConnStreamsAcrossReads(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	cw := &wsConn{Conn: a, r: bufio.NewReader(a), client: true}
	sr := &wsConn{Conn: b, r: bufio.NewReader(b), client: false}
	payload := bytes.Repeat([]byte("xy"), 5000)
	go func() { _, _ = cw.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(sr, got); err != nil {
		t.Fatalf("readfull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("stream corrupted across frame boundary")
	}
}

func TestWSConnRejectsMalformedFrames(t *testing.T) {
	check := func(name string, frame []byte) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		rc := &wsConn{Conn: b, r: bufio.NewReader(b), client: true}
		go func() { _, _ = a.Write(frame); a.Close() }()
		buf := make([]byte, 256)
		if _, err := rc.Read(buf); err == nil {
			t.Fatalf("%s: Read returned nil error, want the connection dropped", name)
		}
	}
	check("reserved opcode 0x3", []byte{0x83, 0x00})
	check("oversized ping", append([]byte{0x89, 126, 0x00, 200}, make([]byte, 200)...))
}

func TestWSServerRejectsNonWS(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := wsServerHandshake(c, "", time.Now().Add(2*time.Second)); err != errNotWS {
			t.Errorf("expected errNotWS, got %v", err)
		}
	}()
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	resp, _ := bufio.NewReader(c).ReadString('\n')
	if !bytes.Contains([]byte(resp), []byte("404")) {
		t.Fatalf("probe got %q, want 404", resp)
	}
}
