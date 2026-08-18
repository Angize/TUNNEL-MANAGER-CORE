package tlscover

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func tlsDest(t *testing.T, cn string, serve func(c net.Conn)) (addr string) {
	t.Helper()
	cert, err := SelfSignedCert(cn)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	return ln.Addr().String()
}

func realDest(t *testing.T, cn string) (addr string) {
	return tlsDest(t, cn, func(c net.Conn) {
		c.Write([]byte("HELLO-FROM-REAL\n"))
		time.Sleep(200 * time.Millisecond)
		c.Close()
	})
}

func holdingDest(t *testing.T, cn string) (addr string) {
	stop := make(chan struct{})
	addr = tlsDest(t, cn, func(c net.Conn) {
		_ = c.(*tls.Conn).Handshake()
		<-stop
		c.Close()
	})
	t.Cleanup(func() { close(stop) })
	return addr
}

func echoDest(t *testing.T, cn string) (addr string) {
	return tlsDest(t, cn, func(c net.Conn) { io.Copy(c, c); c.Close() })
}

func coverServer(t *testing.T, psk, destAddr string, tweak func(*Server)) (addr string) {
	t.Helper()
	sv, err := NewServer(psk, "real.example")
	if err != nil {
		t.Fatal(err)
	}
	sv.dest = destAddr
	if tweak != nil {
		tweak(sv)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c, err := sv.Handle(raw, time.Now().Add(5*time.Second))
				if err != nil {
					return
				}
				c.Write([]byte("TUNNEL-OK\n"))
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCoverAuthenticatedClient(t *testing.T) {
	const psk = "reality-psk-abcdefghij"
	dest := realDest(t, "real.example")
	cov := coverServer(t, psk, dest, nil)

	raw, err := net.Dial("tcp", cov)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ClientConn(raw, "real.example", psk, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("authenticated handshake: %v", err)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	if line != "TUNNEL-OK\n" {
		t.Fatalf("authenticated client got %q, want the tunnel greeting", line)
	}
}

func TestCoverProbeSeesRealSite(t *testing.T) {
	const psk = "reality-psk-abcdefghij"
	dest := realDest(t, "real.example")
	cov := coverServer(t, psk, dest, nil)

	c, err := tls.Dial("tcp", cov, &tls.Config{InsecureSkipVerify: true, ServerName: "real.example"})
	if err != nil {
		t.Fatalf("probe handshake: %v", err)
	}
	defer c.Close()
	cn := c.ConnectionState().PeerCertificates[0].Subject.CommonName
	if cn != "real.example" {
		t.Fatalf("probe saw cert CN %q — expected the REAL dest, cover leaked its own cert", cn)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	if line != "HELLO-FROM-REAL\n" {
		t.Fatalf("probe read %q, want the real site's bytes", line)
	}
}

func TestCoverProbeIsNeverDroppedWhenTheRelayPoolIsFull(t *testing.T) {
	const psk = "reality-psk-abcdefghij"
	dest := holdingDest(t, "real.example")
	cov := coverServer(t, psk, dest, func(sv *Server) {
		sv.relay = make(chan struct{}, 2)
		sv.idle = 300 * time.Millisecond
	})
	probe := func() (*tls.Conn, error) {
		return tls.Dial("tcp", cov, &tls.Config{InsecureSkipVerify: true, ServerName: "real.example"})
	}

	for i := 0; i < 2; i++ {
		c, err := probe()
		if err != nil {
			t.Fatalf("filler probe %d: %v", i, err)
		}
		defer c.Close()
	}

	c, err := probe()
	if err != nil {
		t.Fatalf("probe arriving on a full relay pool was dropped: %v", err)
	}
	defer c.Close()
	if cn := c.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "real.example" {
		t.Fatalf("probe saw cert CN %q — it did not reach the real dest", cn)
	}
}

func TestCoverRelayBoundIsIdleNotLifetime(t *testing.T) {
	const psk = "reality-psk-abcdefghij"
	dest := echoDest(t, "real.example")
	cov := coverServer(t, psk, dest, func(sv *Server) { sv.idle = 200 * time.Millisecond })

	c, err := tls.Dial("tcp", cov, &tls.Config{InsecureSkipVerify: true, ServerName: "real.example"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 10; i++ {
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatalf("write %d on a busy relay: %v", i, err)
		}
		var b [1]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			t.Fatalf("the relay cut a BUSY connection at exchange %d: %v", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestCoverQueueIsNotJustTheRelayPoolAgain(t *testing.T) {
	const psk = "reality-psk-abcdefghij"
	dest := holdingDest(t, "real.example")
	cov := coverServer(t, psk, dest, func(sv *Server) {
		sv.relay = make(chan struct{}, 2)
		sv.queue = make(chan struct{}, 2)
		sv.idle = 300 * time.Millisecond
	})
	probe := func() (*tls.Conn, error) {
		return tls.Dial("tcp", cov, &tls.Config{InsecureSkipVerify: true, ServerName: "real.example"})
	}

	for i := 0; i < 2; i++ {
		c, err := probe()
		if err != nil {
			t.Fatalf("filler probe %d: %v", i, err)
		}
		defer c.Close()
	}

	c, err := probe()
	if err != nil {
		t.Fatalf("a probe arriving on a full pool was dropped: %v — with the waiting room the same size "+
			"as the pool, a goroutine that holds its queue token while relaying leaves no room to wait "+
			"in, and the connection is closed straight after its ClientHello", err)
	}
	defer c.Close()
	if cn := c.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "real.example" {
		t.Fatalf("the queued probe saw cert CN %q — it did not reach the real dest", cn)
	}
}
