package tlscover

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// tlsDest runs a TLS server with a recognizable cert CN and hands each accepted
// connection to serve. Every dest helper below is a thin wrapper on this.
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

// realDest stands in for the borrowed site: a normal TLS server with a
// recognizable cert CN that greets whoever completes a handshake.
func realDest(t *testing.T, cn string) (addr string) {
	return tlsDest(t, cn, func(c net.Conn) {
		c.Write([]byte("HELLO-FROM-REAL\n"))
		time.Sleep(200 * time.Millisecond)
		c.Close()
	})
}

// holdingDest completes the handshake and then says nothing and never closes,
// so ONLY the cover's own idle bound can ever end the relay.
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

// echoDest echoes forever: a connection that keeps exchanging bytes.
func echoDest(t *testing.T, cn string) (addr string) {
	return tlsDest(t, cn, func(c net.Conn) { io.Copy(c, c); c.Close() })
}

// coverServer runs a REALITY-style cover pointing at destAddr. tweak, if given,
// adjusts the server BEFORE it accepts anything.
func coverServer(t *testing.T, psk, destAddr string, tweak func(*Server)) (addr string) {
	t.Helper()
	sv, err := NewServer(psk, "real.example")
	if err != nil {
		t.Fatal(err)
	}
	sv.dest = destAddr // override the :443 dest for the test
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
					return // ErrProbe (proxied) or a bad hello
				}
				c.Write([]byte("TUNNEL-OK\n")) // authenticated client
			}()
		}
	}()
	return ln.Addr().String()
}

// TestCoverAuthenticatedClient: our client (with the token) terminates at the
// cover server and gets the tunnel greeting, not the real site.
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

// TestCoverProbeSeesRealSite: a probe (a plain TLS client WITHOUT the token) is
// transparently proxied to the real dest, so it completes a handshake against
// the real site's certificate and reads the real site's bytes — active-probe
// resistance.
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

// TestCoverProbeIsNeverDroppedWhenTheRelayPoolIsFull is the whole class: no probe
// may ever be closed on the spot because earlier probes hold the relay slots.
//
// ⚠ This test shrinks ONLY sv.relay and leaves sv.queue at its full size, so it
// passes with or without a working queue — see the sibling below, which is the one
// that actually exercises it. What this covers is the idle bound: dest never closes
// here, so nothing but the idle timer can hand a slot back.
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

	for i := 0; i < 2; i++ { // fill every slot with a probe that then goes silent
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

// TestCoverRelayBoundIsIdleNotLifetime pins the other side of the same knob: the
// bound must never become a lifetime cap. Cutting a busy relay would break a real
// download through the cover and be a fingerprint of its own. Green before this
// change too (there was no bound at all) — it exists to keep it that way.
func TestCoverRelayBoundIsIdleNotLifetime(t *testing.T) {
	const psk = "reality-psk-abcdefghij"
	dest := echoDest(t, "real.example")
	cov := coverServer(t, psk, dest, func(sv *Server) { sv.idle = 200 * time.Millisecond })

	c, err := tls.Dial("tcp", cov, &tls.Config{InsecureSkipVerify: true, ServerName: "real.example"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 10; i++ { // ~1s of chatter across a 200ms idle bound
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

// TestCoverQueueIsNotJustTheRelayPoolAgain is the test the sibling above only looked
// like. In production maxWaiting == maxRelays, and the queue token used to be held for
// the goroutine's WHOLE life — relay included — so a goroutine in service still
// occupied a waiting-room slot. The queue was therefore full exactly when the relay
// pool was, every new probe hit the `default` arm, and it was CLOSED ON THE SPOT: the
// instant FIN straight after the ClientHello that this carrier exists to never emit,
// at exactly the concurrency it emitted it at before the queue was added.
//
// Shrinking BOTH semaphores to the same small number is what reproduces the production
// relationship. The third probe must wait for a slot and then reach the real dest, not
// get a connection reset.
func TestCoverQueueIsNotJustTheRelayPoolAgain(t *testing.T) {
	const psk = "reality-psk-abcdefghij"
	dest := holdingDest(t, "real.example")
	cov := coverServer(t, psk, dest, func(sv *Server) {
		sv.relay = make(chan struct{}, 2)
		sv.queue = make(chan struct{}, 2) // the production relationship: same size as the relay pool
		sv.idle = 300 * time.Millisecond
	})
	probe := func() (*tls.Conn, error) {
		return tls.Dial("tcp", cov, &tls.Config{InsecureSkipVerify: true, ServerName: "real.example"})
	}

	for i := 0; i < 2; i++ { // both relay slots taken by probes that then go silent
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
