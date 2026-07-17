package dnstun

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

// pipeTransport is an in-memory WireTransport: Send delivers onto the peer's rx channel (dropping
// a lossPct fraction to model an unreliable DNS channel), Recv reads this end's rx. A cross-wired
// pair stands in for the real DNS transport so the session layer is testable without a resolver.
type pipeTransport struct {
	tx     chan []byte // datagrams this end sends (the peer's rx)
	rx     chan []byte // datagrams this end receives
	loss   int
	mu     sync.Mutex // guards rng (math/rand/v2 is not concurrency-safe)
	rng    *mrand.Rand
	closed chan struct{}
	once   sync.Once
}

func newPipePair(lossPct int) (client, server *pipeTransport) {
	c2s := make(chan []byte, 1024)
	s2c := make(chan []byte, 1024)
	client = &pipeTransport{tx: c2s, rx: s2c, loss: lossPct, rng: mrand.New(mrand.NewPCG(1, 2)), closed: make(chan struct{})}
	server = &pipeTransport{tx: s2c, rx: c2s, loss: lossPct, rng: mrand.New(mrand.NewPCG(3, 4)), closed: make(chan struct{})}
	return
}

func (p *pipeTransport) Send(d []byte) error {
	select {
	case <-p.closed:
		return net.ErrClosed
	default:
	}
	p.mu.Lock()
	drop := p.loss > 0 && p.rng.IntN(100) < p.loss
	p.mu.Unlock()
	if drop {
		return nil // lost in transit — kcp-go retransmits
	}
	cp := append([]byte(nil), d...)
	select {
	case p.tx <- cp:
	case <-p.closed:
	default: // peer not draining: drop
	}
	return nil
}

func (p *pipeTransport) Recv() ([]byte, error) {
	select {
	case d := <-p.rx:
		return d, nil
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

func (p *pipeTransport) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// TestSessionOverLossyPipe is the Phase-A end-to-end proof: two sessions (dial + serve) complete
// the X25519 handshake and exchange an AEAD-sealed, reliable byte stream IN BOTH DIRECTIONS over
// a 15%-lossy transport — the whole session layer the DNS carrier rides on, minus the DNS codec.
func TestSessionOverLossyPipe(t *testing.T) {
	cliT, srvT := newPipePair(15)
	cfg := SessionConfig{PSK: "correct-horse-battery-staple", Cipher: "chacha20"}

	srvCh := make(chan net.Conn, 1)
	go func() {
		c, err := ServeSession(srvT, cfg)
		if err != nil {
			t.Errorf("ServeSession: %v", err)
			srvCh <- nil
			return
		}
		srvCh <- c
	}()

	cli, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer cli.Close()

	const payloadSize = 24 * 1024
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	// Client writes upstream; a reader collects the echo. The write must start so the server's
	// AcceptKCP (blocked on the first KCP datagram) returns.
	go func() { _, _ = cli.Write(payload) }()

	srv := <-srvCh
	if srv == nil {
		t.Fatal("server session failed")
	}
	defer srv.Close()

	// Server echoes full-duplex (separate concern from its own reads — one read loop that writes
	// each chunk back; never io.Copy on the same session, which self-stalls half-duplex).
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := srv.Read(buf)
			if err != nil {
				return
			}
			if _, err := srv.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	got := make([]byte, payloadSize)
	readDone := make(chan error, 1)
	go func() {
		off := 0
		buf := make([]byte, 4096)
		for off < len(got) {
			n, err := cli.Read(buf)
			if err != nil {
				readDone <- err
				return
			}
			copy(got[off:], buf[:n])
			off += n
		}
		readDone <- nil
	}()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("read echo: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out: session did not converge under loss")
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch: sealed reliable stream corrupted data")
	}
}

// TestSessionWrongPSKFails proves the handshake authenticates: a client with the wrong PSK cannot
// establish a session — the server never MAC-verifies its init, so it never answers and the dial
// times out (rather than silently forming an unauthenticated tunnel).
func TestSessionWrongPSKFails(t *testing.T) {
	orig := handshakeTimeout
	handshakeTimeout = 1200 * time.Millisecond
	defer func() { handshakeTimeout = orig }()

	cliT, srvT := newPipePair(0)
	go func() { _, _ = ServeSession(srvT, SessionConfig{PSK: "server-psk", Cipher: "chacha20"}) }()

	_, err := DialSession(cliT, SessionConfig{PSK: "wrong-client-psk", Cipher: "chacha20"})
	if err == nil {
		t.Fatal("DialSession succeeded with a mismatched PSK — handshake did not authenticate")
	}
}

// TestServeSessionRecoversFromVanishedClient proves the server's single session slot is never
// parked forever. A client arms the server with a valid init but then vanishes without completing
// the KCP handshake (crash, or its own resp was lost so it timed out); the server sits in
// AcceptKCP. A NEW client's init (different ephemeral) must make ServeSession return so the carrier
// reconnects and accepts the new client — the old behavior ignored the new init and deadlocked.
func TestServeSessionRecoversFromVanishedClient(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "recover-me", Cipher: "chacha20"}

	srvErr := make(chan error, 1)
	go func() {
		_, err := ServeSession(srvT, cfg)
		srvErr <- err
	}()

	// Client 1 arms the server with a valid init, then goes silent (never sends a KCP datagram).
	ci1, err := crypto.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci1)...))
	time.Sleep(200 * time.Millisecond) // let the server arm and enter AcceptKCP

	select {
	case err := <-srvErr:
		t.Fatalf("ServeSession returned before a new client dialed: %v", err)
	default:
	}

	// Client 2 dials with a fresh ephemeral: this must unblock the parked server.
	ci2, err := crypto.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci2)...))

	select {
	case err := <-srvErr:
		if err == nil {
			t.Fatal("ServeSession returned nil; expected an error so the carrier reconnects")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeSession stayed parked in AcceptKCP after a new client dialed")
	}
}

// TestServeSessionUnblocksOnTransportClose proves Close honors its contract even before a client
// connects: with the server armed and parked in AcceptKCP, closing the transport (what the
// carrier's Close does when no session is live yet) must unblock ServeSession — otherwise the
// queue conn is never closed and the goroutines leak.
func TestServeSessionUnblocksOnTransportClose(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "close-me", Cipher: "chacha20"}

	srvErr := make(chan error, 1)
	go func() {
		_, err := ServeSession(srvT, cfg)
		srvErr <- err
	}()

	ci, err := crypto.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci)...))
	time.Sleep(200 * time.Millisecond) // arm + enter AcceptKCP

	_ = srvT.Close() // carrier Close with no live session tears down the transport

	select {
	case err := <-srvErr:
		if err == nil {
			t.Fatal("expected ServeSession error after the transport closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeSession did not unblock when the transport closed (queue-conn leak)")
	}
}

// TestSessionCloseIsIdempotent guards the teardown path (Close is called from multiple defers).
func TestSessionCloseIsIdempotent(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "k", Cipher: "chacha20"}
	go func() {
		c, err := ServeSession(srvT, cfg)
		if err == nil {
			_ = c.Close()
		}
	}()
	cli, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	go func() { _, _ = cli.Write([]byte("wake")) }() // unblock the server's AcceptKCP
	time.Sleep(200 * time.Millisecond)
	if err := cli.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
