package dnstun

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

type pipeTransport struct {
	tx     chan []byte
	rx     chan []byte
	loss   int
	mu     sync.Mutex
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
		return nil
	}
	cp := append([]byte(nil), d...)
	select {
	case p.tx <- cp:
	case <-p.closed:
	default:
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

func TestSessionOverLossyPipe(t *testing.T) {
	cliT, srvT := newPipePair(15)
	cfg := SessionConfig{PSK: "correct-horse-battery-staple", Cipher: "chacha20-poly1305"}

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

	go func() { _, _ = cli.Write(payload) }()

	srv := <-srvCh
	if srv == nil {
		t.Fatal("server session failed")
	}
	defer srv.Close()

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

func TestSessionWrongPSKFails(t *testing.T) {
	orig := handshakeTimeout
	handshakeTimeout = 1200 * time.Millisecond
	defer func() { handshakeTimeout = orig }()

	cliT, srvT := newPipePair(0)
	go func() { _, _ = ServeSession(srvT, SessionConfig{PSK: "server-psk", Cipher: "chacha20-poly1305"}) }()

	_, err := DialSession(cliT, SessionConfig{PSK: "wrong-client-psk", Cipher: "chacha20-poly1305"})
	if err == nil {
		t.Fatal("DialSession succeeded with a mismatched PSK — handshake did not authenticate")
	}
}

func TestServeSessionRecoversFromVanishedClient(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "recover-me", Cipher: "chacha20-poly1305"}

	srvCh := make(chan net.Conn, 1)
	srvErr := make(chan error, 1)
	go func() {
		c, err := ServeSession(srvT, cfg)
		if err != nil {
			srvErr <- err
			return
		}
		srvCh <- c
	}()

	ci1, err := crypto.GenerateEphemeralNoPad()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci1)...))
	time.Sleep(200 * time.Millisecond)

	select {
	case err := <-srvErr:
		t.Fatalf("ServeSession returned before a new client dialed: %v", err)
	case <-srvCh:
		t.Fatal("ServeSession returned before a new client dialed")
	default:
	}

	cli2, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("client 2 DialSession: %v", err)
	}
	defer cli2.Close()
	payload := []byte("hello from the second client")
	go func() { _, _ = cli2.Write(payload) }()

	select {
	case err := <-srvErr:
		t.Fatalf("ServeSession errored instead of adopting the new client: %v", err)
	case srv := <-srvCh:
		defer srv.Close()
		got := make([]byte, len(payload))
		_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(srv, got); err != nil {
			t.Fatalf("server read from the adopted client: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("adopted-client data mismatch: got %q want %q", got, payload)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeSession stayed parked after a new client fully dialed (no adopt)")
	}
}

func TestServeSessionIgnoresReplayedInit(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "no-teardown", Cipher: "chacha20-poly1305"}

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

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := cli.Write([]byte("ping")); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	srv := <-srvCh
	if srv == nil {
		t.Fatal("server session failed to establish")
	}
	defer srv.Close()
	buf := make([]byte, 64)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := srv.Read(buf); err != nil {
		t.Fatalf("server first read (establish): %v", err)
	}

	attacker, err := crypto.GenerateEphemeralNoPad()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, attacker)...))

	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := srv.Read(buf); err != nil {
		t.Fatalf("live session was disrupted by a bare replayed init: %v", err)
	}
}

func TestServeSessionUnblocksOnTransportClose(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "close-me", Cipher: "chacha20-poly1305"}

	srvErr := make(chan error, 1)
	go func() {
		_, err := ServeSession(srvT, cfg)
		srvErr <- err
	}()

	ci, err := crypto.GenerateEphemeralNoPad()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci)...))
	time.Sleep(200 * time.Millisecond)

	_ = srvT.Close()

	select {
	case err := <-srvErr:
		if err == nil {
			t.Fatal("expected ServeSession error after the transport closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeSession did not unblock when the transport closed (queue-conn leak)")
	}
}

func TestServeSessionStagedSetResistsEviction(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "no-evict", Cipher: "chacha20-poly1305"}

	srvCh := make(chan net.Conn, 1)
	srvErr := make(chan error, 1)
	go func() {
		c, err := ServeSession(srvT, cfg)
		if err != nil {
			srvErr <- err
			return
		}
		srvCh <- c
	}()

	ci1, err := crypto.GenerateEphemeralNoPad()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci1)...))
	time.Sleep(200 * time.Millisecond)

	cli, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("legit DialSession: %v", err)
	}
	defer cli.Close()

	for i := 0; i < maxStaged-1; i++ {
		atk, gerr := crypto.GenerateEphemeralNoPad()
		if gerr != nil {
			t.Fatal(gerr)
		}
		_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, atk)...))
	}
	time.Sleep(150 * time.Millisecond)

	payload := []byte("survived the eviction flood")
	go func() { _, _ = cli.Write(payload) }()

	select {
	case err := <-srvErr:
		t.Fatalf("ServeSession errored instead of adopting the legit client: %v", err)
	case srv := <-srvCh:
		defer srv.Close()
		got := make([]byte, len(payload))
		_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(srv, got); err != nil {
			t.Fatalf("server read from the adopted client after the eviction flood: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("adopted-client data mismatch: got %q want %q", got, payload)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the legit client's staged candidate was evicted by the init flood (never adopted)")
	}
}

func TestSessionKeepaliveReapsSilentPeer(t *testing.T) {
	origKA, origFloor := defaultKeepalive, keepaliveDeadFloor
	defaultKeepalive, keepaliveDeadFloor = 50*time.Millisecond, 250*time.Millisecond
	defer func() { defaultKeepalive, keepaliveDeadFloor = origKA, origFloor }()

	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "reap-me", Cipher: "chacha20-poly1305"}

	go func() {
		for {
			d, err := srvT.Recv()
			if err != nil {
				return
			}
			if len(d) >= 1 && d[0] == kindHandshake {
				e, perr := crypto.ParseInit(cfg.PSK, d[1:])
				if perr != nil {
					continue
				}
				sr, gerr := crypto.GenerateEphemeralNoPad()
				if gerr != nil {
					continue
				}
				_ = srvT.Send(append([]byte{kindHandshake}, crypto.RespMsg(cfg.PSK, e, sr)...))
			}

		}
	}()

	cli, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer cli.Close()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, e := cli.Read(buf)
		done <- e
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("client Read returned nil; expected the keepalive to reap the silent-peer session")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("keepalive did not reap the silent-peer session within 2s (deadWindow was 250ms)")
	}
}

func TestSessionCloseIsIdempotent(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "k", Cipher: "chacha20-poly1305"}
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
	go func() { _, _ = cli.Write([]byte("wake")) }()
	time.Sleep(200 * time.Millisecond)
	if err := cli.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
