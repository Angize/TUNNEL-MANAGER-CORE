package dnstun

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

func TestOneKeepalivePingDoesNotBlockTheAdoptInPlaceRecovery(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "a-ping-is-not-a-session", Cipher: "chacha20-poly1305"}

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

	cli1, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("client 1 DialSession: %v", err)
	}
	sc1, ok := cli1.(*sessionConn)
	if !ok {
		t.Fatalf("DialSession returned %T, not *sessionConn — this test can no longer send the ping "+
			"the client's keepalive loop sends, so it must not report success", cli1)
	}
	sc1.sendKind(kindPing)
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
	payload := []byte("hello from the client that arrived after a keepalive")
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
		t.Fatal("ServeSession stayed parked after a new client fully dialed. One keepalive ping from " +
			"the PREVIOUS client marked the session established, so the new one was torn down instead " +
			"of adopted, so the recovery a restarted peer depends on is defeated by a packet that " +
			"carries no data at all.")
	}
}

func TestDataStillProvesTheSessionIsEstablished(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "data-does-prove-it", Cipher: "chacha20-poly1305"}

	srvCh := make(chan net.Conn, 1)
	go func() {
		if c, err := ServeSession(srvT, cfg); err == nil {
			srvCh <- c
		}
	}()

	cli1, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("client 1 DialSession: %v", err)
	}
	defer cli1.Close()
	first := []byte("real data from the first client")
	go func() { _, _ = cli1.Write(first) }()

	var srv net.Conn
	select {
	case srv = <-srvCh:
		defer srv.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("the first client never established, so this test proves nothing")
	}
	got := make([]byte, len(first))
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("server read from the established client: %v", err)
	}

	ci2, err := crypto.GenerateEphemeralNoPad()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci2)...))
	cli2, err := DialSession(cliT, cfg)
	if err == nil {
		defer cli2.Close()
		go func() { _, _ = cli2.Write([]byte("from the second client")) }()
	}

	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	_, err = srv.Read(buf)
	if err == nil {
		t.Fatal("the established session kept serving after a second client established")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("the server conn failed with %v, not net.ErrClosed — so it was NOT torn down. "+
			"tryStaged took the adopt-in-place branch on a session that has really carried data, and an "+
			"established conv-0 KCP session cannot be retrofitted: the carrier has to be made to "+
			"reconnect instead", err)
	}
}
