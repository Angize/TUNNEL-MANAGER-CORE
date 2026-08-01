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

// TestOneKeepalivePingDoesNotBlockTheAdoptInPlaceRecovery is TestServeSessionRecoversFromVanishedClient
// with ONE difference, and that difference was enough to undo the whole recovery.
//
// v2.48.8 / #132 made the server adopt a new client IN PLACE when the live session's own client has
// vanished before establishing KCP — about one round trip, instead of parking until a KCP dead-link
// timeout. The gate is `liveProven`, documented as "the live session is established / establishing",
// and tryStaged tears down rather than adopting only because "an established conv-0 KCP session can't
// be retrofitted".
//
// `case kindPing` set that flag. A ping is a sealed keepalive one layer BELOW KCP and establishes
// nothing, so any client that lived long enough to send a single keepalive left the server unable to
// adopt anyone afterwards. The existing recovery test cannot see it: its client 1 arms the server and
// goes silent immediately, so no ping is ever sent.
//
// The ping here is sent through sendKind — the same call the client's keepalive loop makes — rather
// than by waiting on a timer, so the test is instant and deterministic. Everything on the SERVER side
// is production code.
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

	// Client 1 completes the crypto handshake — so the server's LIVE sealer is its — and then sends
	// one keepalive ping. It never writes, so KCP is never established: exactly the state #132's
	// adopt-in-place is for.
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
	time.Sleep(200 * time.Millisecond) // let the server's recvPump take the ping

	select {
	case err := <-srvErr:
		t.Fatalf("ServeSession returned before a new client dialed: %v", err)
	case <-srvCh:
		t.Fatal("ServeSession returned before a new client dialed")
	default:
	}

	// Client 1 is now gone as far as the tunnel is concerned. Client 2 fully dials over the SAME
	// transport and writes — a real new client completing the KCP handshake.
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
			"of adopted — the #132 recovery, defeated by a packet that carries no data at all.")
	}
}

// TestDataStillProvesTheSessionIsEstablished is the other half, and it is what stops the fix above
// from being "never tear down": a client that has really carried DATA has an established conv-0 KCP
// session, which cannot be retrofitted, so a later client must NOT be adopted in place.
//
// Without this, deleting `liveProven = true` from the data case as well would leave both tests green
// while quietly corrupting a live session.
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

	// A second client arrives. The live session is ESTABLISHED, so the server must tear down and let
	// the carrier re-accept — never splice the newcomer into the running KCP conversation.
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

	// The assertion must be that WE tore the conn down, not merely that a Read failed — and finding
	// the right discriminator took measuring both variants rather than guessing at one:
	//
	//	tear-down (correct)      "use of closed network connection"  == net.ErrClosed
	//	adopt-in-place (broken)  "io: read/write on closed pipe"     == io.ErrClosedPipe
	//
	// A first cut asserted only `err != nil`, and a second guessed at os.ErrDeadlineExceeded. BOTH
	// passed on the broken code, because "no data arrived" has several spellings and neither of those
	// was the one it produces. net.ErrClosed is the sentinel qpc.Close() raises, so it names the
	// tear-down itself instead of one of its symptoms.
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
