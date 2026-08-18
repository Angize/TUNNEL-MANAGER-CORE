package packet

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	fecResetPSK    = "e2e-shared-pre-shared-key-1234567890"
	fecResetCipher = "aes-256-gcm"
	// The dead window is deadMult x keepalive and nothing else, so keepalive is what sizes it here. It
	// has to clear the handshake retransmit wait, which is jitterFrac(1s): under that, a client calls
	// the session it just installed stale and re-handshakes forever without reaching the keepalive path.
	fecResetKeepalive = time.Second
)

// waitUntil polls cond until it holds or the budget runs out, naming what was being waited for.
func waitUntil(t *testing.T, what string, budget time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// seedBlocks pushes n packets through a live FEC tunnel one at a time, so the sender's encoder flushes one
// block per packet (its idle timer fires long before the next write) and the receiver's decoder ends up
// holding blocks 0..n-1, each reconstructed and marked done. fecSeedLen is what makes the collision exact
// later: the same payload length seals to the same shardLen, so a fresh block 0 matches the stale one's
// geometry and is swallowed by the done guard rather than the geometry guard.
const fecSeedLen = 200

func seedBlocks(t *testing.T, from, to *os.File, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		pkt := bytes.Repeat([]byte{byte(0xA0 + i)}, fecSeedLen)
		if _, err := from.Write(pkt); err != nil {
			t.Fatalf("seed packet %d: %v", i, err)
		}
		if got := readWithTimeout(t, to, "seed packet"); !bytes.Equal(got, pkt) {
			t.Fatalf("seed packet %d did not traverse the tunnel", i)
		}
	}
}

// TestUDPFecDecoderResetAfterClientRestart drives a real FEC tunnel, restarts the CLIENT, and asserts the
// first upstream packet of the new session reaches the server's TUN. A restarted client numbers its FEC
// blocks from zero again while the server's decoder still holds the dead session's blocks on exactly those
// ids, so without the reset at the staged-session promotion the new shards are swallowed by the done guard
// and the packet is lost. This covers the SERVER-side install site, reached from the keepalive ping.
func TestUDPFecDecoderResetAfterClientRestart(t *testing.T) {
	srvDev, srvCtrl := tunPair(t, "frsrv")
	cli1Dev, cli1Ctrl := tunPair(t, "frcli1")
	cli2Dev, cli2Ctrl := tunPair(t, "frcli2")
	ka := fecResetKeepalive
	addr := freeUDPPort(t)

	srv, err := Listen([]string{addr}, srvDev, ka, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli1, err := Dial(addr, cli1Dev, ka, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	go srv.Run()
	go cli1.Run()
	t.Cleanup(func() { srv.Close() })
	waitUntil(t, "the first tunnel to come up", 5*time.Second, func() bool { return cli1.sealer() != nil })

	seedBlocks(t, cli1Ctrl, srvCtrl, 3)
	first := srv.peer.Load()
	if first == nil {
		t.Fatal("the server never learned the first client")
	}
	cli1.Close()

	cli2, err := Dial(addr, cli2Dev, ka, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Dial (restarted client): %v", err)
	}
	go cli2.Run()
	t.Cleanup(func() { cli2.Close() })
	// The server installs the new session only when a frame opens under it — the restarted client's
	// keepalive ping — and learnPeer runs in the same step, so the new source port IS the install signal.
	// Waiting on it also pins the write below to after the install site has run.
	waitUntil(t, "the server to install the restarted client's session", 8*time.Second, func() bool {
		p := srv.peer.Load()
		return p != nil && p.String() != first.String()
	})

	pkt := bytes.Repeat([]byte{0x5C}, fecSeedLen)
	if _, err := cli2Ctrl.Write(pkt); err != nil {
		t.Fatalf("inject restarted client->server: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "restarted client->server"); !bytes.Equal(got, pkt) {
		t.Fatalf("restarted client->server payload mismatch: got %d bytes", len(got))
	}
}

// TestUDPFecDecoderResetAfterServerRestart is the mirror: the SERVER restarts, so it is the CLIENT's
// decoder that still holds the dead session's blocks when the fresh server starts numbering from zero.
// This covers the client-side install site, reached from the handshake RESP.
//
// The re-handshake is the JUDGE's, which is why the status file is wired: a client cannot tell a peer
// that restarted from one that is merely quiet, so it is told. This is therefore also the end-to-end
// proof that a real pair recovers from a real server restart with no clock involved.
func TestUDPFecDecoderResetAfterServerRestart(t *testing.T) {
	srv1Dev, srv1Ctrl := tunPair(t, "frsrv1")
	srv2Dev, srv2Ctrl := tunPair(t, "frsrv2")
	cliDev, cliCtrl := tunPair(t, "frcli")
	ka := fecResetKeepalive
	addr := freeUDPPort(t)

	srv1, err := Listen([]string{addr}, srv1Dev, ka, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err := Dial(addr, cliDev, ka, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	cli.SetStatusPath(filepath.Join(t.TempDir(), "core.json")) // the verdict mailbox hangs off it
	go srv1.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close() })
	// Downstream needs BOTH ends up: the server drops what it cannot seal, and it installs the session
	// only once a frame opens under it.
	waitUntil(t, "the first tunnel to come up", 5*time.Second,
		func() bool { return srv1.sealer() != nil && srv1.peer.Load() != nil })

	seedBlocks(t, srv1Ctrl, cliCtrl, 3)
	srv1.Close()

	srv2, err := Listen([]string{addr}, srv2Dev, ka, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Listen (restarted server): %v", err)
	}
	go srv2.Run()
	t.Cleanup(func() { srv2.Close() })
	// What the node's probe would say: nothing is crossing. udp declares no source-port axis, so rung
	// zero is not there to spend and this lands straight on the handshake.
	liveVerdict(t, cli.st.verdictPath(), settledEpoch(t, cli.st), poolCmd{Cmd: cmdFail})
	waitUntil(t, "the client to re-handshake with the restarted server", 10*time.Second,
		func() bool { return srv2.sealer() != nil && srv2.peer.Load() != nil })

	pkt := bytes.Repeat([]byte{0x5C}, fecSeedLen)
	if _, err := srv2Ctrl.Write(pkt); err != nil {
		t.Fatalf("inject restarted server->client: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "restarted server->client"); !bytes.Equal(got, pkt) {
		t.Fatalf("restarted server->client payload mismatch: got %d bytes", len(got))
	}
}

// TestFecDecoderResetFromDeliver pins the structural half the two tunnel tests cannot reach on demand:
// the carriers install a session from deliver(), which input() may already be running under d.mu, so
// reset() must not take that lock. A reset that locked would hang here rather than fail. The clear must
// still land — the block fed before it, and its share of the byte budget, must be gone by the next input.
func TestFecDecoderResetFromDeliver(t *testing.T) {
	var d *fecDecoder
	delivered := 0
	d = newFecDecoder(func([]byte) {
		delivered++
		d.reset() // exactly what handleCrypto does when it promotes a staged session
	})

	d.input(fecDataShard(7, 4, 2))
	if delivered != 1 {
		t.Fatalf("the shard was not delivered (%d), so reset() was never reached from deliver()", delivered)
	}
	oneBlock := d.bytes
	if len(d.blocks) != 1 || oneBlock == 0 {
		t.Fatalf("block 7 should still be held until the next input(): %d blocks, %d bytes", len(d.blocks), oneBlock)
	}

	d.input(fecDataShard(9, 4, 2))
	if _, ok := d.blocks[7]; ok {
		t.Fatal("the pending reset did not clear the old session's block 7")
	}
	if d.bytes != oneBlock {
		t.Fatalf("byte budget = %d, want %d (block 9 alone) — the reset must zero it with the blocks", d.bytes, oneBlock)
	}
}
