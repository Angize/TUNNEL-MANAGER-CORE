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

	fecResetKeepalive = time.Second
)

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

func TestUDPFecDecoderResetAfterClientRestart(t *testing.T) {
	defer func(d time.Duration) { pingEvery = d }(pingEvery)
	pingEvery = fecResetKeepalive
	srvDev, srvCtrl := tunPair(t, "frsrv")
	cli1Dev, cli1Ctrl := tunPair(t, "frcli1")
	cli2Dev, cli2Ctrl := tunPair(t, "frcli2")
	addr := freeUDPPort(t)

	srv, err := Listen([]string{addr}, srvDev, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli1, err := Dial(addr, cli1Dev, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
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

	cli2, err := Dial(addr, cli2Dev, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Dial (restarted client): %v", err)
	}
	go cli2.Run()
	t.Cleanup(func() { cli2.Close() })

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

func TestUDPFecDecoderResetAfterServerRestart(t *testing.T) {
	defer func(d time.Duration) { pingEvery = d }(pingEvery)
	pingEvery = fecResetKeepalive
	srv1Dev, srv1Ctrl := tunPair(t, "frsrv1")
	srv2Dev, srv2Ctrl := tunPair(t, "frsrv2")
	cliDev, cliCtrl := tunPair(t, "frcli")
	addr := freeUDPPort(t)

	srv1, err := Listen([]string{addr}, srv1Dev, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err := Dial(addr, cliDev, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	cli.SetStatusPath(filepath.Join(t.TempDir(), "core.json"))
	go srv1.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	waitUntil(t, "the first tunnel to come up", 5*time.Second,
		func() bool { return srv1.sealer() != nil && srv1.peer.Load() != nil })

	seedBlocks(t, srv1Ctrl, cliCtrl, 3)
	srv1.Close()

	srv2, err := Listen([]string{addr}, srv2Dev, false, true, fecResetPSK, fecResetCipher, true, 4, 2)
	if err != nil {
		t.Fatalf("Listen (restarted server): %v", err)
	}
	go srv2.Run()
	t.Cleanup(func() { srv2.Close() })

	spendThePortRung(t, cli, func() {
		liveVerdict(t, cli.st.verdictPath(), settledEpoch(t, cli.st), poolCmd{Cmd: cmdFail})
	})
	liveVerdict(t, cli.st.verdictPath(), settledEpoch(t, cli.st), poolCmd{Cmd: cmdFail})
	waitUntil(t, "the client to re-handshake with the restarted server", 25*time.Second,
		func() bool { return srv2.sealer() != nil && srv2.peer.Load() != nil })

	pkt := bytes.Repeat([]byte{0x5C}, fecSeedLen)
	if _, err := srv2Ctrl.Write(pkt); err != nil {
		t.Fatalf("inject restarted server->client: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "restarted server->client"); !bytes.Equal(got, pkt) {
		t.Fatalf("restarted server->client payload mismatch: got %d bytes", len(got))
	}
}

func TestFecDecoderResetFromDeliver(t *testing.T) {
	var d *fecDecoder
	delivered := 0
	d = fecDecoderFor(t, 4, 2, func([]byte) {
		delivered++
		d.reset()
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
