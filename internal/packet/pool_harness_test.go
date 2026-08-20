package packet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const probePSK = "probe-shared-pre-shared-key-1234567890"

func probePair(t *testing.T, tag string, extra ...string) (cli, srv *UDP, a1, a2 string, cliCtrl, srvCtrl *os.File) {
	t.Helper()
	srvDev, sc := tunPair(t, tag+"s")
	cliDev, cc := tunPair(t, tag+"c")
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	a1 = fmt.Sprintf("127.0.0.1:%d", port)
	a2 = fmt.Sprintf("127.0.0.2:%d", port)
	srv, err = Listen([]string{a1, a2}, srvDev, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err = Dial(a1, cliDev, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	dir := t.TempDir()
	cli.SetStatusPath(filepath.Join(dir, "core.json"))
	cli.SetPeerPool(NewPeerPool(append([]string{a1, a2}, extra...), 0))
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	pkt := bytes.Repeat([]byte{0xC7}, 120)
	deadline := time.Now().Add(10 * time.Second)
	for !cli.peerAnswered.Load() {
		if _, err := cc.Write(pkt); err != nil {
			t.Fatalf("inject: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the tunnel never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cli, srv, a1, a2, cc, sc
}

// A status path for a carrier that keeps RUNNING past the end of the test: the writer is a one-second
// sampler, so a t.TempDir() gets removed out from under it while the teardown is still in flight.
func runningStatusPath(t *testing.T, closer interface{ Close() error }) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "corestatus")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closer.Close()
		time.Sleep(150 * time.Millisecond) // let the sampler notice closeCh before the directory goes
		os.RemoveAll(dir)
	})
	return filepath.Join(dir, "core.status")
}

// A ws edge carrier wired the way SetStatusPath wires one in production: the pool reports through the
// tunnel's one status file, and the walk is bound to its two axes.
func edgeCarrier(t *testing.T, ips []string, snis []wsSNIEntry) (*TCP, *wsPool) {
	t.Helper()
	p := newWSPool(ips, snis)
	b := &TCP{isClient: true, ws: true, wsTLS: true, pool: p, addr: "pool", closeCh: make(chan struct{})}
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	return b, p
}

// The same for a direct carrier. src may be nil for a destination-only pool.
func peerCarrier(t *testing.T, dst, src []string) (*TCP, *PeerPool, *PeerPool) {
	t.Helper()
	b := &TCP{isClient: true, closeCh: make(chan struct{})}
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	pp := NewPeerPool(dst, 0)
	b.SetPeerPool(pp)
	var sp *PeerPool
	if src != nil {
		sp = NewPeerPool(src, 0)
		b.SetSourcePool(sp)
	}
	return b, pp, sp
}

// What the carrier is on, as the node would read it out of the status file.
func (b *TCP) pretendConnected(low, high string) {
	b.livePair.Store(&pairNow{low: low, high: high})
	b.cur.Store(&connFramer{})
	b.st.write() // production republishes on a one-second sampler; a test must not read a stale pair
}

func (b *TCP) pretendDown() {
	b.livePair.Store(nil)
	b.cur.Store(nil)
	b.st.write()
}

// A verdict as it actually arrives: written into the carrier's mailbox and read on the poll. A test that
// calls the walk directly says nothing about the arms in front of it.
func (b *TCP) deliver(t *testing.T, c poolCmd, path string) bool {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return b.rc.poll(b.rotateLowTCP, b.rotateHighTCP, b.pinApplied, b.st.pathEpoch)
}

func (b *TCP) tunFail(t *testing.T, low, high string) bool {
	t.Helper()
	return b.deliver(t, poolCmd{Cmd: cmdFail, Low: low, High: high, Epoch: b.st.pathEpoch()}, b.st.verdictPath())
}

func (b *TCP) tunOK(t *testing.T, low, high string) bool {
	t.Helper()
	return b.deliver(t, poolCmd{Cmd: cmdOK, Low: low, High: high, Epoch: b.st.pathEpoch()}, b.st.verdictPath())
}

func (b *TCP) operatorPin(t *testing.T, kind, key string) bool {
	t.Helper()
	return b.deliver(t, poolCmd{Kind: kind, Key: key}, b.st.pinPath())
}

func (b *TCP) operatorRetest(t *testing.T, kind, key string) bool {
	t.Helper()
	return b.deliver(t, poolCmd{Cmd: cmdRetest, Kind: kind, Key: key}, b.st.pinPath())
}

// The status file, parsed the way the node parses it.
func (b *TCP) readStatus(t *testing.T) struct {
	Active string         `json:"active"`
	Epoch  int64          `json:"epoch"`
	Ready  bool           `json:"ready"`
	Pair   pairStatus     `json:"pair"`
	Health []healthStatus `json:"health"`
	Events []coreEvent    `json:"events"`
} {
	t.Helper()
	var st struct {
		Active string         `json:"active"`
		Epoch  int64          `json:"epoch"`
		Ready  bool           `json:"ready"`
		Pair   pairStatus     `json:"pair"`
		Health []healthStatus `json:"health"`
		Events []coreEvent    `json:"events"`
	}
	data, err := os.ReadFile(b.st.path)
	if err != nil {
		t.Fatalf("status file: %v", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("status file: %v", err)
	}
	return st
}

// A whole outage, the way the node delivers one: a verdict every sweep until the pool actually moves.
// The ladder answers the first ones with its free rungs -- a redraw of the source port blames nobody --
// and only the last one walks. A test that sends ONE verdict and expects a step is testing a ladder
// with no rungs.
func (b *TCP) tunFailUntilItMoves(t *testing.T, low, high string) bool {
	t.Helper()
	for i := 0; i < portTries+2; i++ {
		if b.tunFail(t, low, high) {
			return true
		}
	}
	return false
}
