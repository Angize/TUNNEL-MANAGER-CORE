//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// Received packets are written across the TUN's queues, one writer each, and the writer is chosen from
// the packet's own flow.
//
// The failure that matters leaves a WORKING tunnel: send a connection's packets to two different
// writers and they reach the TUN out of order. Nothing errors, nothing logs, every byte still arrives
// -- and the tunnelled tcp reads its own reordering as loss and throttles itself. Throughput goes DOWN
// and the only symptom is a number. So these pin the choice of writer, not whether it works.

// flowPkt builds a minimal IPv4 packet with the given addresses, protocol and ports.
func flowPkt(t *testing.T, src, dst string, proto byte, sport, dport uint16) []byte {
	t.Helper()
	p := make([]byte, 24)
	p[0] = 0x45 // version 4, ihl 5
	p[9] = proto
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	return p
}

func TestOneFlowAlwaysGoesToOneWriter(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proto byte
	}{{"tcp", 6}, {"udp", 17}} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := flowPkt(t, "10.0.0.1", "10.0.0.2", tc.proto, 1234, 443)
			want := flowHash(pkt)
			for i := 0; i < 50; i++ {
				// a fresh copy each time, as the receive path hands over a fresh buffer per frame
				again := append([]byte(nil), pkt...)
				if got := flowHash(again); got != want {
					t.Fatalf("the same flow hashed to %d and %d: its packets would split across writers",
						want, got)
				}
			}
		})
	}
}

func TestDifferentFlowsDoNotAllLandOnOneWriter(t *testing.T) {
	// 64 connections from one host to one host, as a browser or a download manager opens
	seen := map[uint32]int{}
	for port := 1024; port < 1088; port++ {
		seen[flowHash(flowPkt(t, "10.0.0.1", "10.0.0.2", 6, uint16(port), 443))%4]++
	}
	if len(seen) < 2 {
		t.Fatal("64 connections all hashed to one writer: the spread is not happening at all")
	}
	for q, n := range seen {
		if n == 0 || n > 48 {
			t.Fatalf("writer %d got %d of 64 connections: the hash is lopsided", q, n)
		}
	}
}

// Every field that identifies a connection has to reach the hash. A hash that ignores the ports sends
// every connection between two hosts to one writer -- which is exactly the busy case.
func TestTheHashUsesAddressesAndPorts(t *testing.T) {
	base := flowPkt(t, "10.0.0.1", "10.0.0.2", 6, 1234, 443)
	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"source address", flowPkt(t, "10.0.0.9", "10.0.0.2", 6, 1234, 443)},
		{"destination address", flowPkt(t, "10.0.0.1", "10.0.0.9", 6, 1234, 443)},
		{"source port", flowPkt(t, "10.0.0.1", "10.0.0.2", 6, 9999, 443)},
		{"destination port", flowPkt(t, "10.0.0.1", "10.0.0.2", 6, 1234, 8443)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if flowHash(tc.pkt) == flowHash(base) {
				t.Fatalf("changing the %s did not change the writer: that field is not in the hash",
					tc.name)
			}
		})
	}
}

// Anything unparseable must land on queue 0 rather than on an arbitrary one: queue 0 is the reader's
// own, written inline, so an odd packet keeps the exact path it had.
func TestWhatCannotBeParsedGoesToTheReadersOwnQueue(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"runt", []byte{0x45, 0, 0}},
		{"not ipv4", append([]byte{0x60}, make([]byte, 40)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := flowHash(tc.pkt); got != 0 {
				t.Fatalf("hashed to %d, want 0", got)
			}
		})
	}
}

// A carrier with one queue must keep the path it had: written inline by the reader, with no channel
// and no second goroutine. Anything else adds a hop and a scheduling delay to every packet of every
// tunnel that never asked for workers.
func TestASingleQueueCarrierWritesInline(t *testing.T) {
	d, done := fakeDev(t)
	w := newTunWriters([]*tun.Device{d})
	defer w.close()
	if w.ch != nil {
		t.Fatal("a single-queue carrier built writer channels")
	}
	w.write(flowPkt(t, "10.0.0.1", "10.0.0.2", 6, 1234, 443))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the packet never reached the device")
	}
}

// Every packet must reach a device, whichever writer it is steered to -- a queue that is created but
// never drained is a blackhole for the flows the kernel puts on it.
func TestEveryQueueIsDrained(t *testing.T) {
	const queues = 4
	var mu sync.Mutex
	got := map[int]int{}
	var devs []*tun.Device
	var files []*os.File
	for i := 0; i < queues; i++ {
		r, wr, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, r, wr)
		devs = append(devs, tun.FromFile(wr, "q"))
		// BYTES, not reads: a pipe is a byte stream, so several packets can arrive in one Read and
		// counting reads would undercount them.
		go func(i int, r *os.File) {
			b := make([]byte, 4096)
			for {
				n, err := r.Read(b)
				if err != nil {
					return
				}
				mu.Lock()
				got[i] += n
				mu.Unlock()
			}
		}(i, r)
	}
	t.Cleanup(func() {
		for _, f := range files {
			f.Close()
		}
	})
	w := newTunWriters(devs)
	defer w.close()

	const flows, pktLen = 200, 24
	for port := 0; port < flows; port++ {
		w.write(flowPkt(t, "10.0.0.1", "10.0.0.2", 6, uint16(1024+port), 443))
	}
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		total, used := 0, len(got)
		for _, n := range got {
			total += n
		}
		mu.Unlock()
		if total == flows*pktLen && used > 1 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("%d of %d bytes arrived, across %d of %d queues", total, flows*pktLen, used, queues)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// The one that matters: ONE connection's packets must all reach the SAME writer.
//
// flowHash being right is not enough -- write has to actually use it. Anything that spreads packets by
// something other than the flow (a round robin, a counter, the queue depth) still delivers every byte
// and still fills every queue, so the drain test and the hash tests both stay green. What breaks is
// the ORDER inside a connection, and the only symptom is the tunnelled tcp slowing down.
func TestOneConnectionsPacketsAllReachOneWriter(t *testing.T) {
	devs, count := pipeDevs(t, 4)
	w := newTunWriters(devs)
	defer w.close()

	const packets, pktLen = 60, 24
	for i := 0; i < packets; i++ {
		// the SAME connection every time, as a download is
		w.write(flowPkt(t, "10.0.0.1", "10.0.0.2", 6, 1234, 443))
	}
	deadline := time.After(5 * time.Second)
	for {
		got := count()
		total, used := 0, 0
		for _, n := range got {
			total += n
			if n > 0 {
				used++
			}
		}
		if total == packets*pktLen {
			if used != 1 {
				t.Fatalf("one connection was spread across %d writers: its packets reach the TUN out "+
					"of order and the tunnelled tcp reads that as loss", used)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatalf("%d of %d bytes arrived across %d writers", total, packets*pktLen, used)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// pipeDevs returns n pipe-backed devices and a function reporting the bytes each has received.
func pipeDevs(t *testing.T, n int) ([]*tun.Device, func() []int) {
	t.Helper()
	var mu sync.Mutex
	got := make([]int, n)
	var devs []*tun.Device
	for i := 0; i < n; i++ {
		r, wr, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close(); wr.Close() })
		devs = append(devs, tun.FromFile(wr, "q"))
		go func(i int, r *os.File) {
			b := make([]byte, 4096)
			for {
				k, err := r.Read(b)
				if err != nil {
					return
				}
				mu.Lock()
				got[i] += k
				mu.Unlock()
			}
		}(i, r)
	}
	return devs, func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), got...)
	}
}

// fakeDev is a Device over a pipe, and a channel that fires when something is written to it.
func fakeDev(t *testing.T) (*tun.Device, chan struct{}) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	done := make(chan struct{})
	go func() {
		b := make([]byte, 64)
		if n, err := r.Read(b); err == nil && n > 0 {
			close(done)
		}
	}()
	return tun.FromFile(w, "q0"), done
}

// Every queue the interface has must have a READER, not just a writer.
//
// This is the bug that shipped in the first cut of this work and was only caught on a live tunnel: the
// receive side opened N queues and the send side still read from queue 0 alone. The kernel steers
// packets onto every queue it knows about, in BOTH directions, so queues 1..N-1 swallowed everything
// the send path was supposed to carry -- including the handshake. The tunnel did not run slow, it
// never came up.
//
// Nothing about the shape of the code says the two counts must match, so it is asserted here.
func TestEveryQueueOpenedAlsoGetsASendLoop(t *testing.T) {
	src := string(mustRead(t, "raw_linux.go"))
	if !strings.Contains(src, "for i := range r.txq {") {
		t.Fatal("Run does not start a loop per send queue: any queue past the first is a blackhole for " +
			"whatever the kernel steers onto it")
	}
	// and the loops must read their OWN queue, not the carrier's first device
	if strings.Contains(src, "r.dev.Read(buf)") || strings.Contains(src, "r.dev.TryRead(buf)") {
		t.Fatal("a send loop still reads r.dev: every loop would drain queue 0 and none would drain " +
			"the rest")
	}
}

// The two halves must agree on how many queues there are. A carrier that writes across N queues but
// reads from M of them blackholes the difference, whichever way round it is.
func TestTheReadAndWriteHalvesUseTheSameQueues(t *testing.T) {
	c, err := net.ListenIP("ip4:253", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Skipf("no raw socket here (needs root): %v", err)
	}
	defer c.Close()
	devs, count := pipeDevs(t, 3)
	r := newRaw(c, devs[0], 0, false, "", "", "bare", true)
	r.proto = 253
	r.rxw = newTunWriters(devs)
	if err := r.buildTxQueues(devs[1:], r.proto); err != nil {
		t.Skipf("cannot open the extra send sockets here: %v", err)
	}
	defer r.closeTxQueues()
	_ = count
	if len(r.txq) != len(r.rxw.devs) {
		t.Fatalf("%d send queues against %d receive queues: the difference is a blackhole",
			len(r.txq), len(r.rxw.devs))
	}
	for i := range r.txq {
		if r.txq[i].dev != r.rxw.devs[i] {
			t.Fatalf("queue %d is read from one device and written to another", i)
		}
	}
}

// Each pipeline needs a socket of its OWN. Sharing one still sends every packet -- it just does it one
// at a time behind go's per-socket write lock, so the tunnel works and the parallelism does not.
func TestEachSendQueueHasItsOwnSocket(t *testing.T) {
	c, err := net.ListenIP("ip4:254", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Skipf("no raw socket here (needs root): %v", err)
	}
	defer c.Close()
	devs, _ := pipeDevs(t, 3)
	r := newRaw(c, devs[0], 0, false, "", "", "bare", true)
	r.proto = 254
	if err := r.buildTxQueues(devs[1:], r.proto); err != nil {
		t.Skipf("cannot open the extra send sockets here: %v", err)
	}
	defer r.closeTxQueues()
	seen := map[*ipv4.PacketConn]bool{}
	for i, q := range r.txq {
		if q.batch == nil {
			t.Fatalf("queue %d has no socket to send on", i)
		}
		if seen[q.batch] {
			t.Fatalf("queue %d shares a socket with an earlier one: they queue behind one write lock", i)
		}
		seen[q.batch] = true
	}
}
