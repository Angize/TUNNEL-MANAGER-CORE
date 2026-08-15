//go:build linux

package packet

import (
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/ipv4"
)

// A burst leaves in one syscall instead of one per packet. MEASURED in a netns: ~500 Mbit/s of
// 1400-byte packets is ~45,000 sendto per second per direction, and the core sat at ~90% of ONE cpu in
// every configuration tried. Batching that carried raw/bare from ~464 to ~661 Mbit/s.
//
// What the tests here pin is the part that can go wrong silently — WHEN the fast path is taken. It
// changes which socket call carries the bytes, so a carrier that needs per-packet work at the socket
// must never reach it, and the cost of asking must not land on the carriers that never batch.

func TestOnlyAPlainSendPathBatches(t *testing.T) {
	// The fast path is "write these bytes to that address" and nothing else. Everything with per-packet
	// work at the socket keeps the single-packet path — which is also the only one it has ever had.
	pc := &ipv4.PacketConn{}
	for _, tc := range []struct {
		name string
		set  func(r *Raw)
		want bool
	}{
		{"a plain carrier batches", func(r *Raw) {}, true},
		{"no wrapped socket: nothing to batch with", func(r *Raw) { r.batch = nil }, false},
		{"FEC: shards leave on a callback, not from this loop",
			func(r *Raw) { r.fecEnc = &fecEncoder{} }, false},
		{"a pinned source needs its own control message per packet",
			func(r *Raw) { r.replySrc.Store(&net.IP{10, 0, 0, 1}) }, false},
		{"a forged link sends on its own socket",
			func(r *Raw) { r.link = &fakeFDLink{fd: 7} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Raw{batch: pc, link: &fakeFDLink{fd: -1}}
			tc.set(r)
			if got := r.canBatch(); got != tc.want {
				t.Fatalf("canBatch() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A batch must never WAIT for a second packet. The drain uses TryRead, which reports "nothing there"
// instead of sleeping; with a plain Read in that loop a tunnel carrying one packet at a time would
// hold each one until the next arrived, turning an idle link into a stalled one. There is no way to
// observe that from outside a running tunnel, so this reads the source.
func TestTheBatchDrainNeverWaits(t *testing.T) {
	b, err := os.ReadFile("raw_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "for n < maxBatch {")
	if i < 0 {
		t.Fatal("the drain loop is not the expected shape; check what bounds it now")
	}
	body := src[i:]
	if end := strings.Index(body, "\n\t\t\t}"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "TryRead") {
		t.Fatal("the drain does not use TryRead, so it can block waiting for a packet that never comes")
	}
}

// A short write is the kernel saying "I took this many". Re-sending the rest would duplicate packets
// that already left, and a datagram carrier drops rather than blocks anyway — the tunnelled L4
// retransmits. So sendBatch reports what went and never retries.
func TestSendBatchIsSafeWhenThereIsNothingToSend(t *testing.T) {
	if n := sendBatch(nil, []ipv4.Message{{}}); n != 0 {
		t.Fatalf("a nil socket sent %d", n)
	}
	if n := sendBatch(&ipv4.PacketConn{}, nil); n != 0 {
		t.Fatalf("an empty batch sent %d", n)
	}
	if batchConn(nil) != nil {
		t.Fatal("wrapping a nil socket produced a non-nil batcher")
	}
	// The shape that actually reaches a guard like this one: a TYPED nil. An interface parameter would
	// have carried it past the test above and into a dereference, so the literal nil alone proves
	// nothing about the case that can really happen.
	if batchConn((*net.IPConn)(nil)) != nil {
		t.Fatal("wrapping a typed-nil socket produced a non-nil batcher")
	}
}

// maxBatch bounds the message array. The TUN's queue holds at most one super-packet's worth of
// segments (64 KB / MSS ≈ 45 at 1400), so the cap must sit above that — otherwise a burst is split
// across two syscalls for no reason, which is the cost this whole change exists to remove.
func TestMaxBatchClearsOneSuperPacket(t *testing.T) {
	if maxBatch < 64*1024/1400 {
		t.Fatalf("maxBatch %d is under one super-packet's segment count", maxBatch)
	}
}

type fakeFDLink struct {
	ipLink
	fd int
}

func (f *fakeFDLink) fakeFD() int { return f.fd }

// Every slot of the batch must be pointed at ITS OWN packet. The array and its one-element Buffers
// slices are reused across batches now, so writing through a fixed index -- ms[0] instead of ms[n] --
// would send N copies of one packet and drop the rest, with the right count and the right length going
// out and nothing logged. Only the far end would see it, as a stream that stops making sense.
func TestEachBatchSlotCarriesItsOwnPacket(t *testing.T) {
	src := string(mustRead(t, "raw_linux.go"))
	i := strings.Index(src, "for n < maxBatch {")
	if i < 0 {
		t.Fatal("the drain loop is not the expected shape")
	}
	body := src[i:]
	if end := strings.Index(body, "\n\t\t\t}"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "ms[n].Buffers[0]") {
		t.Fatal("the drain does not fill ms[n]: a fixed index would send one packet many times")
	}
	if strings.Contains(body, "ms[0].Buffers[0]") {
		t.Fatal("the drain writes through ms[0] inside the loop, overwriting every earlier packet")
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
