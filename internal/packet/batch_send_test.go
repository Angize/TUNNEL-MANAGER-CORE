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

// The cheap half of the condition has to be tested FIRST. canBatch reaches an atomic and an interface
// method; Queued is a slice length. With the two the other way round the expensive half ran on every
// packet even on a tunnel that never batches — MEASURED at about -7% with GSO off, where the queue is
// always empty. There is no way to observe evaluation order from outside, so this reads the source.
func TestTheCheapConditionIsTestedFirst(t *testing.T) {
	b, err := os.ReadFile("raw_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "r.dev.Queued() > 0 && r.canBatch()")
	j := strings.Index(src, "r.canBatch() && r.dev.Queued() > 0")
	if j >= 0 {
		t.Fatal("canBatch() is evaluated before Queued(), so its cost is paid per packet on every " +
			"carrier — including the ones that can never batch")
	}
	if i < 0 {
		t.Fatal("the batch condition is not the expected shape; check whether it still short-circuits " +
			"on the cheap test")
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
