//go:build linux

package packet

import (
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/ipv4"
)

func TestOnlyAPlainSendPathBatches(t *testing.T) {

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

		{"a pinned source still batches — sendmmsg carries its control message",
			func(r *Raw) { r.replySrc.Store(&net.IP{10, 0, 0, 1}) }, true},
		{"a forged link sends on its own socket",
			func(r *Raw) { r.link = &fakeFDLink{fd: 7} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Raw{batch: pc, link: &fakeFDLink{fd: -1}}
			tc.set(r)
			q := &txQueue{batch: r.batch}
			if got := r.canBatch(q); got != tc.want {
				t.Fatalf("canBatch() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestABatchedSendCarriesThePinnedSource(t *testing.T) {
	src := string(mustRead(t, "raw_linux.go"))
	i := strings.Index(src, "if r.canBatch(q) {")
	if i < 0 {
		t.Fatal("the batch block is not the expected shape; check what guards it now")
	}
	body := src[i:]
	if end := strings.Index(body, "r.writeOut(pkt, peer)"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "r.pinnedSrc()") || !strings.Contains(body, "r.srcOOB(") {
		t.Fatal("the batch block never asks for the pinned source, so a server's burst would leave " +
			"from the kernel's default IP")
	}

	if n := strings.Count(body, ".OOB = "); n < 2 {
		t.Fatalf("only %d message(s) in the batch get a control message; the drained ones would go out "+
			"unpinned", n)
	}
}

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

	if batchConn((*net.IPConn)(nil)) != nil {
		t.Fatal("wrapping a typed-nil socket produced a non-nil batcher")
	}
}

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
