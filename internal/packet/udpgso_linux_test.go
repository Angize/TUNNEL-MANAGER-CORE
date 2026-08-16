//go:build linux

package packet

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// txTo opens a udpTx aimed at a real listening socket, and returns both ends.
func txTo(t *testing.T) (*udpTx, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close() })
	tx := newUDPTx(cli)
	if tx == nil {
		t.Fatal("no udpTx on linux")
	}
	return tx, srv, srv.LocalAddr().(*net.UDPAddr)
}

// frames of one size must arrive as that many SEPARATE datagrams, each whole.
//
// The failure this pins is silent and total: get the segment size or the buffer layout wrong and the
// peer receives one giant datagram, or segments cut at the wrong offset. Every one then fails the AEAD
// and is dropped without a word, so the tunnel simply carries nothing while every counter looks fine.
func TestASegmentedSendArrivesAsSeparateWholeDatagrams(t *testing.T) {
	tx, srv, to := txTo(t)
	const n, size = 8, 200
	want := make([]string, n)
	tx.reset()
	for i := 0; i < n; i++ {
		p := make([]byte, size)
		copy(p, fmt.Sprintf("frame-%02d", i))
		for k := 9; k < size; k++ {
			p[k] = byte('a' + i)
		}
		want[i] = string(p)
		tx.add(p, to)
	}
	segs, sz := tx.gsoRun()
	if segs != n || sz != size {
		t.Fatalf("gsoRun() = (%d,%d), want (%d,%d): the uniform run was not recognised", segs, sz, n, size)
	}
	var errs sendErrLog
	if got := tx.flush(&errs); got != n {
		t.Fatalf("flush sent %d of %d", got, n)
	}

	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	for i := 0; i < n; i++ {
		m, _, err := srv.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("datagram %d never arrived (%v) — the run was sent as one, not %d", i, err, n)
		}
		if m != size {
			t.Fatalf("datagram %d is %d bytes, want %d: the segment size did not reach the kernel", i, m, size)
		}
		if string(buf[:m]) != want[i] {
			t.Fatalf("datagram %d has the wrong bytes: segments were cut at the wrong offset", i)
		}
	}
}

// A run may end in ONE shorter frame, which is the kernel's rule and the common tail of a burst.
func TestASegmentedSendAllowsOneShorterTail(t *testing.T) {
	tx, srv, to := txTo(t)
	tx.reset()
	for _, l := range []int{300, 300, 300, 120} {
		tx.add(make([]byte, l), to)
	}
	segs, size := tx.gsoRun()
	if segs != 4 || size != 300 {
		t.Fatalf("gsoRun() = (%d,%d), want (4,300): a short tail must still ride the run", segs, size)
	}
	var errs sendErrLog
	if got := tx.flush(&errs); got != 4 {
		t.Fatalf("flush sent %d of 4", got)
	}
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	for i, want := range []int{300, 300, 300, 120} {
		m, _, err := srv.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("datagram %d never arrived: %v", i, err)
		}
		if m != want {
			t.Fatalf("datagram %d is %d bytes, want %d", i, m, want)
		}
	}
}

// A LONGER frame after the first ends the run there: the kernel cuts every segment but the last to one
// size, so letting a bigger one in would truncate it and hand the peer a frame that cannot open.
func TestARunStopsAtTheFirstFrameThatWouldNotFit(t *testing.T) {
	for _, tc := range []struct {
		name string
		lens []int
		segs int
	}{
		{"a longer frame ends the run", []int{100, 100, 400, 100}, 2},
		{"a shorter frame ends it too, but rides it", []int{100, 100, 60, 100}, 3},
		{"one frame is not worth a control message", []int{100}, 0},
		{"two of a size is", []int{100, 100}, 2},
		{"a first frame of zero is refused", []int{0, 0}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, _, to := txTo(t)
			tx.reset()
			for _, l := range tc.lens {
				tx.add(make([]byte, l), to)
			}
			if segs, _ := tx.gsoRun(); segs != tc.segs {
				t.Fatalf("gsoRun() gave %d segments, want %d", segs, tc.segs)
			}
		})
	}
}

// Neither kernel limit may be crossed: past 64 KiB or 64 segments the write fails ENTIRELY rather than
// sending what fits, so a burst that reached either would vanish.
func TestARunStaysUnderTheKernelLimits(t *testing.T) {
	tx, _, to := txTo(t)
	tx.reset()
	for i := 0; i < maxBatch; i++ {
		tx.add(make([]byte, 1400), to)
	}
	segs, size := tx.gsoRun()
	if segs > gsoMaxSegs {
		t.Fatalf("%d segments, over the %d cap", segs, gsoMaxSegs)
	}
	if segs*size > gsoMaxBytes {
		t.Fatalf("%d bytes, over the %d cap", segs*size, gsoMaxBytes)
	}
	if segs < 2 {
		t.Fatalf("a full burst of equal frames produced only %d segments", segs)
	}
}

// Whatever the run leaves behind must still go. A burst is only partly uniform far more often than not,
// and frames silently dropped between the two paths are indistinguishable from network loss.
func TestEveryFrameLeavesEvenWhenOnlyPartOfTheBurstIsUniform(t *testing.T) {
	tx, srv, to := txTo(t)
	tx.reset()
	lens := []int{250, 250, 250, 900, 120, 900}
	for _, l := range lens {
		tx.add(make([]byte, l), to)
	}
	var errs sendErrLog
	if got := tx.flush(&errs); got != len(lens) {
		t.Fatalf("flush sent %d of %d frames", got, len(lens))
	}
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	got := 0
	for range lens {
		if _, _, err := srv.ReadFromUDP(buf); err != nil {
			break
		}
		got++
	}
	if got != len(lens) {
		t.Fatalf("%d of %d datagrams arrived: frames were lost between the segmented run and the "+
			"fallback", got, len(lens))
	}
}
