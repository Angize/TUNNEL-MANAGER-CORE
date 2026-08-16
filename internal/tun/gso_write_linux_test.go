//go:build linux

package tun

import (
	"bytes"
	"os"
	"syscall"
	"testing"
)

// rawGSOPair is a GSO Device holding a REAL fd, as production does, plus the peer standing in for the
// kernel. FromFileGSO cannot serve here: it sets fd<0, which takes the joining fallback and so says
// nothing about the path every received packet actually goes through.
func rawGSOPair(t *testing.T) (*Device, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	dev := &Device{f: os.NewFile(uintptr(fds[0]), "gso-w"), fd: fds[0], Name: "gso-w", gso: true}
	peer := os.NewFile(uintptr(fds[1]), "gso-w-peer")
	t.Cleanup(func() { dev.Close(); peer.Close() })
	return dev, peer
}

// A GSO write must reach the kernel as ONE packet carrying the ten-byte header the interface was opened
// to expect, with the packet whole behind it. Two iovecs are an implementation detail the kernel must
// not be able to observe -- a scatter that arrived as two writes would be two malformed frames.
func TestAGSOWriteArrivesAsOnePacketBehindItsHeader(t *testing.T) {
	dev, peer := rawGSOPair(t)
	pkt := tcp4(120)

	if n, err := dev.Write(pkt); err != nil || n != len(pkt) {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(pkt))
	}
	buf := make([]byte, 4096)
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if want := vnetHdrLen + len(pkt); n != want {
		t.Fatalf("kernel saw %d bytes, want %d — the header and the packet did not arrive as one write", n, want)
	}
	if got := buf[:vnetHdrLen]; !bytes.Equal(got, make([]byte, vnetHdrLen)) {
		t.Fatalf("virtio header = % x, want all zero (one complete packet, checksums done)", got)
	}
	if got := buf[vnetHdrLen:n]; !bytes.Equal(got, pkt) {
		t.Fatalf("packet was altered in flight: got %d bytes, want the %d written", len(got), len(pkt))
	}
}

// Consecutive writes must stay separate packets. A gather that leaked into the next write would splice
// two L3 packets into one frame, which the interface would drop as malformed.
func TestAGSOWriteDoesNotSmearIntoTheNextPacket(t *testing.T) {
	dev, peer := rawGSOPair(t)
	first, second := tcp4(40), tcp4(80)

	for _, p := range [][]byte{first, second} {
		if _, err := dev.Write(p); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	buf := make([]byte, 4096)
	for _, want := range [][]byte{first, second} {
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatalf("peer read: %v", err)
		}
		if n != vnetHdrLen+len(want) || !bytes.Equal(buf[vnetHdrLen:n], want) {
			t.Fatalf("read %d bytes, want %d holding exactly one packet", n, vnetHdrLen+len(want))
		}
	}
}

// The point of the two iovecs: a received packet must reach the TUN without a per-packet allocation.
// Prepending the header by joining cost one allocation and one copy of the whole packet, on the single
// hottest call of a receiving core -- an allocation here is the defect, so the test measures allocations.
func TestAGSOWriteAllocatesNothingPerPacket(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("open %s: %v", os.DevNull, err)
	}
	defer f.Close()
	// /dev/null rather than a socketpair: it swallows every write, so the measurement is the write path
	// and never a buffer filling up.
	dev := &Device{f: f, fd: int(f.Fd()), Name: "null", gso: true}
	pkt := tcp4(1360)

	if n := testing.AllocsPerRun(200, func() {
		if _, err := dev.Write(pkt); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}); n != 0 {
		t.Fatalf("Write allocates %.1f times per packet, want 0", n)
	}
}

// The device the tests use elsewhere has no raw fd and must keep working: it joins the two pieces
// instead of gathering them, and the bytes that come out must be identical.
func TestAGSOWriteWithoutARawFDStillCarriesTheHeader(t *testing.T) {
	dev, peer := gsoPair(t)
	pkt := tcp4(64)

	if _, err := dev.Write(pkt); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if n != vnetHdrLen+len(pkt) || !bytes.Equal(buf[vnetHdrLen:n], pkt) {
		t.Fatalf("read %d bytes, want %d holding the packet behind a header", n, vnetHdrLen+len(pkt))
	}
}
