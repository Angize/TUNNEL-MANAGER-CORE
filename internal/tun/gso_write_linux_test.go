//go:build linux

package tun

import (
	"bytes"
	"os"
	"syscall"
	"testing"
)

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

func TestAGSOWriteAllocatesNothingPerPacket(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("open %s: %v", os.DevNull, err)
	}
	defer f.Close()

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
