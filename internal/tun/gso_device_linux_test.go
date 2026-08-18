//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"strings"
	"syscall"
	"testing"
)

func gsoPair(t *testing.T) (*Device, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	dev := FromFileGSO(os.NewFile(uintptr(fds[0]), "gso-dev"), "gso-dev")
	peer := os.NewFile(uintptr(fds[1]), "gso-peer")
	t.Cleanup(func() { dev.Close(); peer.Close() })
	return dev, peer
}

func vnetPacket(flags, gsoType byte, gsoSize int, pkt []byte) []byte {
	out := make([]byte, vnetHdrLen+len(pkt))
	out[0] = flags
	out[1] = gsoType
	binary.LittleEndian.PutUint16(out[4:6], uint16(gsoSize))
	copy(out[vnetHdrLen:], pkt)
	return out
}

func tcp4(payload int) []byte {
	pkt := make([]byte, 20+20+payload)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:22], 1234)
	binary.BigEndian.PutUint16(pkt[22:24], 443)
	pkt[32] = 5 << 4
	pkt[33] = 0x18
	binary.BigEndian.PutUint16(pkt[36:38], 0xbeef)
	for i := 40; i < len(pkt); i++ {
		pkt[i] = byte(i)
	}
	return pkt
}

func l4csum(pkt []byte) uint16 { return binary.BigEndian.Uint16(pkt[36:38]) }

func TestGSOPassThroughFinalizesTheDeferredChecksum(t *testing.T) {
	dev, peer := gsoPair(t)

	pkt := tcp4(100)
	if _, err := peer.Write(vnetPacket(vnetNeedsCsum, gsoUFO, 1400, pkt)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := dev.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(pkt) {
		t.Fatalf("read %d bytes, want the whole %d-byte packet", n, len(pkt))
	}
	if got := l4csum(buf[:n]); got == 0xbeef {
		t.Fatalf("the packet went out with the kernel's DEFERRED checksum (0x%04x) still in the field — "+
			"the far end drops it and nothing is logged", got)
	}
	if dev.nUnsplit.Load() != 1 {
		t.Fatalf("unsplit super-packets counted %d, want 1", dev.nUnsplit.Load())
	}
	if dev.nSuper.Load() != 0 {
		t.Fatalf("a pass-through must not count as a split super-packet")
	}
}

func TestGSOLegacyUFOIsNeverSegmented(t *testing.T) {

	pkt := make([]byte, 20+8+3000)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 17
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+3000))

	if segs, split := splitGSO(pkt, 1000, gsoUFO); split || len(segs) != 1 {
		t.Fatalf("legacy UFO (gso_type 3) was segmented into %d pieces (split=%v) — its segments are IP "+
			"FRAGMENTS, not datagrams, so every piece would claim the whole payload's UDP header", len(segs), split)
	}
	segs, split := splitGSO(pkt, 1000, gsoUDPL4)
	if !split || len(segs) != 3 {
		t.Fatalf("USO (gso_type 5) produced %d segments (split=%v), want 3 — the real per-datagram type "+
			"had no case and fell through to an unchecked pass-through", len(segs), split)
	}
}

func TestGSOReadDropsRatherThanTruncates(t *testing.T) {
	dev, peer := gsoPair(t)

	big := tcp4(4000)
	small := tcp4(20)
	if _, err := peer.Write(vnetPacket(0, gsoUFO, 1400, big)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write(vnetPacket(0, gsoNone, 0, small)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500)
	n, err := dev.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(small) {
		t.Fatalf("Read returned %d bytes; want the next FITTING packet (%d). A packet that does not fit "+
			"must be dropped, never truncated into a corrupt one", n, len(small))
	}
	if dev.nOversize.Load() != 1 {
		t.Fatalf("oversize drops counted %d, want 1", dev.nOversize.Load())
	}
}

func TestGSOReportsAtRuntimeNotOnlyAtShutdown(t *testing.T) {
	dev, peer := gsoPair(t)

	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	if _, err := peer.Write(vnetPacket(0, gsoTCPv4, 1000, tcp4(2500))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	if _, err := dev.Read(buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "in 1 super-packets -> 3 segments") {
		t.Fatalf("nothing reported while running; log was %q — the knob is unverifiable until shutdown", out.String())
	}

	out.Reset()
	dev.q = nil
	if _, err := peer.Write(vnetPacket(0, gsoTCPv4, 1000, tcp4(2500))); err != nil {
		t.Fatal(err)
	}
	if _, err := dev.Read(buf); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("reported again inside the %v window: %q", gsoReportEvery, out.String())
	}
}

func TestGSOSplitPathStillWorks(t *testing.T) {
	dev, peer := gsoPair(t)

	if _, err := peer.Write(vnetPacket(vnetNeedsCsum, gsoTCPv4, 1000, tcp4(2500))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	got := 0
	for i := 0; i < 3; i++ {
		n, err := dev.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n > 20+20+1000 {
			t.Fatalf("segment %d is %d bytes, larger than one MSS worth of packet", i, n)
		}
		if l4csum(buf[:n]) == 0xbeef {
			t.Fatalf("segment %d carries the untouched checksum — segments must be rebuilt", i)
		}
		got += n - 40
	}
	if got != 2500 {
		t.Fatalf("segments carried %d payload bytes, want 2500", got)
	}
	if dev.nSuper.Load() != 1 || dev.nSeg.Load() != 3 {
		t.Fatalf("counters: %d super / %d segments, want 1 / 3", dev.nSuper.Load(), dev.nSeg.Load())
	}
	if dev.nUnsplit.Load() != 0 || dev.nOversize.Load() != 0 {
		t.Fatalf("a clean split must not count an unsplit or an oversize drop")
	}
}

func TestGSOFirstLineIsNotAllZeros(t *testing.T) {
	dev, peer := gsoPair(t)

	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	if _, err := peer.Write(vnetPacket(0, gsoNone, 0, tcp4(20))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	if _, err := dev.Read(buf); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("the first read reported before anything could have happened: %q", out.String())
	}

	if _, err := peer.Write(vnetPacket(0, gsoTCPv4, 1000, tcp4(2500))); err != nil {
		t.Fatal(err)
	}
	dev.q = nil
	if _, err := dev.Read(buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "in 1 super-packets -> 3 segments") {
		t.Fatalf("the first real coalescing was not reported at once; log was %q", out.String())
	}
}
