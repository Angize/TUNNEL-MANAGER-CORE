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

// gsoPair returns a Device with the virtio-net header path ENABLED over a socketpair, plus the peer fd
// standing in for the kernel side. This is the whole point of FromFileGSO: without it the GSO read path
// cannot be reached from a test at all — Open needs /dev/net/tun and a kernel with IFF_VNET_HDR, and
// FromFile hard-codes gso=false — so only the pure segment() helper was ever covered.
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

// vnetPacket frames one L3 packet the way the kernel does with IFF_VNET_HDR: a 10-byte
// virtio_net_hdr (flags, gso_type, hdr_len, gso_size, csum_start, csum_offset) then the packet.
func vnetPacket(flags, gsoType byte, gsoSize int, pkt []byte) []byte {
	out := make([]byte, vnetHdrLen+len(pkt))
	out[0] = flags
	out[1] = gsoType
	binary.LittleEndian.PutUint16(out[4:6], uint16(gsoSize))
	copy(out[vnetHdrLen:], pkt)
	return out
}

// tcp4 builds one IPv4/TCP packet with `payload` bytes of data and a DELIBERATELY wrong L4
// checksum, so a test can tell "the core recomputed it" from "the core shipped what it was given".
func tcp4(payload int) []byte {
	pkt := make([]byte, 20+20+payload)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:22], 1234) // sport
	binary.BigEndian.PutUint16(pkt[22:24], 443)  // dport
	pkt[32] = 5 << 4                             // data offset = 20 bytes
	pkt[33] = 0x18                               // PSH|ACK
	binary.BigEndian.PutUint16(pkt[36:38], 0xbeef)
	for i := 40; i < len(pkt); i++ {
		pkt[i] = byte(i)
	}
	return pkt
}

func l4csum(pkt []byte) uint16 { return binary.BigEndian.Uint16(pkt[36:38]) }

// TestGSOPassThroughFinalizesTheDeferredChecksum is the regression test for the GSO pass-through
// corruption: readGSO ran finalizeCsum only on the plain-packet branch, so every super-packet splitGSO
// handed back UNSEGMENTED went out still carrying the kernel's deferred virtio partial checksum — not
// dropped, not repaired, just rejected by the far end's stack, with nothing logged at either end.
func TestGSOPassThroughFinalizesTheDeferredChecksum(t *testing.T) {
	dev, peer := gsoPair(t)

	// gso_type 3 is LEGACY UFO, which we never ask for and must never segment: it comes back
	// unsplit. NEEDS_CSUM says the kernel deferred the L4 checksum to us.
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

// TestGSOLegacyUFOIsNeverSegmented pins the decode table itself. VIRTIO_NET_HDR_GSO_UDP (3) is legacy
// UFO — IP-fragmentation semantics — and was mapped to per-datagram UDP segmentation, while the type
// that really means that, USO (5), had no case at all. Nothing requests either today, so this is a
// dormant mine for whoever adds TUN_F_USO4/USO6 expecting UDP upload to accelerate.
func TestGSOLegacyUFOIsNeverSegmented(t *testing.T) {
	// A UDP super-packet big enough that a real segmentation would produce several pieces.
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

// TestGSOReadDropsRatherThanTruncates pins that Read never hands the carrier a shortened packet.
// copy() silently truncates, so an unsegmentable super-packet larger than the caller's buffer used
// to come back as a packet whose IP header claims a length its body no longer has — corruption the
// far end cannot even diagnose. Dropping it costs one packet and is counted.
func TestGSOReadDropsRatherThanTruncates(t *testing.T) {
	dev, peer := gsoPair(t)

	big := tcp4(4000) // unsplittable (gso_type 3) and far larger than the small buffer below
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

// TestGSOReportsAtRuntimeNotOnlyAtShutdown pins the observability half: the counters are logged WHILE
// the tunnel runs, so an operator who turned the knob on can tell "the kernel is coalescing" from "the
// knob is inert" without stopping the tunnel. The first read must report immediately, and a second read
// that changes nothing must NOT report again — an idle tunnel has to stay silent or the line is noise.
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
	if !strings.Contains(out.String(), "gso 1 super-packets -> 3 segments") {
		t.Fatalf("nothing reported while running; log was %q — the knob is unverifiable until shutdown", out.String())
	}

	// A second super-packet inside the reporting window must not produce a second line.
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

// TestGSOSplitPathStillWorks is the other half: a real TSO super-packet must still be segmented,
// counted, and served one packet per Read. Without it the two tests above could be satisfied by a
// device that simply never splits anything.
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

// TestGSOFirstLineIsNotAllZeros is the regression test for the reporting rule reading backwards.
// Reporting on the FIRST read, before the kernel could coalesce anything, makes the first line an
// operator ever sees "0 super-packets -> 0 segments" — exactly the reading that means the knob does
// nothing — and it stamps the window too, so a device that starts coalescing stays silent for ten minutes.
func TestGSOFirstLineIsNotAllZeros(t *testing.T) {
	dev, peer := gsoPair(t)

	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// A plain, non-coalesced packet: nothing to report.
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

	// The moment the kernel DOES coalesce, say so at once — not ten minutes later.
	if _, err := peer.Write(vnetPacket(0, gsoTCPv4, 1000, tcp4(2500))); err != nil {
		t.Fatal(err)
	}
	dev.q = nil
	if _, err := dev.Read(buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "gso 1 super-packets -> 3 segments") {
		t.Fatalf("the first real coalescing was not reported at once; log was %q", out.String())
	}
}
