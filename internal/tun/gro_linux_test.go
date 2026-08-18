//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"os"
	"syscall"
	"testing"
)

func seg(seq uint32, flags byte, payload int) []byte {
	pkt := make([]byte, 20+20+payload)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1111)
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:22], 1234)
	binary.BigEndian.PutUint16(pkt[22:24], 443)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	binary.BigEndian.PutUint32(pkt[28:32], 0x5555)
	pkt[32] = 5 << 4
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 0x2000)
	for i := 40; i < len(pkt); i++ {
		pkt[i] = byte(seq) ^ byte(i)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	binary.BigEndian.PutUint16(pkt[36:38], l4Checksum(pkt, 20, false, 6))
	return pkt
}

func seg6(seq uint32, flags byte, payload int) []byte {
	pkt := make([]byte, 40+20+payload)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(20+payload))
	pkt[6] = 6
	pkt[7] = 64
	pkt[8], pkt[24] = 0xfd, 0xfd
	pkt[23], pkt[39] = 1, 2
	binary.BigEndian.PutUint16(pkt[40:42], 1234)
	binary.BigEndian.PutUint16(pkt[42:44], 443)
	binary.BigEndian.PutUint32(pkt[44:48], seq)
	binary.BigEndian.PutUint32(pkt[48:52], 0x5555)
	pkt[52] = 5 << 4
	pkt[53] = flags
	binary.BigEndian.PutUint16(pkt[54:56], 0x2000)
	for i := 60; i < len(pkt); i++ {
		pkt[i] = byte(seq) ^ byte(i)
	}
	binary.BigEndian.PutUint16(pkt[56:58], l4Checksum(pkt, 40, true, 6))
	return pkt
}

func notTCP(proto byte, payload int) []byte {
	pkt := seg(1, tcpACK, payload)
	pkt[9] = proto
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	return pkt
}

func fragment(pkt []byte) []byte {
	pkt[6] |= 0x20
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	return pkt
}

func groDev(t *testing.T) (*Device, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	dev := &Device{f: os.NewFile(uintptr(fds[0]), "gro"), fd: fds[0], Name: "gro", gso: true}
	peer := os.NewFile(uintptr(fds[1]), "gro-peer")
	t.Cleanup(func() { dev.Close(); peer.Close() })
	return dev, peer
}

func readOne(t *testing.T, peer *os.File) []byte {
	t.Helper()
	buf := make([]byte, 70000)
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if n < vnetHdrLen {
		t.Fatalf("read %d bytes, shorter than a virtio header", n)
	}
	return buf[:n]
}

func writes(t *testing.T, dev *Device, peer *os.File, pkts [][]byte) [][]byte {
	t.Helper()
	if err := dev.WriteBatch(pkts); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	sentinel := seg(0xdead0000, tcpACK|tcpFIN, 8)
	if _, err := dev.Write(sentinel); err != nil {
		t.Fatalf("sentinel write: %v", err)
	}
	var got [][]byte
	for {
		d := readOne(t, peer)
		if bytes.Equal(d[vnetHdrLen:], sentinel) {
			return got
		}
		got = append(got, d)
		if len(got) > len(pkts)+2 {
			t.Fatal("the sentinel never arrived")
		}
	}
}

func TestGROJoinsARunAndSplittingItGivesTheRunBack(t *testing.T) {
	dev, peer := groDev(t)
	in := [][]byte{seg(1000, tcpACK, 100), seg(1100, tcpACK, 100), seg(1200, tcpACK|tcpPSH, 60)}
	want := [][]byte{seg(1000, tcpACK, 100), seg(1100, tcpACK, 100), seg(1200, tcpACK|tcpPSH, 60)}

	got := writes(t, dev, peer, in)
	if len(got) != 1 {
		t.Fatalf("%d writes, want 1 — the run was not joined", len(got))
	}
	hdr, super := got[0][:vnetHdrLen], got[0][vnetHdrLen:]
	if hdr[0] != vnetNeedsCsum || hdr[1] != gsoTCPv4 {
		t.Fatalf("virtio flags/type = %d/%d, want %d/%d", hdr[0], hdr[1], vnetNeedsCsum, gsoTCPv4)
	}
	if hl := binary.LittleEndian.Uint16(hdr[2:4]); hl != 40 {
		t.Fatalf("hdr_len = %d, want 40", hl)
	}
	if gs := binary.LittleEndian.Uint16(hdr[4:6]); gs != 100 {
		t.Fatalf("gso_size = %d, want 100 (the leader's payload)", gs)
	}
	if cs, co := binary.LittleEndian.Uint16(hdr[6:8]), binary.LittleEndian.Uint16(hdr[8:10]); cs != 20 || co != 16 {
		t.Fatalf("csum_start/offset = %d/%d, want 20/16", cs, co)
	}
	if total := int(binary.BigEndian.Uint16(super[2:4])); total != len(super) {
		t.Fatalf("ip total length = %d, want %d", total, len(super))
	}
	if super[33]&tcpPSH == 0 {
		t.Fatal("the push of the last segment did not reach the super-packet's header")
	}

	segs, split := splitGSO(super, 100, gsoTCPv4)
	if !split || len(segs) != len(want) {
		t.Fatalf("splitting gave %d segments (split=%v), want %d", len(segs), split, len(want))
	}
	for i := range want {

		if !bytes.Equal(segs[i][40:], want[i][40:]) {
			t.Fatalf("segment %d carries different payload than the packet that went in", i)
		}
		if s := binary.BigEndian.Uint32(segs[i][24:28]); s != binary.BigEndian.Uint32(want[i][24:28]) {
			t.Fatalf("segment %d sequence = %d, want %d", i, s, binary.BigEndian.Uint32(want[i][24:28]))
		}
		if got, exp := segs[i][33], want[i][33]; got != exp {
			t.Fatalf("segment %d flags = %#x, want %#x", i, got, exp)
		}
	}
}

func TestGROLeavesAPartialTheKernelCanComplete(t *testing.T) {
	dev, peer := groDev(t)
	got := writes(t, dev, peer, [][]byte{seg(1, tcpACK, 200), seg(201, tcpACK, 200)})
	if len(got) != 1 {
		t.Fatalf("%d writes, want 1", len(got))
	}
	super := got[0][vnetHdrLen:]

	completed := ^fold(sumBytes(super[20:], 0))

	zeroed := append([]byte(nil), super...)
	zeroed[36], zeroed[37] = 0, 0
	if want := l4Checksum(zeroed, 20, false, 6); completed != want {
		t.Fatalf("completing the partial gives %#04x, but the packet's checksum is %#04x", completed, want)
	}
}

func TestGRORefusesToJoinWhatItMustNot(t *testing.T) {
	bump := func(f func([]byte)) [][]byte {
		a, b := seg(1, tcpACK, 100), seg(101, tcpACK, 100)
		f(b)
		binary.BigEndian.PutUint16(b[10:12], 0)
		binary.BigEndian.PutUint16(b[10:12], ipChecksum(b[:20]))
		return [][]byte{a, b}
	}
	cases := map[string][][]byte{
		"a hole in the sequence":  {seg(1, tcpACK, 100), seg(102, tcpACK, 100)},
		"a different connection":  bump(func(p []byte) { binary.BigEndian.PutUint16(p[22:24], 444) }),
		"a newer acknowledgement": bump(func(p []byte) { binary.BigEndian.PutUint32(p[28:32], 0x6666) }),
		"a different window":      bump(func(p []byte) { binary.BigEndian.PutUint16(p[34:36], 0x3000) }),
		"a different ttl":         bump(func(p []byte) { p[8] = 32 }),
		"a fin":                   {seg(1, tcpACK, 100), seg(101, tcpACK|tcpFIN, 100)},
		"a reset":                 {seg(1, tcpACK, 100), seg(101, tcpACK|0x04, 100)},
		"a syn":                   {seg(1, tcpACK, 100), seg(101, tcpACK|0x02, 100)},
		"an urgent pointer":       {seg(1, tcpACK, 100), seg(101, tcpACK|0x20, 100)},
		"a push on the leader":    {seg(1, tcpACK|tcpPSH, 100), seg(101, tcpACK, 100)},
		"a longer follower":       {seg(1, tcpACK, 100), seg(101, tcpACK, 140)},
		"a pure acknowledgement":  {seg(1, tcpACK, 100), seg(101, tcpACK, 0)},
		"udp, not tcp":            {notTCP(17, 100), notTCP(17, 100)},
		"icmp, not tcp":           {notTCP(1, 100), notTCP(1, 100)},
		"a fragment":              {fragment(seg(1, tcpACK, 100)), fragment(seg(101, tcpACK, 100))},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			dev, peer := groDev(t)
			got := writes(t, dev, peer, in)
			if len(got) != 2 {
				t.Fatalf("%d writes, want 2 — %s was joined and must not be", len(got), name)
			}
			for i := range in {
				if !bytes.Equal(got[i][vnetHdrLen:], in[i]) {
					t.Fatalf("packet %d was altered on its way out", i)
				}
			}
		})
	}
}

func TestGROEndsTheRunAtAShortSegment(t *testing.T) {
	dev, peer := groDev(t)
	got := writes(t, dev, peer, [][]byte{
		seg(1, tcpACK, 100), seg(101, tcpACK, 60), seg(161, tcpACK, 100), seg(261, tcpACK, 100),
	})
	if len(got) != 2 {
		t.Fatalf("%d writes, want 2 (the run ends at the short segment, then a new one starts)", len(got))
	}
	if gs := binary.LittleEndian.Uint16(got[0][4:6]); gs != 100 {
		t.Fatalf("first gso_size = %d, want 100", gs)
	}
	if n := len(got[1][vnetHdrLen:]) - 40; n != 200 {
		t.Fatalf("second write carries %d payload bytes, want 200", n)
	}
}

func TestGROJoinsIPv6TheSameWay(t *testing.T) {
	dev, peer := groDev(t)
	got := writes(t, dev, peer, [][]byte{seg6(1, tcpACK, 100), seg6(101, tcpACK, 100)})
	if len(got) != 1 {
		t.Fatalf("%d writes, want 1", len(got))
	}
	hdr, super := got[0][:vnetHdrLen], got[0][vnetHdrLen:]
	if hdr[1] != gsoTCPv6 {
		t.Fatalf("gso_type = %d, want %d", hdr[1], gsoTCPv6)
	}
	if pl := int(binary.BigEndian.Uint16(super[4:6])); pl != len(super)-40 {
		t.Fatalf("ipv6 payload length = %d, want %d", pl, len(super)-40)
	}
	segs, split := splitGSO(super, 100, gsoTCPv6)
	if !split || len(segs) != 2 {
		t.Fatalf("splitting gave %d segments (split=%v), want 2", len(segs), split)
	}
}

func TestGROSplitsARunTooBigForOneWrite(t *testing.T) {
	dev, peer := groDev(t)
	var in [][]byte
	seq := uint32(1)
	for i := 0; i < 80; i++ {
		in = append(in, seg(seq, tcpACK, 1000))
		seq += 1000
	}
	got := writes(t, dev, peer, in)
	if len(got) < 2 {
		t.Fatalf("%d writes, want more than one — the bound did not hold", len(got))
	}
	total := 0
	for _, w := range got {
		if n := len(w) - vnetHdrLen; n > groMaxBytes {
			t.Fatalf("a write carried %d bytes, past the %d bound", n, groMaxBytes)
		}
		total += len(w) - vnetHdrLen - 40
	}
	if want := 80 * 1000; total != want {
		t.Fatalf("%d payload bytes came out, %d went in — a bound dropped data", total, want)
	}
}

func TestGROIsInertWithoutTheVirtioHeader(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	dev := &Device{f: os.NewFile(uintptr(fds[0]), "plain"), fd: fds[0], Name: "plain"}
	peer := os.NewFile(uintptr(fds[1]), "plain-peer")
	t.Cleanup(func() { dev.Close(); peer.Close() })

	in := [][]byte{seg(1, tcpACK, 100), seg(101, tcpACK, 100)}
	if err := dev.WriteBatch(in); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	buf := make([]byte, 4096)
	for i := range in {
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatalf("peer read: %v", err)
		}
		if !bytes.Equal(buf[:n], in[i]) {
			t.Fatalf("packet %d came out changed on a device with no virtio header", i)
		}
	}
}

func TestGROJoinsWithoutARawFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	dev := FromFileGSO(w, "nofd")

	in := [][]byte{seg(1, tcpACK, 100), seg(101, tcpACK, 100)}
	want := vnetHdrLen + 40 + 200
	if err := dev.WriteBatch(in); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != want {
		t.Fatalf("the joined write is %d bytes, want %d (header + one set of headers + both payloads)",
			n, want)
	}
	if buf[0] != vnetNeedsCsum || binary.LittleEndian.Uint16(buf[4:6]) != 100 {
		t.Fatalf("the virtio header did not survive the join: flags=%d gso_size=%d",
			buf[0], binary.LittleEndian.Uint16(buf[4:6]))
	}
	if !bytes.Equal(buf[vnetHdrLen+40:n], append(append([]byte(nil), in[0][40:]...), in[1][40:]...)) {
		t.Fatal("the payloads did not come out in order")
	}
}

func TestTheWriteCountersDescribeEverythingThatLeft(t *testing.T) {
	dev, peer := groDev(t)
	go func() {
		buf := make([]byte, 70000)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()

	if err := dev.WriteBatch([][]byte{seg(1, tcpACK, 100), seg(101, tcpACK, 100)}); err != nil {
		t.Fatal(err)
	}
	if err := dev.WriteBatch([][]byte{notTCP(17, 60), notTCP(1, 60), seg(9, tcpACK|tcpFIN, 20)}); err != nil {
		t.Fatal(err)
	}
	if got, want := dev.nOut.Load(), uint64(5); got != want {
		t.Fatalf("%d packets counted out, want %d — the single-packet writes are missing", got, want)
	}
	if got, want := dev.nWrites.Load(), uint64(4); got != want {
		t.Fatalf("%d writes counted, want %d (one joined + three alone)", got, want)
	}
}

func TestGROJoinsWithoutAllocating(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("open %s: %v", os.DevNull, err)
	}
	defer f.Close()
	dev := &Device{f: f, fd: int(f.Fd()), Name: "null", gso: true}
	in := [][]byte{seg(1, tcpACK, 1000), seg(1001, tcpACK, 1000), seg(2001, tcpACK, 1000)}

	if n := testing.AllocsPerRun(200, func() {

		binary.BigEndian.PutUint16(in[0][2:4], uint16(len(in[0])))
		if err := dev.WriteBatch(in); err != nil {
			t.Fatalf("WriteBatch: %v", err)
		}
	}); n != 0 {
		t.Fatalf("WriteBatch allocates %.1f times per run, want 0", n)
	}
}
