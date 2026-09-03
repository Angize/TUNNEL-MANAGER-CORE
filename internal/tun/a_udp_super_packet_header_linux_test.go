//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"os"
	"syscall"
	"testing"
)

func usoDev(t *testing.T) (*Device, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	dev := &Device{f: os.NewFile(uintptr(fds[0]), "uso"), fd: fds[0], Name: "uso", gso: true, uso: true}
	peer := os.NewFile(uintptr(fds[1]), "uso-peer")
	t.Cleanup(func() { dev.Close(); peer.Close() })
	return dev, peer
}

func udp4(sport, dport uint16, payload int, fill byte) []byte {
	pkt := make([]byte, 20+udpHdrLen+payload)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1111)
	pkt[6] = 0x40
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpHdrLen+payload))
	for i := 28; i < len(pkt); i++ {
		pkt[i] = fill
	}
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	binary.BigEndian.PutUint16(pkt[26:28], l4Checksum(pkt, 20, false, 17))
	return pkt
}

func udp6(sport, dport uint16, payload int, fill byte) []byte {
	pkt := make([]byte, 40+udpHdrLen+payload)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpHdrLen+payload))
	pkt[6] = 17
	pkt[7] = 64
	pkt[8], pkt[24] = 0xfd, 0xfd
	pkt[23], pkt[39] = 1, 2
	binary.BigEndian.PutUint16(pkt[40:42], sport)
	binary.BigEndian.PutUint16(pkt[42:44], dport)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpHdrLen+payload))
	for i := 48; i < len(pkt); i++ {
		pkt[i] = fill
	}
	binary.BigEndian.PutUint16(pkt[46:48], l4Checksum(pkt, 40, true, 17))
	return pkt
}

// A super-packet the kernel merely accepts is not a super-packet it segments correctly, and a wrong
// field here is invisible: the write returns the full length either way. So every field the virtio
// header carries is read back off the wire and checked against what the datagrams say it should be,
// rather than against what this package believes it wrote.
func TestTheUDPSuperPacketHeaderSaysWhatTheDatagramsSay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mk      func(sport, dport uint16, payload int, fill byte) []byte
		ipHdr   int
		gsoType byte
	}{
		{"ipv4", udp4, 20, gsoUDPL4},
		{"ipv6", udp6, 40, gsoUDPL4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev, peer := usoDev(t)
			const seg, segs = 500, 4
			var pkts [][]byte
			for i := 0; i < segs; i++ {
				pkts = append(pkts, tc.mk(5000, 443, seg, byte('a'+i)))
			}
			if err := dev.WriteBatch(pkts); err != nil {
				t.Fatalf("WriteBatch: %v", err)
			}
			out := readOne(t, peer)
			vnet, body := out[:vnetHdrLen], out[vnetHdrLen:]

			if got := vnet[0]; got != vnetNeedsCsum {
				t.Fatalf("flags = %#x, want %#x: the kernel will not fill the udp checksum", got, vnetNeedsCsum)
			}
			if got := vnet[1]; got != tc.gsoType {
				t.Fatalf("gso_type = %d, want %d (UDP_L4)", got, tc.gsoType)
			}
			if got, want := int(binary.LittleEndian.Uint16(vnet[2:4])), tc.ipHdr+udpHdrLen; got != want {
				t.Fatalf("hdr_len = %d, want %d: the kernel copies this many bytes onto every segment", got, want)
			}
			if got := int(binary.LittleEndian.Uint16(vnet[4:6])); got != seg {
				t.Fatalf("gso_size = %d, want %d: the kernel cuts the payload at this stride", got, seg)
			}
			if got := int(binary.LittleEndian.Uint16(vnet[6:8])); got != tc.ipHdr {
				t.Fatalf("csum_start = %d, want %d", got, tc.ipHdr)
			}
			if got := int(binary.LittleEndian.Uint16(vnet[8:10])); got != 6 {
				t.Fatalf("csum_offset = %d, want 6: that is where a udp checksum lives", got)
			}

			wantBody := tc.ipHdr + udpHdrLen + seg*segs
			if len(body) != wantBody {
				t.Fatalf("super-packet is %d bytes, want %d", len(body), wantBody)
			}
			l4Len := udpHdrLen + seg*segs
			if got := int(binary.BigEndian.Uint16(body[tc.ipHdr+4 : tc.ipHdr+6])); got != l4Len {
				t.Fatalf("udp length field = %d, want %d", got, l4Len)
			}
			if tc.ipHdr == 20 {
				if got := int(binary.BigEndian.Uint16(body[2:4])); got != wantBody {
					t.Fatalf("ip total length = %d, want %d", got, wantBody)
				}
				if got := ipChecksum(body[:20]); got != 0xffff && binary.BigEndian.Uint16(body[10:12]) != ipChecksum(zeroCsum(body[:20])) {
					t.Fatalf("ip header checksum was not recomputed for the new total length (got %#x)", got)
				}
			} else {
				if got := int(binary.BigEndian.Uint16(body[4:6])); got != l4Len {
					t.Fatalf("ipv6 payload length = %d, want %d", got, l4Len)
				}
			}
			if got := binary.BigEndian.Uint16(body[tc.ipHdr+6 : tc.ipHdr+8]); got != pseudoSum(body, tc.ipHdr, tc.ipHdr == 40, 17, l4Len) {
				t.Fatalf("udp checksum field = %#x, want the pseudo-header sum the kernel finishes", got)
			}

			for i := 0; i < segs; i++ {
				off := tc.ipHdr + udpHdrLen + i*seg
				want := bytes.Repeat([]byte{byte('a' + i)}, seg)
				if !bytes.Equal(body[off:off+seg], want) {
					t.Fatalf("segment %d payload is not the %d-th datagram's: the run was assembled "+
						"in the wrong order or with the wrong stride", i, i)
				}
			}
		})
	}
}

func zeroCsum(hdr []byte) []byte {
	c := append([]byte(nil), hdr...)
	c[10], c[11] = 0, 0
	return c
}

// groMaxSegs is 64 and the kernel's own UDP_MAX_SEGMENTS is the same number. One off either way is a
// super-packet the kernel takes and silently drops, so the boundary is driven for real rather than
// reasoned about.
func TestAUDPRunStopsAtTheKernelsSegmentCeiling(t *testing.T) {
	dev, peer := usoDev(t)
	var pkts [][]byte
	for i := 0; i < groMaxSegs+10; i++ {
		pkts = append(pkts, udp4(5000, 443, 100, byte(i)))
	}
	if err := dev.WriteBatch(pkts); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	out := readOne(t, peer)
	body := out[vnetHdrLen:]
	segs := (len(body) - 20 - udpHdrLen) / 100
	if segs != groMaxSegs {
		t.Fatalf("the first super-packet carries %d segments, want exactly %d", segs, groMaxSegs)
	}
	if got := int(binary.LittleEndian.Uint16(out[4:6])); got != 100 {
		t.Fatalf("gso_size = %d, want 100", got)
	}
}

// The device only gets to build these when the kernel granted TUN_F_USO4/USO6. On a kernel that did
// not, a UDP_L4 super-packet is a write the kernel accepts and then drops -- every udp datagram in the
// tunnel would vanish. The flag is the whole gate, so it is checked here rather than trusted.
func TestWithoutTheKernelsBlessingUDPIsWrittenOnePacketAtATime(t *testing.T) {
	dev, peer := usoDev(t)
	dev.uso = false
	pkts := [][]byte{udp4(5000, 443, 300, 'a'), udp4(5000, 443, 300, 'b')}
	if err := dev.WriteBatch(pkts); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	for i := range pkts {
		out := readOne(t, peer)
		if got := out[1]; got != gsoNone {
			t.Fatalf("packet %d went out with gso_type %d: a super-packet was built without USO", i, got)
		}
		if len(out) != vnetHdrLen+len(pkts[i]) {
			t.Fatalf("packet %d is %d bytes, want a single %d-byte datagram", i, len(out), len(pkts[i]))
		}
	}
}

// Everything a run must refuse. Each of these, coalesced, is delivered to the wrong socket or with the
// wrong bytes, and none of them fails loudly.
func TestWhatAUDPRunRefusesToCoalesce(t *testing.T) {
	full := udp4(5000, 443, 400, 'a')
	for _, tc := range []struct {
		name string
		pkts [][]byte
	}{
		{"a different destination port", [][]byte{full, udp4(5000, 444, 400, 'b')}},
		{"a different source port", [][]byte{full, udp4(5001, 443, 400, 'b')}},
		{"a longer second segment", [][]byte{full, udp4(5000, 443, 401, 'b')}},
		{"a fragment", [][]byte{full, fragment(udp4(5000, 443, 400, 'b'))}},
		{"a tcp packet in the middle", [][]byte{full, seg(1, tcpACK, 400)}},
		{"a v6 datagram after a v4 one", [][]byte{full, udp6(5000, 443, 400, 'b')}},
		{"an empty datagram", [][]byte{udp4(5000, 443, 0, 'a'), full}},
		{"a single datagram on its own", [][]byte{full}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if n, _ := udpRun(tc.pkts); n >= 2 {
				t.Fatalf("udpRun coalesced %d of these into one super-packet", n)
			}
		})
	}
}

// A run of three where only the first two match must carry two, not three and not one.
func TestAUDPRunEndsWhereTheFlowChanges(t *testing.T) {
	pkts := [][]byte{
		udp4(5000, 443, 400, 'a'),
		udp4(5000, 443, 400, 'b'),
		udp4(5000, 9999, 400, 'c'),
	}
	n, segSize := udpRun(pkts)
	if n != 2 || segSize != 400 {
		t.Fatalf("udpRun = %d segments of %d, want 2 of 400", n, segSize)
	}
}
