package tun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"

	"golang.org/x/sys/unix"
)

// refSplitGSO and refSegment are the segmenter as it was before the cursor:
// every segment in its own fresh slice, handed out by a second copy. They are
// kept here, byte for byte, as the reference the cursor must reproduce.
func refSplitGSO(pkt []byte, gsoSize, gsoType int) (segs [][]byte, split bool) {
	switch gsoType &^ gsoECN {
	case gsoTCPv4, gsoTCPv6:
		return refSegment(pkt, gsoSize, true)
	case gsoUDPL4:
		return refSegment(pkt, gsoSize, false)
	default:
		return [][]byte{pkt}, false
	}
}

func refSegment(pkt []byte, gsoSize int, isTCP bool) (segs [][]byte, split bool) {
	v6 := pkt[0]>>4 == 6
	var ipHdrLen int
	if v6 {
		l4Off, proto, ok := ipv6L4Offset(pkt)
		if !ok || (isTCP && proto != 6) || (!isTCP && proto != 17) {
			return [][]byte{pkt}, false
		}
		ipHdrLen = l4Off
	} else {
		ipHdrLen = int(pkt[0]&0x0f) * 4
	}
	minL4 := 8
	if isTCP {
		minL4 = 20
	}
	if len(pkt) < ipHdrLen+minL4 {
		return [][]byte{pkt}, false
	}
	l4Hdr := 8
	if isTCP {
		l4Hdr = int(pkt[ipHdrLen+12]>>4) * 4
		if l4Hdr < 20 {
			return [][]byte{pkt}, false
		}
	}
	hdrLen := ipHdrLen + l4Hdr
	if len(pkt) <= hdrLen || gsoSize <= 0 {
		return [][]byte{pkt}, false
	}
	payload := pkt[hdrLen:]

	var baseSeq uint32
	var flags byte
	if isTCP {
		baseSeq = binary.BigEndian.Uint32(pkt[ipHdrLen+4 : ipHdrLen+8])
		flags = pkt[ipHdrLen+13]
	}
	var baseID uint16
	if !v6 {
		baseID = binary.BigEndian.Uint16(pkt[4:6])
	}

	var out [][]byte
	for off, i := 0, 0; off < len(payload); off, i = off+gsoSize, i+1 {
		end := off + gsoSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[off:end]
		last := end == len(payload)

		seg := make([]byte, hdrLen+len(chunk))
		copy(seg, pkt[:hdrLen])
		copy(seg[hdrLen:], chunk)

		if v6 {
			binary.BigEndian.PutUint16(seg[4:6], uint16((ipHdrLen-40)+l4Hdr+len(chunk)))
		} else {
			binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg)))
			binary.BigEndian.PutUint16(seg[4:6], baseID+uint16(i))
			seg[10], seg[11] = 0, 0
			binary.BigEndian.PutUint16(seg[10:12], ipChecksum(seg[:ipHdrLen]))
		}

		if isTCP {
			binary.BigEndian.PutUint32(seg[ipHdrLen+4:ipHdrLen+8], baseSeq+uint32(off))
			f := flags
			if !last {
				f &^= 0x09
			}
			seg[ipHdrLen+13] = f
			writeL4Csum(seg, ipHdrLen, v6, 6)
		} else {
			binary.BigEndian.PutUint16(seg[ipHdrLen+4:ipHdrLen+6], uint16(8+len(chunk)))
			writeL4Csum(seg, ipHdrLen, v6, 17)
		}
		out = append(out, seg)
	}
	return out, true
}

// refRead is what the old Device handed out for one message read from the
// tun: the segments (or the one whole packet), and the counter moves.
func refRead(msg []byte) (segs [][]byte, super, nseg, unsplit uint64) {
	if len(msg) <= vnetHdrLen {
		return nil, 0, 0, 0
	}
	m := append([]byte(nil), msg...)
	flags := m[0]
	gsoType := int(m[1])
	gsoSize := int(binary.LittleEndian.Uint16(m[4:6]))
	pkt := m[vnetHdrLen:]
	segs, split := [][]byte{pkt}, false
	if gsoType&^gsoECN != gsoNone {
		segs, split = refSplitGSO(pkt, gsoSize, gsoType)
	}
	if !split {
		if flags&vnetNeedsCsum != 0 {
			finalizeCsum(pkt)
		}
		if gsoType&^gsoECN != gsoNone {
			unsplit = 1
		}
		return segs, 0, 0, unsplit
	}
	return segs, 1, uint64(len(segs)), 0
}

func vnet(flags byte, gsoType, gsoSize int) []byte {
	h := make([]byte, vnetHdrLen)
	h[0] = flags
	h[1] = byte(gsoType)
	binary.LittleEndian.PutUint16(h[4:6], uint16(gsoSize))
	return h
}

func v4(proto byte, l4 []byte) []byte {
	p := make([]byte, 20+len(l4))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], 0xfff0)
	p[8] = 64
	p[9] = proto
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{10, 0, 0, 2})
	copy(p[20:], l4)
	return p
}

func v6(proto byte, ext bool, l4 []byte) []byte {
	extLen := 0
	if ext {
		extLen = 8
	}
	p := make([]byte, 40+extLen+len(l4))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], uint16(extLen+len(l4)))
	p[6] = proto
	p[7] = 64
	p[8], p[23] = 0xfd, 1
	p[24], p[39] = 0xfd, 2
	if ext {
		p[6] = 0
		p[40] = proto
	}
	copy(p[40+extLen:], l4)
	return p
}

func mkTCP(hdr int, flags byte, payload []byte) []byte {
	t := make([]byte, hdr+len(payload))
	binary.BigEndian.PutUint16(t[0:2], 40000)
	binary.BigEndian.PutUint16(t[2:4], 443)
	binary.BigEndian.PutUint32(t[4:8], 0xfffffe00)
	t[12] = byte(hdr/4) << 4
	t[13] = flags
	copy(t[hdr:], payload)
	return t
}

func mkUDP(payload []byte) []byte {
	u := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:2], 40000)
	binary.BigEndian.PutUint16(u[2:4], 443)
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	copy(u[8:], payload)
	return u
}

type segCase struct {
	name string
	msg  []byte
}

func segCases() []segCase {
	rng := rand.New(rand.NewSource(1381))
	pay := func(n int) []byte {
		b := make([]byte, n)
		rng.Read(b)
		return b
	}
	var cs []segCase
	add := func(name string, msg []byte) { cs = append(cs, segCase{name, msg}) }

	type fam struct {
		name  string
		v6    bool
		ext   bool
		ipHdr int
	}
	fams := []fam{{"v4", false, false, 20}, {"v6", true, false, 40}, {"v6ext", true, true, 48}}
	type l4k struct {
		name string
		tcp  bool
		hdr  int
	}
	l4s := []l4k{{"tcp20", true, 20}, {"tcp32", true, 32}, {"udp", false, 8}}
	for _, f := range fams {
		for _, k := range l4s {
			for _, g := range []int{7, 536, 1448} {
				maxPay := 65535 - f.ipHdr - k.hdr
				if g == 7 {
					maxPay = 2003
				}
				for _, n := range []int{1, g - 1, g, g + 1, 3*g + 7, maxPay} {
					if n < 1 || n > maxPay {
						continue
					}
					var l4 []byte
					var proto byte
					var gt int
					if k.tcp {
						l4, proto = mkTCP(k.hdr, 0x19, pay(n)), 6
						gt = gsoTCPv4
						if f.v6 {
							gt = gsoTCPv6
						}
					} else {
						l4, proto, gt = mkUDP(pay(n)), 17, gsoUDPL4
					}
					var pkt []byte
					if f.v6 {
						pkt = v6(proto, f.ext, l4)
					} else {
						pkt = v4(proto, l4)
					}
					base := fmt.Sprintf("%s/%s/gso%d/pay%d", f.name, k.name, g, n)
					add(base, append(vnet(vnetNeedsCsum, gt, g), pkt...))
					if k.tcp {
						add(base+"/ecn", append(vnet(vnetNeedsCsum, gt|gsoECN, g), pkt...))
					}
				}
			}
		}
	}

	plain := v4(6, mkTCP(20, 0x18, pay(900)))
	add("plain/needs-csum", append(vnet(vnetNeedsCsum, gsoNone, 0), plain...))
	add("plain/no-csum", append(vnet(0, gsoNone, 0), plain...))
	add("plain/udp6-needs-csum", append(vnet(vnetNeedsCsum, gsoNone, 0), v6(17, false, mkUDP(pay(333)))...))
	add("unsplit/tcp-gso-on-udp6", append(vnet(vnetNeedsCsum, gsoTCPv6, 500), v6(17, false, mkUDP(pay(3000)))...))
	add("unsplit/udp-gso-on-tcp6", append(vnet(vnetNeedsCsum, gsoUDPL4, 500), v6(6, false, mkTCP(20, 0x18, pay(3000)))...))
	add("unsplit/tcp-dataoff-too-small", append(vnet(vnetNeedsCsum, gsoTCPv4, 500), v4(6, mkTCP(16, 0x18, pay(3000)))...))
	add("unsplit/gso-size-zero", append(vnet(vnetNeedsCsum, gsoTCPv4, 0), v4(6, mkTCP(20, 0x18, pay(3000)))...))
	add("unsplit/header-only", append(vnet(vnetNeedsCsum, gsoTCPv4, 500), v4(6, mkTCP(20, 0x18, nil))...))
	add("unsplit/too-short-for-l4", append(vnet(0, gsoTCPv4, 500), v4(6, make([]byte, 12))...))
	add("unsplit/unknown-gso-type", append(vnet(0, 3, 500), v4(6, mkTCP(20, 0x18, pay(3000)))...))
	add("vnet-only", vnet(0, gsoNone, 0))
	return cs
}

type counts struct{ super, seg, unsplit, oversize uint64 }

func (d *Device) counts() counts {
	return counts{d.nSuper.Load(), d.nSeg.Load(), d.nUnsplit.Load(), d.nOversize.Load()}
}

func seqpacketDevice(t *testing.T) (*Device, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	t.Cleanup(func() { unix.Close(fds[0]); unix.Close(fds[1]) })
	if err := unix.SetNonblock(fds[0], true); err != nil {
		t.Fatalf("nonblock: %v", err)
	}
	unix.SetsockoptInt(fds[1], unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
	unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	return &Device{fd: fds[0], Name: "segtest", gso: true, rbuf: make([]byte, vnetHdrLen+65535)}, fds[1]
}

// TestReadHandsOutWhatTheOldSegmenterDid drives the real Device.Read and
// Device.TryRead, fed through a SOCK_SEQPACKET pair so that one write is one
// tun read, exactly like /dev/net/tun. For every shape in segCases (v4, v6
// and v6 with an extension header; TCP with and without options, UDP; three
// segment sizes; payloads on and around the segment boundary and at the 64 KiB
// limit; ECN; plain packets with and without NEEDS_CSUM; every unsplittable
// shape) and for two caller buffer sizes (one so small that some segments are
// dropped as oversize in the middle of a super-packet), the packets handed
// out must be byte-identical, in the same order, to what the old segmenter
// produced, and the four gso counters must move by the same amounts.
//
// It proves the cursor changes no byte on the wire of any carrier, since every
// carrier reads the tun only through Read/TryRead. It does not prove anything
// about speed; BenchmarkSegment does that.
func TestReadHandsOutWhatTheOldSegmenterDid(t *testing.T) {
	for _, bufSize := range []int{65535, 700} {
		for _, viaRead := range []bool{true, false} {
			d, w := seqpacketDevice(t)
			buf := make([]byte, bufSize)
			for _, c := range segCases() {
				name := fmt.Sprintf("buf%d/read=%v/%s", bufSize, viaRead, c.name)
				want, super, nseg, unsplit := refRead(c.msg)
				var keep [][]byte
				var dropped uint64
				for _, s := range want {
					if len(s) > bufSize {
						dropped++
						continue
					}
					keep = append(keep, s)
				}
				before := d.counts()
				if _, err := unix.Write(w, c.msg); err != nil {
					t.Fatalf("%s: write: %v", name, err)
				}
				for i, exp := range keep {
					var n int
					if viaRead && i == 0 {
						var err error
						if n, err = d.Read(buf); err != nil {
							t.Fatalf("%s: Read: %v", name, err)
						}
					} else {
						var ok bool
						var err error
						if n, ok, err = d.TryRead(buf); err != nil || !ok {
							t.Fatalf("%s: TryRead #%d: ok=%v err=%v, want packet %d of %d", name, i, ok, err, i+1, len(keep))
						}
					}
					if !bytes.Equal(buf[:n], exp) {
						t.Fatalf("%s: packet %d of %d differs from the old segmenter (len %d vs %d)", name, i+1, len(keep), n, len(exp))
					}
				}
				if n, ok, err := d.TryRead(buf); err != nil || ok {
					t.Fatalf("%s: extra packet after the expected %d: n=%d ok=%v err=%v", name, len(keep), n, ok, err)
				}
				after := d.counts()
				got := counts{after.super - before.super, after.seg - before.seg, after.unsplit - before.unsplit, after.oversize - before.oversize}
				if exp := (counts{super, nseg, unsplit, dropped}); got != exp {
					t.Fatalf("%s: counters moved %+v, the old path would have moved %+v", name, got, exp)
				}
			}
		}
	}
}

func benchSuper() []byte {
	payload := make([]byte, 65535-20-32)
	rand.New(rand.NewSource(7)).Read(payload)
	return v4(6, mkTCP(32, 0x18, payload))
}

// BenchmarkSegment splits one 64 KiB TCP super-packet into 1448-byte segments
// and hands each one to a caller buffer: "old" is the slice-per-segment path
// plus the copy in serve, "cursor" builds each segment straight into the
// caller's buffer. Same work otherwise, including both checksums.
func BenchmarkSegment(b *testing.B) {
	pkt := benchSuper()
	buf := make([]byte, 65535)
	b.Run("old", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(pkt)))
		for i := 0; i < b.N; i++ {
			segs, _ := refSegment(pkt, 1448, true)
			for _, s := range segs {
				copy(buf, s)
			}
		}
	})
	b.Run("cursor", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(pkt)))
		var c segCursor
		for i := 0; i < b.N; i++ {
			c.load(pkt, 1448, gsoTCPv4)
			for !c.empty() {
				c.next(buf)
			}
		}
	})
}
