package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func prependIP4(src, dst net.IP, proto int, l4 []byte) []byte {
	h := make([]byte, 20+len(l4))
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(len(h)))
	h[8] = 64
	h[9] = byte(proto)
	copy(h[12:16], src.To4())
	copy(h[16:20], dst.To4())
	copy(h[20:], l4)
	return h
}

var (
	testSrc = net.IPv4(10, 20, 0, 1)
	testDst = net.IPv4(10, 20, 0, 2)
)

func TestRawProfileRoundTrip(t *testing.T) {

	payloads := [][]byte{
		[]byte("the-sealed-aead-frame-goes-here-0123456789"),
		{0x45, 0x00, 0x11, 0x22, 0x33},
		bytes.Repeat([]byte{0xAA}, 1),
	}
	for name := range rawProfiles {
		proto, _ := rawEffProto(name, 0)
		for i, pl := range payloads {
			for _, client := range []bool{true, false} {
				l4 := rawEncap(name, pl, testSrc, testDst, client, 0x1234, 0, 0, uint32(i+1), 0, 0x10203040, 0, 0, tcpPshAck)

				withIP := prependIP4(testSrc, testDst, proto, l4)
				for _, variant := range []struct {
					name string
					pkt  []byte
				}{{"with-ip", withIP}, {"no-ip", l4}} {
					got, _, _, ok := rawDecap(name, proto, variant.pkt)
					if !ok {
						t.Fatalf("profile %s payload#%d client=%v %s: decap failed", name, i, client, variant.name)
					}
					if !bytes.Equal(got, pl) {
						t.Fatalf("profile %s payload#%d client=%v %s: got %x want %x", name, i, client, variant.name, got, pl)
					}
				}
			}
		}
	}
}

func TestRawProtoNumbers(t *testing.T) {
	want := map[string]int{"bare": 253, "ipip": 4, "gre": 47, "icmp": 1, "udp": 17, "tcp": 6, "esp": 50}
	for name, n := range want {
		got, ok := rawEffProto(name, 0)
		if !ok || got != n {
			t.Errorf("proto(%s) = %d,%v want %d", name, got, ok, n)
		}
	}
	if _, ok := rawEffProto("nope", 0); ok {
		t.Error("rawEffProto accepted an unknown profile")
	}
}

func TestRawEffProto(t *testing.T) {

	cases := []struct {
		profile  string
		override int
		want     int
		wantOK   bool
	}{
		{"bare", 0, 253, true},
		{"bare", 58, 58, true},
		{"bare", 255, 255, true},
		{"bare", 300, 253, true},
		{"bare", -1, 253, true},
		{"gre", 58, 47, true},
		{"udp", 99, 17, true},
		{"nope", 58, 0, false},
	}
	for _, c := range cases {
		got, ok := rawEffProto(c.profile, c.override)
		if got != c.want || ok != c.wantOK {
			t.Errorf("rawEffProto(%q,%d) = %d,%v want %d,%v", c.profile, c.override, got, ok, c.want, c.wantOK)
		}
	}
}

func TestRawBareCustomProtoRoundTrip(t *testing.T) {

	pl := []byte("the-sealed-aead-frame")
	const custom = 58
	l4 := rawEncap("bare", pl, testSrc, testDst, true, 0, 0, 0, 0, 0, 0, 0, 0, tcpPshAck)
	if !bytes.Equal(l4, pl) {
		t.Fatalf("bare added a header: %x", l4)
	}
	for _, variant := range []struct {
		name string
		pkt  []byte
	}{
		{"with-ip", prependIP4(testSrc, testDst, custom, l4)},
		{"no-ip", l4},
	} {
		got, _, _, ok := rawDecap("bare", custom, variant.pkt)
		if !ok {
			t.Fatalf("%s: bare/proto-%d decap failed", variant.name, custom)
		}
		if !bytes.Equal(got, pl) {
			t.Fatalf("%s: got %x want %x", variant.name, got, pl)
		}
	}
}

func TestRawBipIpipHaveNoL4Header(t *testing.T) {
	pl := []byte("payload")
	for _, name := range []string{"bare", "ipip"} {
		l4 := rawEncap(name, pl, testSrc, testDst, true, 0, 0, 0, 0, 0, 0, 0, 0, tcpPshAck)
		if !bytes.Equal(l4, pl) {
			t.Errorf("profile %s added a header: %x", name, l4)
		}
	}
}

func TestRawChecksumsValid(t *testing.T) {
	pl := bytes.Repeat([]byte{0x5A}, 41)

	icmp := rawEncap("icmp", pl, testSrc, testDst, true, 0xABCD, 0, 0, 7, 0, 0, 0, 0, tcpPshAck)
	if s := onesComplementSum(icmp); s != 0 {
		t.Errorf("icmp checksum invalid: fold = %#x", s)
	}

	tcp := rawEncap("tcp", pl, testSrc, testDst, true, 0, 0, 0, 99, 0, 0, 0, 0, tcpPshAck)
	if s := l4Checksum(testSrc, testDst, protoTCP, tcp); s != 0 {
		t.Errorf("tcp checksum invalid: fold = %#x", s)
	}

	udp := rawEncap("udp", pl, testSrc, testDst, true, 0, 0, 0, 99, 0, 0, 0, 0, tcpPshAck)
	if s := l4Checksum(testSrc, testDst, protoUDP, udp); s != 0 && s != 0xffff {
		t.Errorf("udp checksum invalid: fold = %#x", s)
	}
}

func TestRawICMPDirection(t *testing.T) {
	req := rawEncap("icmp", []byte("x"), testSrc, testDst, true, 1, 0, 0, 1, 0, 0, 0, 0, tcpPshAck)
	if req[0] != 8 {
		t.Errorf("client ICMP type = %d, want 8 (echo request)", req[0])
	}
	rep := rawEncap("icmp", []byte("x"), testSrc, testDst, false, 1, 0, 0, 1, 0, 0, 0, 0, tcpPshAck)
	if rep[0] != 0 {
		t.Errorf("server ICMP type = %d, want 0 (echo reply)", rep[0])
	}
}

func TestRawTCPLiveFlowFields(t *testing.T) {

	tcp := rawEncap("tcp", []byte("data"), testSrc, testDst, true, 0, 0, 0, 0x11223344, 0x55667788, 0, 0, 0, tcpPshAck)
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != 0x11223344 {
		t.Errorf("tcp seq = %#x, want %#x", got, 0x11223344)
	}
	if got := binary.BigEndian.Uint32(tcp[8:12]); got != 0x55667788 {
		t.Errorf("tcp ack = %#x, want the passed non-zero ack (ack=0 with the ACK flag is a forged-segment tell)", got)
	}
	if got := binary.BigEndian.Uint16(tcp[14:16]); got != rawTCPWindow {
		t.Errorf("tcp window = %#x, want realistic %#x", got, rawTCPWindow)
	}
	if tcp[13] != 0x18 {
		t.Errorf("tcp flags = %#x, want PSH|ACK (0x18)", tcp[13])
	}
}

func TestRawESPHeader(t *testing.T) {

	pl := []byte("the-sealed-aead-frame")
	const spi, seq = 0x0A1B2C3D, 0x00000007
	esp := rawEncap("esp", pl, testSrc, testDst, true, 0, 0, 0, seq, 0, spi, 0, 0, tcpPshAck)
	if len(esp) != 8+len(pl) {
		t.Fatalf("esp header length = %d, want %d", len(esp)-len(pl), 8)
	}
	if got := binary.BigEndian.Uint32(esp[0:4]); got != spi {
		t.Errorf("esp SPI = %#x, want the per-session %#x", got, spi)
	}
	if got := binary.BigEndian.Uint32(esp[4:8]); got != seq {
		t.Errorf("esp seq = %#x, want the incrementing %#x", got, seq)
	}
	for _, variant := range []struct {
		name string
		pkt  []byte
	}{
		{"with-ip", prependIP4(testSrc, testDst, protoESP, esp)},
		{"no-ip", esp},
	} {
		got, _, _, ok := rawDecap("esp", protoESP, variant.pkt)
		if !ok {
			t.Fatalf("%s: esp decap failed", variant.name)
		}
		if !bytes.Equal(got, pl) {
			t.Fatalf("%s: got %x want %x", variant.name, got, pl)
		}
	}
}

func TestRawDecapRejectsShortCarrier(t *testing.T) {

	if _, _, _, ok := rawDecap("gre", protoGRE, []byte{0x00, 0x00}); ok {
		t.Error("gre decap accepted fewer than 4 header bytes")
	}
	if _, _, _, ok := rawDecap("icmp", protoICMP, []byte{0x08, 0x00}); ok {
		t.Error("icmp decap accepted fewer than 8 header bytes")
	}
	if _, _, _, ok := rawDecap("tcp", protoTCP, bytes.Repeat([]byte{0x00}, 10)); ok {
		t.Error("tcp decap accepted fewer than 20 header bytes")
	}
	if _, _, _, ok := rawDecap("esp", protoESP, []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00}); ok {
		t.Error("esp decap accepted fewer than 8 header bytes")
	}

	if _, _, _, ok := rawDecap("bare", protoBare, []byte{0x01, 0x02}); !ok {
		t.Error("bare decap should accept any bytes as the frame")
	}

	if _, _, _, ok := rawDecap("gre", protoGRE, prependIP4(testSrc, testDst, protoGRE, []byte{0x00})); ok {
		t.Error("gre decap accepted an IPv4 packet too short for its GRE header")
	}
}

func TestL4ChecksumSplitMatchesReference(t *testing.T) {
	ref := func(src, dst net.IP, proto int, l4 []byte) uint16 {
		s, d := src.To4(), dst.To4()
		pseudo := make([]byte, 12+len(l4))
		copy(pseudo[0:4], s)
		copy(pseudo[4:8], d)
		pseudo[9] = byte(proto)
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(l4)))
		copy(pseudo[12:], l4)
		return onesComplementSum(pseudo)
	}
	for i := 0; i < 2000; i++ {
		l4 := make([]byte, i%73)
		for j := range l4 {
			l4[j] = byte(i*31 + j*17)
		}
		src := net.IPv4(byte(i), byte(i>>8), 1, 2)
		dst := net.IPv4(3, 4, byte(i>>4), byte(i))
		for _, proto := range []int{protoTCP, protoUDP} {
			if got, want := l4Checksum(src, dst, proto, l4), ref(src, dst, proto, l4); got != want {
				t.Fatalf("len=%d proto=%d got=%04x want=%04x", len(l4), proto, got, want)
			}
		}
	}
}

func TestEveryProfileHasAHeaderLen(t *testing.T) {
	for name := range rawProfiles {
		if _, ok := rawHeaderLens[name]; !ok {
			t.Errorf("raw/%s is a registered profile with no entry in rawHeaderLens — it would encapsulate "+
				"with no header while the docs and the node's MTU say otherwise", name)
		}
	}
	for name := range rawHeaderLens {
		if _, ok := rawProfiles[name]; !ok {
			t.Errorf("rawHeaderLens carries %q, which is no longer a registered profile", name)
		}
	}

	for name := range rawProfiles {
		pl := []byte("0123456789")
		got := len(rawEncap(name, pl, testSrc, testDst, true, 1, 0, 0, 2, 3, 4, 0, 0, tcpPshAck)) - len(pl)
		if want := rawHeaderLens[name]; got != want {
			t.Errorf("raw/%s: rawEncap added %d header bytes, rawHeaderLens says %d", name, got, want)
		}
	}
}
