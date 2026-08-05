// Raw-IP encapsulation profiles for the "raw" transport. Each profile wraps a sealed core frame in a
// different IP-layer carrier so the tunnel mimics ordinary IPIP / GRE / ICMP / TCP / UDP traffic — or
// "bip", our native minimal framing. Only the carrier header, and so the IP protocol number on the wire,
// changes between them; the sealed frame is the innermost payload either way:
//
//	bip   proto 253  no L4 header            [IPv4][sealed]
//	ipip  proto 4    no L4 header            [IPv4][sealed]
//	gre   proto 47   4-byte GRE header       [IPv4][GRE][sealed]
//	icmp  proto 1    8-byte ICMP echo        [IPv4][ICMP][sealed]  (req 8 / reply 0)
//	udp   proto 17   8-byte UDP header        [IPv4][UDP][sealed]
//	tcp   proto 6    20-byte TCP header       [IPv4][TCP][sealed]  (PSH|ACK, live-flow seq/ack/window)
//	esp   proto 50    8-byte ESP header       [IPv4][ESP][sealed]  (IPsec ESP: per-session SPI + seq)
//
// The receiver ignores the carrier header's contents — the inner AEAD tag is the real integrity check —
// so it only has to be well formed enough to look like the protocol it imitates and to be skipped.
package packet

import (
	"encoding/binary"
	"net"
	"sort"
)

// IP protocol numbers, one per profile.
const (
	protoICMP = 1
	protoIPIP = 4
	protoTCP  = 6
	protoUDP  = 17
	protoGRE  = 47
	protoESP  = 50
	protoBIP  = 253 // private/experimental range: our native no-L4-header profile
)

// rawProfiles maps a profile name to its IP protocol number. It is also the
// authoritative set of valid profile names.
var rawProfiles = map[string]int{
	"bip":  protoBIP,
	"ipip": protoIPIP,
	"gre":  protoGRE,
	"icmp": protoICMP,
	"udp":  protoUDP,
	"tcp":  protoTCP,
	"esp":  protoESP,
}

// Fixed, plausible ports for the tcp/udp profiles: the client's 51820 (inside Linux's
// 32768-60999 ephemeral range, so an ordinary source port) talking to the server's :443.
const (
	rawClientPort = 51820
	rawServerPort = 443
	// rawTCPWindow is the advertised window on the synthetic tcp profile. A fixed 0xffff
	// paired with a zero ACK reads as a forged segment to a stateful DPI; a realistic,
	// steady-state window plus a non-zero ACK (set in wire()) make it look like a live
	// established flow instead. 64240 is a very common Linux advertised window.
	rawTCPWindow = 0xFAF0 // 64240
)

// rawPorts returns the (source, destination) port pair THIS end stamps on a tcp/udp carrier packet. A
// conversation reverses — client ephemeral->443, server 443->ephemeral — and two ends both sending
// 51820->443 is not one: no middlebox pairs the halves up, so the downstream arrives as an unsolicited
// NEW inbound flow a NAT drops, and two half-flows aimed at each other are a signature in themselves.
func rawPorts(isClient bool) (sport, dport uint16) {
	if isClient {
		return rawClientPort, rawServerPort
	}
	return rawServerPort, rawClientPort
}

// RawProfileNames lists the valid profile names, sorted, for config validation and its error messages.
// Exported so config.go reads the same map the wire does instead of keeping a second copy of it.
func RawProfileNames() []string {
	out := make([]string, 0, len(rawProfiles))
	for name := range rawProfiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// RawProfileValid reports whether name is a registered profile.
func RawProfileValid(name string) bool {
	_, ok := rawProfiles[name]
	return ok
}

// RawProfileOwning returns the profile that owns an IP protocol number, if any. It is what stops bip's
// raw_proto from borrowing a number whose header a middlebox will try to parse: bip sends no L4 header,
// so an outer "protocol 6" with ciphertext where the TCP header belongs reads as a malformed segment on
// every stateful box in the path — random ports, no SYN it ever saw, a checksum that cannot verify.
func RawProfileOwning(proto int) (string, bool) {
	for _, name := range RawProfileNames() { // sorted: one number, one owner, deterministically
		if rawProfiles[name] == proto {
			return name, true
		}
	}
	return "", false
}

// rawChecksumBindsSource reports whether this profile's carrier header carries a checksum computed over
// the OUTER SOURCE address, so rawEncap's bytes are only valid if the packet really leaves from that
// source. udp and tcp do (the IPv4 pseudo-header is part of l4Checksum); icmp, bip, ipip, gre and esp do
// not. It exists for one decision — sendViaConn's fallback when the pinned source cannot be used.
func rawChecksumBindsSource(profile string) bool {
	switch rawProfiles[profile] {
	case protoUDP, protoTCP:
		return true
	}
	return false
}

// rawProtoFor returns the IP protocol number for a profile name.
func rawProtoFor(profile string) (int, bool) {
	p, ok := rawProfiles[profile]
	return p, ok
}

// rawEffProto returns the EFFECTIVE outer IP protocol number for a carrier. The bare "bip" profile may
// override its native 253 with any 1..255 (raw_proto) to slip past a protocol-whitelist filter. Every
// other profile keeps its fixed number, since that number is tied to its forged L4 header.
func rawEffProto(profile string, rawProto int) (int, bool) {
	base, ok := rawProfiles[profile]
	if !ok {
		return 0, false
	}
	if profile == "bip" && rawProto >= 1 && rawProto <= 255 {
		return rawProto, true
	}
	return base, true
}

// rawEncap prepends profile's carrier header to a sealed frame and returns the bytes to hand the raw
// socket (the kernel prepends the outer IPv4 header, so it is not included here). src/dst are the tunnel
// endpoint IPs, needed for the TCP checksum; isClient selects the direction-dependent fields; id/seq make
// the ICMP/TCP headers look like a live flow; spi is the per-session ESP SPI.
func rawEncap(profile string, payload []byte, src, dst net.IP, isClient bool, id uint16, seq, ack, spi uint32) []byte {
	switch rawProfiles[profile] {
	case protoBIP, protoIPIP:
		return payload // native / IP-in-IP: the sealed frame is the whole payload

	case protoGRE:
		h := make([]byte, 4+len(payload))
		// flags+version = 0 (no checksum/key/seq, version 0); protocol type = IPv4
		binary.BigEndian.PutUint16(h[2:4], 0x0800)
		copy(h[4:], payload)
		return h

	case protoICMP:
		h := make([]byte, 8+len(payload))
		if isClient {
			h[0] = 8 // echo request
		} else {
			h[0] = 0 // echo reply
		}
		binary.BigEndian.PutUint16(h[4:6], id)
		binary.BigEndian.PutUint16(h[6:8], uint16(seq))
		copy(h[8:], payload)
		binary.BigEndian.PutUint16(h[2:4], onesComplementSum(h)) // checksum over header+payload
		return h

	case protoUDP:
		sp, dp := rawPorts(isClient)
		h := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(h[0:2], sp)
		binary.BigEndian.PutUint16(h[2:4], dp)
		binary.BigEndian.PutUint16(h[4:6], uint16(len(h)))
		copy(h[8:], payload)
		cs := l4Checksum(src, dst, protoUDP, h)
		if cs == 0 {
			cs = 0xffff // 0 means "no checksum" in UDP; use the equivalent 0xffff
		}
		binary.BigEndian.PutUint16(h[6:8], cs)
		return h

	case protoTCP:
		// A PSH|ACK data segment on the raw carrier's fixed ports, in this end's direction (seq
		// advances by payload bytes like a real stream; ack is a non-zero peer ISN, not the
		// tell-tale 0). Identical byte layout to the desync injector, so both share buildTCPSeg
		// (tcpseg.go).
		// No options: these are the carrier's OWN frames, with no kernel TCP beside them to be
		// told apart from, and adding any would change the wire format.
		sp, dp := rawPorts(isClient)
		return buildTCPSeg(src, dst, sp, dp, seq, ack, tcpPshAck, rawTCPWindow, nil, payload)

	case protoESP:
		// IPsec ESP (RFC 4303): [SPI 4B][seq 4B] then the sealed frame as the "encrypted
		// payload". A real ESP flow keeps a constant SPI per Security Association and an
		// incrementing sequence — spi is fixed for the session, seq advances per packet. The
		// receiver ignores both (the inner AEAD tag is the real integrity check).
		h := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint32(h[0:4], spi)
		binary.BigEndian.PutUint32(h[4:8], seq)
		copy(h[8:], payload)
		return h
	}
	return payload
}

// rawDecap strips the profile's carrier header, returning the inner sealed frame. A raw ip4 read MAY or
// may not include the outer IPv4 header depending on the platform, so rawDecap detects a genuine one
// (version 4, total-length and protocol matching) and strips it only then. proto is the EFFECTIVE outer
// protocol number, used only to recognise that header; the stripping itself keys off the PROFILE.
func rawDecap(profile string, proto int, pkt []byte) ([]byte, bool) {
	framing := rawProfiles[profile]
	if len(pkt) >= 20 && pkt[0]>>4 == 4 {
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		// A genuine included IPv4 header: version 4, a sane IHL, this carrier's own protocol at byte 9, and a
		// total-length that fits the bytes read. Keying off total <= len(pkt) rather than an exact match
		// tolerates a platform that pads the read; the [ihl:total] slice then drops the pad.
		if ihl >= 20 && total >= ihl && total <= len(pkt) && int(pkt[9]) == proto {
			pkt = pkt[ihl:total] // a real IPv4 header was included; strip it (and any trailing pad)
		}
	}
	switch framing {
	case protoBIP, protoIPIP:
		return pkt, true
	case protoGRE:
		return skip(pkt, 4)
	case protoICMP, protoUDP, protoESP:
		return skip(pkt, 8) // ICMP echo / UDP / ESP (SPI+seq) all carry an 8-byte header
	case protoTCP:
		if len(pkt) < 20 {
			return nil, false
		}
		off := int(pkt[12]>>4) * 4 // data offset word count -> bytes
		return skip(pkt, off)
	}
	return nil, false
}

func skip(pkt []byte, n int) ([]byte, bool) {
	if n < 0 || len(pkt) < n {
		return nil, false
	}
	return pkt[n:], true
}

// sumBytes accumulates the 16-bit big-endian words of b into a running RFC-1071 sum, padding a final
// odd byte with a zero low byte. Fold + complement with foldComplement to finish. Splitting the sum
// out lets a caller add several buffers' partial sums without concatenating them (see l4Checksum).
func sumBytes(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// foldComplement folds a running RFC-1071 sum's carries into 16 bits and returns its one's-complement.
func foldComplement(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// onesComplementSum computes the 16-bit one's-complement checksum (RFC 1071)
// used by ICMP over the buffer as-is (the checksum field must be zero on entry).
func onesComplementSum(b []byte) uint16 {
	return foldComplement(sumBytes(b))
}

// l4Checksum computes the TCP/UDP checksum over the IPv4 pseudo-header plus the
// L4 segment (whose own checksum field must be zero on entry). The 12-byte pseudo-header lives on the
// stack and is summed together with the segment IN PLACE — no per-packet heap buffer or copy. This is
// exact because the pseudo-header is an even length, so sumBytes(ph)+sumBytes(l4) == sumBytes(ph++l4).
func l4Checksum(src, dst net.IP, proto int, l4 []byte) uint16 {
	s, d := src.To4(), dst.To4()
	var ph [12]byte
	if s != nil {
		copy(ph[0:4], s)
	}
	if d != nil {
		copy(ph[4:8], d)
	}
	ph[9] = byte(proto)
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(l4)))
	return foldComplement(sumBytes(ph[:]) + sumBytes(l4))
}
