package packet

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sort"
)

const (
	protoICMP    = 1
	protoIPIP    = 4
	protoTCP     = 6
	protoUDP     = 17
	protoGRE     = 47
	protoESP     = 50
	protoAH      = 51
	protoEtherIP = 97
	protoIPComp  = 108
	protoL2TPv3  = 115
	protoBare    = 253
)

const (
	tcpOptEOL     = 0
	tcpOptNOPKind = 1
	tcpOptTSKind  = 8
	tcpOptTSBytes = 10
)

var rawProfiles = map[string]int{
	"bare":    protoBare,
	"ipip":    protoIPIP,
	"gre":     protoGRE,
	"icmp":    protoICMP,
	"udp":     protoUDP,
	"tcp":     protoTCP,
	"esp":     protoESP,
	"ah":      protoAH,
	"etherip": protoEtherIP,
	"ipcomp":  protoIPComp,
	"l2tpv3":  protoL2TPv3,
}

var rawHeaderLens = map[string]int{
	"bare":    0,
	"ipip":    0,
	"etherip": 2,
	"ipcomp":  4,
	"gre":     4,
	"icmp":    8,
	"udp":     8,
	"esp":     8,
	"l2tpv3":  8,
	"tcp":     32,
	"ah":      24,
}

func rawHeaderLen(profile string) int { return rawHeaderLens[profile] }

const (
	rawClientPort = 51820
	rawServerPort = 443

	rawTCPWindow = 0xFAF0
)

var rawSportPool = [...]uint16{
	20, 21, 22, 53, 69, 80, 88, 110, 111, 113, 115, 123,
	135, 137, 138, 139, 143, 161, 162, 179, 199, 209, 220, 389,
	427, 443, 445, 464, 497, 514, 515, 520, 543, 544, 546, 547,
	548, 587, 591, 593, 601, 623, 636, 646, 749, 830, 853, 873,
	902, 992, 993, 995, 1080, 1099, 1110, 1214, 1400, 1433, 1434, 1521,
	1645, 1646, 1755, 1812, 1813, 1830, 1883, 1935, 2000, 2001, 2049, 2052,
	2053, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376, 2379, 2380,
	2525, 3000, 3050, 3074, 3100, 3128, 3283, 3306, 3307, 3478, 3479, 3480,
	3690, 3724, 3725, 4000, 4222, 4369, 4380, 4443, 5000, 5004, 5005, 5060,
	5061, 5062, 5140, 5222, 5223, 5228, 5229, 5269, 5353, 5432, 5433, 5601,
	5671, 5672, 5800, 5900, 5901, 5938, 6112, 6113, 6379, 6443, 6588, 6881,
	6969, 7000, 7001, 7199, 7946, 8000, 8008, 8009, 8010, 8053, 8080, 8081,
	8086, 8088, 8090, 8100, 8123, 8181, 8200, 8285, 8291, 8301, 8302, 8443,
	8444, 8472, 8500, 8554, 8600, 8880, 8883, 8888, 9000, 9001, 9042, 9080,
	9090, 9091, 9092, 9093, 9100, 9101, 9102, 9160, 9200, 9300, 9418, 9443,
	10000, 10050, 10051, 10248, 10249, 10250, 10255, 10256, 11211, 19302, 19303, 19305,
	25565, 27017, 27018, 27019, 28015, 50000, 61613, 61616,
}

func rawPorts(isClient bool, srv, cli uint16) (sport, dport uint16) {
	if srv == 0 {
		srv = rawServerPort
	}
	if cli == 0 {
		cli = rawClientPort
	}
	if isClient {
		return cli, srv
	}
	return srv, cli
}

func rawRollSport() uint16 {
	n := len(rawSportPool)
	limit := 65536 - (65536 % n)
	for i := 0; i < 8; i++ {
		var rb [2]byte
		if _, err := io.ReadFull(rand.Reader, rb[:]); err != nil {
			return 0
		}
		if v := int(binary.BigEndian.Uint16(rb[:])); v < limit {
			return rawSportPool[v%n]
		}
	}
	return 0
}

func RawProfileHasPorts(profile string) bool {
	switch rawProfiles[profile] {
	case protoUDP, protoTCP:
		return true
	}
	return false
}

func RawProfileNames() []string {
	out := make([]string, 0, len(rawProfiles))
	for name := range rawProfiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func RawProfileValid(name string) bool {
	_, ok := rawProfiles[name]
	return ok
}

func RawProfileOwning(proto int) (string, bool) {
	for _, name := range RawProfileNames() {
		if rawProfiles[name] == proto {
			return name, true
		}
	}
	return "", false
}

func rawChecksumBindsSource(profile string) bool {
	switch rawProfiles[profile] {
	case protoUDP, protoTCP:
		return true
	}
	return false
}

func rawEffProto(profile string, rawProto int) (int, bool) {
	base, ok := rawProfiles[profile]
	if !ok {
		return 0, false
	}
	if profile == "bare" && rawProto >= 1 && rawProto <= 255 {
		return rawProto, true
	}
	return base, true
}

func tcpTSOption(tsval, tsecr uint32) []byte {
	o := []byte{tcpOptNOPKind, tcpOptNOPKind, tcpOptTSKind, tcpOptTSBytes, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(o[4:8], tsval)
	binary.BigEndian.PutUint32(o[8:12], tsecr)
	return o
}

func peerTSVal(tcp []byte) uint32 {
	off := int(tcp[12]>>4) * 4
	if off <= 20 || off > len(tcp) {
		return 0
	}
	for i := 20; i < off; {
		switch tcp[i] {
		case tcpOptEOL:
			return 0
		case tcpOptNOPKind:
			i++
		default:
			if i+1 >= off || int(tcp[i+1]) < 2 || i+int(tcp[i+1]) > off {
				return 0
			}
			if tcp[i] == tcpOptTSKind && tcp[i+1] == tcpOptTSBytes {
				return binary.BigEndian.Uint32(tcp[i+2 : i+6])
			}
			i += int(tcp[i+1])
		}
	}
	return 0
}

func rawEncap(profile string, payload []byte, src, dst net.IP, isClient bool, id, port, cport uint16, seq, ack, spi, tsval, tsecr uint32, flags byte) []byte {
	switch rawProfiles[profile] {
	case protoBare, protoIPIP:
		return payload

	case protoGRE:
		h := make([]byte, rawHeaderLen(profile)+len(payload))

		binary.BigEndian.PutUint16(h[2:4], 0x0800)
		copy(h[4:], payload)
		return h

	case protoICMP:
		h := make([]byte, rawHeaderLen(profile)+len(payload))
		if isClient {
			h[0] = 8
		} else {
			h[0] = 0
		}
		binary.BigEndian.PutUint16(h[4:6], id)
		binary.BigEndian.PutUint16(h[6:8], uint16(seq))
		copy(h[8:], payload)
		binary.BigEndian.PutUint16(h[2:4], onesComplementSum(h))
		return h

	case protoUDP:
		sp, dp := rawPorts(isClient, port, cport)
		h := make([]byte, rawHeaderLen(profile)+len(payload))
		binary.BigEndian.PutUint16(h[0:2], sp)
		binary.BigEndian.PutUint16(h[2:4], dp)
		binary.BigEndian.PutUint16(h[4:6], uint16(len(h)))
		copy(h[8:], payload)
		cs := l4Checksum(src, dst, protoUDP, h)
		if cs == 0 {
			cs = 0xffff
		}
		binary.BigEndian.PutUint16(h[6:8], cs)
		return h

	case protoTCP:
		sp, dp := rawPorts(isClient, port, cport)
		return buildTCPSeg(src, dst, sp, dp, seq, ack, flags, rawTCPWindow, tcpTSOption(tsval, tsecr), payload)

	case protoESP:
		h := make([]byte, rawHeaderLen(profile)+len(payload))
		binary.BigEndian.PutUint32(h[0:4], spi)
		binary.BigEndian.PutUint32(h[4:8], seq)
		copy(h[8:], payload)
		return h

	case protoL2TPv3:
		h := make([]byte, rawHeaderLen(profile)+len(payload))
		sess := spi
		if sess == 0 {
			sess = 1
		}
		binary.BigEndian.PutUint32(h[0:4], sess)
		binary.BigEndian.PutUint32(h[4:8], spi*0x9E3779B9+0x85EBCA6B)
		copy(h[8:], payload)
		return h

	case protoAH:
		h := make([]byte, rawHeaderLen(profile)+len(payload))
		h[0], h[1] = protoIPIP, 4
		binary.BigEndian.PutUint32(h[4:8], spi)
		binary.BigEndian.PutUint32(h[8:12], seq)
		mix := uint64(spi)<<32 | uint64(seq)
		for i := 0; i < 12; i += 4 {
			mix = splitmix64(mix)
			binary.BigEndian.PutUint32(h[12+i:16+i], uint32(mix>>32))
		}
		copy(h[24:], payload)
		return h

	case protoIPComp:
		h := make([]byte, rawHeaderLen(profile)+len(payload))
		h[0] = protoIPIP
		binary.BigEndian.PutUint16(h[2:4], 2)
		copy(h[4:], payload)
		return h

	case protoEtherIP:
		h := make([]byte, rawHeaderLen(profile)+len(payload))
		h[0] = 0x30
		copy(h[2:], payload)
		return h
	}
	return payload
}

func splitmix64(x uint64) uint64 {
	x += 0x9E3779B97F4A7C15
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

func rawDecap(profile string, proto int, pkt []byte) (body []byte, sport uint16, tsval uint32, ok bool) {
	framing := rawProfiles[profile]
	if len(pkt) >= 20 && pkt[0]>>4 == 4 {
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))

		if ihl >= 20 && total >= ihl && total <= len(pkt) && int(pkt[9]) == proto {
			pkt = pkt[ihl:total]
		}
	}
	switch framing {
	case protoBare, protoIPIP:
		return pkt, 0, 0, true
	case protoTCP:
		if len(pkt) < 20 {
			return nil, 0, 0, false
		}
		off := int(pkt[12]>>4) * 4
		b, ok := skip(pkt, off)
		return b, binary.BigEndian.Uint16(pkt[0:2]), peerTSVal(pkt), ok
	case protoUDP:
		if len(pkt) < rawHeaderLen(profile) {
			return nil, 0, 0, false
		}
		b, ok := skip(pkt, rawHeaderLen(profile))
		return b, binary.BigEndian.Uint16(pkt[0:2]), 0, ok
	case protoGRE, protoICMP, protoESP, protoAH, protoEtherIP, protoIPComp, protoL2TPv3:
		b, ok := skip(pkt, rawHeaderLen(profile))
		return b, 0, 0, ok
	}
	return nil, 0, 0, false
}

func skip(pkt []byte, n int) ([]byte, bool) {
	if n < 0 || len(pkt) < n {
		return nil, false
	}
	return pkt[n:], true
}

func sumBytes(b []byte) uint32 {
	var sum uint64
	for len(b) >= 8 {
		v := binary.BigEndian.Uint64(b)
		sum += v >> 48
		sum += (v >> 32) & 0xffff
		sum += (v >> 16) & 0xffff
		sum += v & 0xffff
		b = b[8:]
	}
	for len(b) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint64(b[0]) << 8
	}

	for sum>>32 != 0 {
		sum = (sum & 0xffffffff) + (sum >> 32)
	}
	return uint32(sum)
}

func foldComplement(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func onesComplementSum(b []byte) uint16 {
	return foldComplement(sumBytes(b))
}

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

func rawPortOr(port int) uint16 {
	if port < 1 || port > 65535 {
		return 0
	}
	return uint16(port)
}
