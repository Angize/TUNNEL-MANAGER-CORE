package packet

import (
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"
)

const (
	facadeNone = 0
	facadeDNS  = 1
	facadeHTTP = 2
)

const (
	dnsHeaderLen = 12
	dnsOptLen    = 11

	httpLenField = "0000000000"
	httpEnd      = "\r\n\r\n"
)

var dnsQName = []byte{3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0}

var dnsPrefixLen = dnsHeaderLen + len(dnsQName) + 4 + dnsOptLen

var (
	httpReqTmpl = httpShell("POST /api/v1/data HTTP/1.1\r\nHost: cdn.jsdelivr.net\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n")
	httpRspTmpl = httpShell("HTTP/1.1 200 OK\r\nServer: nginx\r\n")
)

func httpShell(head string) []byte {
	return []byte(head + "Content-Type: application/octet-stream\r\nContent-Length: " + httpLenField + httpEnd)
}

var facadeIDCtr atomic.Uint32

func init() {
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		facadeIDCtr.Store(binary.BigEndian.Uint32(b[:]))
	}
}

func facadeKindFor(profile string) int {
	switch rawProfiles[profile] {
	case protoUDP:
		return facadeDNS
	case protoTCP:
		return facadeHTTP
	}
	return facadeNone
}

func FacadeSupported(profile string) bool { return facadeKindFor(profile) != facadeNone }

func FacadePort(profile string) int {
	switch facadeKindFor(profile) {
	case facadeDNS:
		return 53
	case facadeHTTP:
		return 80
	}
	return 0
}

func facadePrefixLen(kind int, isQuery bool) int {
	switch kind {
	case facadeDNS:
		return dnsPrefixLen
	case facadeHTTP:
		if isQuery {
			return len(httpReqTmpl)
		}
		return len(httpRspTmpl)
	}
	return 0
}

func FacadeOverhead(profile string) int {
	kind := facadeKindFor(profile)
	q, r := facadePrefixLen(kind, true), facadePrefixLen(kind, false)
	if q >= r {
		return q
	}
	return r
}

func writeFacade(dst []byte, kind int, isQuery bool, payloadLen int) {
	switch kind {
	case facadeDNS:
		writeDNSFacade(dst, isQuery, payloadLen)
	case facadeHTTP:
		writeHTTPFacade(dst, isQuery, payloadLen)
	}
}

func writeDNSFacade(dst []byte, isQuery bool, payloadLen int) {
	clear(dst[:dnsPrefixLen])
	binary.BigEndian.PutUint16(dst[0:2], uint16(splitmix64(uint64(facadeIDCtr.Add(1)))))
	flags := uint16(0x8180)
	if isQuery {
		flags = 0x0100
	}
	binary.BigEndian.PutUint16(dst[2:4], flags)
	binary.BigEndian.PutUint16(dst[4:6], 1)
	binary.BigEndian.PutUint16(dst[10:12], 1)
	q := dnsHeaderLen + copy(dst[dnsHeaderLen:], dnsQName)
	binary.BigEndian.PutUint16(dst[q:q+2], 1)
	binary.BigEndian.PutUint16(dst[q+2:q+4], 1)
	opt := q + 4
	binary.BigEndian.PutUint16(dst[opt+1:opt+3], 41)
	binary.BigEndian.PutUint16(dst[opt+3:opt+5], 4096)
	binary.BigEndian.PutUint16(dst[opt+9:opt+11], uint16(payloadLen))
}

func writeHTTPFacade(dst []byte, isQuery bool, payloadLen int) {
	tmpl := httpRspTmpl
	if isQuery {
		tmpl = httpReqTmpl
	}
	end := copy(dst, tmpl) - len(httpEnd)
	putDecimalZero(dst[end-len(httpLenField):end], payloadLen)
}

func putDecimalZero(dst []byte, v int) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte('0' + v%10)
		v /= 10
	}
}
