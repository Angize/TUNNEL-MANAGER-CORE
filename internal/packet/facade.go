package packet

import (
	"bytes"
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
	dnsPrefixLen = 43
	httpCLWidth  = 10
)

var dnsQName = []byte{3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0}

var (
	httpReqTmpl = []byte("POST /api/v1/data HTTP/1.1\r\nHost: cdn.jsdelivr.net\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nContent-Type: application/octet-stream\r\nContent-Length: 0000000000\r\n\r\n")
	httpRspTmpl = []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/octet-stream\r\nContent-Length: 0000000000\r\n\r\n")

	httpReqCLOff = bytes.Index(httpReqTmpl, []byte("Content-Length: ")) + len("Content-Length: ")
	httpRspCLOff = bytes.Index(httpRspTmpl, []byte("Content-Length: ")) + len("Content-Length: ")
)

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
	if isQuery {
		binary.BigEndian.PutUint16(dst[2:4], 0x0100)
	} else {
		binary.BigEndian.PutUint16(dst[2:4], 0x8180)
	}
	binary.BigEndian.PutUint16(dst[4:6], 1)
	binary.BigEndian.PutUint16(dst[10:12], 1)
	copy(dst[12:28], dnsQName)
	binary.BigEndian.PutUint16(dst[28:30], 1)
	binary.BigEndian.PutUint16(dst[30:32], 1)
	dst[32] = 0
	binary.BigEndian.PutUint16(dst[33:35], 41)
	binary.BigEndian.PutUint16(dst[35:37], 4096)
	binary.BigEndian.PutUint32(dst[37:41], 0)
	binary.BigEndian.PutUint16(dst[41:43], uint16(payloadLen))
}

func writeHTTPFacade(dst []byte, isQuery bool, payloadLen int) {
	tmpl, off := httpRspTmpl, httpRspCLOff
	if isQuery {
		tmpl, off = httpReqTmpl, httpReqCLOff
	}
	copy(dst[:len(tmpl)], tmpl)
	putDecimalZero(dst[off:off+httpCLWidth], payloadLen)
}

func putDecimalZero(dst []byte, v int) {
	if v < 0 {
		v = 0
	}
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte('0' + v%10)
		v /= 10
	}
}
