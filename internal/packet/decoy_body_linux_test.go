//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

// A decoy segment has to carry what the REAL segments of its carrier carry. Everything else about the
// decoy is already shaped to match -- the TCP options and the advertised window are copied off the live
// connection -- and the payload was the one part that was not.
//
// On tcp and plain ws the real bytes are AEAD ciphertext, so random bytes are right. On cover and wss
// every real byte is a TLS record, and there a decoy of bare random bytes is the only thing on the
// 4-tuple that could not be a record at all.

// tcpPair gives a real loopback connection, because tcpFakeSegs needs a genuine *net.TCPAddr 4-tuple and
// reads the live socket's options through it. Driving it any other way tests nothing about the path.
func tcpPair(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		done <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if s := <-done; s != nil {
		t.Cleanup(func() { s.Close() })
	}
	return c
}

// decoyPayloads pulls the TCP payload out of each decoy IPv4 packet tcpFakeSegs built.
func decoyPayloads(t *testing.T, pkts [][]byte) [][]byte {
	t.Helper()
	var out [][]byte
	for _, ip := range pkts {
		if len(ip) < 20 {
			t.Fatalf("decoy shorter than an IPv4 header: %d bytes", len(ip))
		}
		ihl := int(ip[0]&0x0f) * 4
		if len(ip) < ihl+20 {
			t.Fatalf("decoy shorter than IP+TCP headers: %d bytes", len(ip))
		}
		doff := int(ip[ihl+12]>>4) * 4
		if len(ip) < ihl+doff {
			t.Fatalf("decoy shorter than its own TCP data offset")
		}
		out = append(out, ip[ihl+doff:])
	}
	return out
}

func TestADecoyCarriesWhatTheCarrierCarries(t *testing.T) {
	conn := tcpPair(t)

	for _, tc := range []struct {
		name string
		b    *TCP
		tls  bool
	}{
		{"cover", &TCP{dsOn: true, dsCount: 2, cover: true}, true},
		{"wss", &TCP{dsOn: true, dsCount: 2, ws: true, wsTLS: true}, true},
		{"plain tcp", &TCP{dsOn: true, dsCount: 2}, false},
		{"ws without tls", &TCP{dsOn: true, dsCount: 2, ws: true}, false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, pkts := tc.b.tcpFakeSegs(conn)
			if len(pkts) == 0 {
				t.Fatal("no decoys built on a real loopback 4-tuple")
			}
			bodies := decoyPayloads(t, pkts)
			if len(bodies) != len(pkts) {
				t.Fatalf("%d decoys, %d payloads", len(pkts), len(bodies))
			}
			for i, p := range bodies {
				if len(p) < 6 {
					t.Fatalf("decoy %d carries %d bytes", i, len(p))
				}
				looksTLS := p[0] == 0x17 && p[1] == 0x03 && p[2] == 0x03 &&
					int(binary.BigEndian.Uint16(p[3:5])) == len(p)-5
				if tc.tls && !looksTLS {
					t.Fatalf("decoy %d on a TLS carrier does not parse as a TLS record: % x — every real "+
						"byte on this 4-tuple is one, so this segment is the only thing in the flow that "+
						"cannot be, and that identifies the injection", i, p[:6])
				}
				if !tc.tls && looksTLS {
					t.Fatalf("decoy %d carries a TLS record on a carrier whose real bytes are bare "+
						"ciphertext — now IT is the odd one out", i)
				}
			}
		})
	}
}

// TestATLSShapedDecoyStaysTheSameSizeOnTheWire: the record header is carved out of the random body, not
// added to it. A decoy that is five bytes longer than every other carrier's is a length tell of its own.
func TestATLSShapedDecoyStaysTheSameSizeOnTheWire(t *testing.T) {
	for i := 0; i < 200; i++ {
		n := len(tlsRecordPayload())
		if n < 48 || n > 111 {
			t.Fatalf("TLS-shaped decoy is %d bytes, outside the 48..111 the bare form uses", n)
		}
	}
}
