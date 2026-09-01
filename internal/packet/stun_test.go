//go:build linux

package packet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func stunShape(t *testing.T) *fluxShape {
	t.Helper()
	sh := deriveFluxShape("a-psk-for-the-stun-shape", 4242, "random")
	return &sh
}

func TestSTUNRoundTrip(t *testing.T) {
	sh := stunShape(t)
	for _, n := range []int{0, 1, 2, 3, 4, 5, 41, 180, 1400} {
		for _, isClient := range []bool{true, false} {
			payload := bytes.Repeat([]byte{0xC3}, n)
			msg := buildSTUN(payload, sh, isClient)

			if len(msg) < stunOverhead {
				t.Fatalf("n=%d: STUN message too short: %d", n, len(msg))
			}
			if binary.BigEndian.Uint32(msg[4:8]) != stunMagic {
				t.Fatalf("n=%d: missing magic cookie", n)
			}
			msgLen := int(binary.BigEndian.Uint16(msg[2:4]))
			if msgLen%4 != 0 {
				t.Fatalf("n=%d: STUN message length %d is not 4-byte aligned", n, msgLen)
			}
			if 20+msgLen != len(msg) {
				t.Fatalf("n=%d: message length %d does not match body %d", n, msgLen, len(msg)-20)
			}
			got, ok := parseSTUN(msg)
			if !ok {
				t.Fatalf("n=%d: parseSTUN rejected our own message", n)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("n=%d: parseSTUN returned %x want %x", n, got, payload)
			}
		}
	}
}

// The carrier claims to be STUN on 3478/5349/19302, so a censor that parses STUN at all is the reader
// it has to survive. It used to send a Binding REQUEST in both directions -- so the "server" asked the
// "client" for its address, forever, and no response ever came back -- and it put up to 1300 bytes of
// ciphertext in a SOFTWARE attribute, which RFC 5389 defines as a UTF-8 product name. Both are one-line
// rules.
//
// Bulk bytes over STUN are TURN indications: the client sends a Send Indication and the relay answers
// with a Data Indication, each carrying XOR-PEER-ADDRESS and DATA. That is what a WebRTC call through a
// TURN relay looks like on the same ports, and the payload sizes are the payload sizes of media.
func TestSTUNLooksLikeATurnRelay(t *testing.T) {
	sh := stunShape(t)
	payload := bytes.Repeat([]byte{0x5A}, 1200)

	up := buildSTUN(payload, sh, true)
	down := buildSTUN(payload, sh, false)

	if got := binary.BigEndian.Uint16(up[0:2]); got != stunSendIndication {
		t.Errorf("the client sends message type %#04x, want a Send Indication %#04x", got, stunSendIndication)
	}
	if got := binary.BigEndian.Uint16(down[0:2]); got != stunDataIndication {
		t.Errorf("the server sends message type %#04x, want a Data Indication %#04x", got, stunDataIndication)
	}
	if binary.BigEndian.Uint16(up[0:2]) == binary.BigEndian.Uint16(down[0:2]) {
		t.Error("both directions still send the same STUN message type")
	}
	for name, msg := range map[string][]byte{"client": up, "server": down} {
		if got := binary.BigEndian.Uint16(msg[20:22]); got != stunAttrPeer {
			t.Errorf("%s: first attribute is %#04x, want XOR-PEER-ADDRESS %#04x — an indication without "+
				"one is malformed", name, got, stunAttrPeer)
		}
		if got := binary.BigEndian.Uint16(msg[32:34]); got != stunAttrData {
			t.Errorf("%s: the payload rides in attribute %#04x, want DATA %#04x", name, got, stunAttrData)
		}
		if bytes.Contains(msg[:32], []byte{0x80, 0x22}) {
			t.Errorf("%s: a SOFTWARE attribute is still on the wire", name)
		}
	}

	fam, port := up[21+4], binary.BigEndian.Uint16(up[26:28])^uint16(stunMagic>>16)
	ip := binary.BigEndian.Uint32(up[28:32]) ^ stunMagic
	if fam != 0x01 {
		t.Errorf("XOR-PEER-ADDRESS family is %#x, want IPv4", fam)
	}
	if port == 0 {
		t.Error("XOR-PEER-ADDRESS carries port 0")
	}
	if b := byte(ip >> 24); b == 0 || b == 10 || b == 127 || b >= 224 {
		t.Errorf("XOR-PEER-ADDRESS relays through %d.x.x.x, which is not a public address", b)
	}
}

func TestSTUNRejectsNonSTUN(t *testing.T) {
	sh := stunShape(t)
	if _, ok := parseSTUN(bytes.Repeat([]byte{0x00}, 24)); ok {
		t.Error("parseSTUN accepted a datagram with no magic cookie")
	}
	if _, ok := parseSTUN(bytes.Repeat([]byte{0x00}, 10)); ok {
		t.Error("parseSTUN accepted a datagram too short for the STUN header")
	}

	msg := buildSTUN([]byte("hello"), sh, true)
	binary.BigEndian.PutUint16(msg[34:36], uint16(len(msg)))
	if _, ok := parseSTUN(msg); ok {
		t.Error("parseSTUN accepted an attribute length past the buffer end")
	}

	msg = buildSTUN([]byte("hello"), sh, true)
	binary.BigEndian.PutUint16(msg[0:2], 0x0001)
	if _, ok := parseSTUN(msg); ok {
		t.Error("parseSTUN accepted a Binding Request, which this carrier never sends")
	}
}
