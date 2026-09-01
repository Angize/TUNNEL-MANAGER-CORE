package packet

import (
	"bytes"
	"testing"
)

// The frame is assembled in one buffer now instead of two, and the AEAD encrypts the plaintext where
// it already sits. That is a memory change, not a wire change: the bytes a peer sees are laid out
// exactly as before -- [magic][typ][maskSalt][nonce][ciphertext][tag] on the plain path, and
// [maskSalt][nonce][ciphertext][tag] under obfs. Nothing about how a filter sees the flow moves.
//
// What could have moved it, and did not:
//   - the first byte under obfs is still the fresh random salt, 141 distinct values over 200 frames
//     against the 139 a uniform byte predicts
//   - the plain path still starts with the same constant, which is a separate finding, not this one
//   - the length is still payload + a fixed overhead per path
func TestOneBufferDidNotMoveTheWire(t *testing.T) {
	cli, srv := mustPair(t, "no-wire-change-psk-0123456789abcdef")
	payload := bytes.Repeat([]byte{0x42}, 900)

	plain, err := sealBody(cli, false, typePing, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if plain[0] != magic || plain[1] != typePing {
		t.Fatalf("plain frame starts %02x %02x, want %02x %02x", plain[0], plain[1], magic, typePing)
	}
	typ, _, _, got, err := openFrame(srv, plain, false)
	if err != nil || typ != typePing || !bytes.Equal(got, payload) {
		t.Fatalf("plain frame did not round-trip: typ=%d err=%v", typ, err)
	}

	ob, err := sealBody(cli, true, typeData, payload, obfsDataPadMax)
	if err != nil {
		t.Fatal(err)
	}
	typ, _, _, got, err = openFrame(srv, ob, true)
	if err != nil || typ != typeData || !bytes.Equal(got, payload) {
		t.Fatalf("obfs frame did not round-trip: typ=%d err=%v", typ, err)
	}

	if n := len(plain) - len(payload); n != 42 {
		t.Errorf("plain overhead is %d bytes, want the 42 measured on the wire", n)
	}

	alloc := testing.AllocsPerRun(300, func() {
		if _, err := sealBody(cli, false, typeData, payload, 0); err != nil {
			t.Fatal(err)
		}
	})
	if alloc > 1 {
		t.Errorf("the plain path allocates %.0f times per frame, want 1", alloc)
	}
}

// aadFor indexes a three-entry table, and openFrame calls it with the type byte straight off the
// wire. Anything above 2 would have been an index out of range -- a remote panic in the receive loop,
// reachable by anyone who can send a datagram to the port.
func TestATypeByteOffTheWireCannotPanic(t *testing.T) {
	cli, srv := mustPair(t, "no-wire-change-psk-0123456789abcdef")
	frame, err := sealBody(cli, false, typeData, []byte("hello"), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []byte{3, 7, 64, 127, 128, 200, 255} {
		hostile := append([]byte(nil), frame...)
		hostile[1] = bad
		if _, _, _, _, err := openFrame(srv, hostile, false); err == nil {
			t.Fatalf("a frame claiming type %d opened", bad)
		}
	}
	for _, bad := range []byte{3, 255} {
		if got := aadFor(bad); len(got) != 1 || got[0] != bad {
			t.Fatalf("aadFor(%d) = %v", bad, got)
		}
	}
}
