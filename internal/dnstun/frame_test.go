package dnstun

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestFrameRoundTripMany(t *testing.T) {

	sizes := []int{0, 1, 20, 1400, 65535}
	var buf bytes.Buffer
	want := make([][]byte, len(sizes))
	for i, sz := range sizes {
		p := make([]byte, sz)
		if _, err := rand.Read(p); err != nil {
			t.Fatal(err)
		}
		want[i] = p
		if err := WritePacket(&buf, p); err != nil {
			t.Fatalf("WritePacket(%d): %v", sz, err)
		}
	}
	for i := range sizes {
		got, err := ReadPacket(&buf)
		if err != nil {
			t.Fatalf("ReadPacket #%d: %v", i, err)
		}
		if !bytes.Equal(got, want[i]) {
			t.Fatalf("packet #%d mismatch (size %d)", i, sizes[i])
		}
	}
}

func TestWritePacketRejectsOversize(t *testing.T) {
	if err := WritePacket(io.Discard, make([]byte, 0x10000)); err == nil {
		t.Fatal("WritePacket accepted a >65535-byte packet")
	}
}

func TestReadPacketTruncatedStream(t *testing.T) {

	var buf bytes.Buffer
	_ = WritePacket(&buf, bytes.Repeat([]byte{0xAB}, 100))
	truncated := buf.Bytes()[:50]
	if _, err := ReadPacket(bytes.NewReader(truncated)); err == nil {
		t.Fatal("ReadPacket returned no error on a truncated frame")
	}
}
