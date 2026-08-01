package packet

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// gRPC's 5-byte message prefix is `compressed(1) length(4)`, and the deframer must read both. The body IS
// the data plane here, exactly as on the POST ladder: handing a compressed message to the framer makes
// the AEAD open garbage, so the tunnel comes up, delivers nothing, and the fault is charged to the edge
// far from its cause — and we advertise grpc-accept-encoding: gzip, so an intermediary is invited to.
func TestGrpcDeframerRefusesACompressedMessage(t *testing.T) {
	payload := []byte("a framed tunnel packet")

	t.Run("an uncompressed message still round-trips", func(t *testing.T) {
		g := &grpcDeframingReader{r: bytes.NewReader(grpcFrame(payload))}
		got, err := io.ReadAll(g)
		if err != nil {
			t.Fatalf("a normal message must decode: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload round-trip: got %q want %q", got, payload)
		}
	})

	t.Run("the compressed flag is refused, by name", func(t *testing.T) {
		msg := grpcFrame(payload)
		if msg[0] != 0 {
			t.Fatalf("grpcFrame set the compressed flag itself (%d) — this test would prove nothing", msg[0])
		}
		msg[0] = 1 // exactly what a compressing intermediary sets

		g := &grpcDeframingReader{r: bytes.NewReader(msg)}
		got, err := io.ReadAll(g)
		if err == nil {
			t.Fatalf("a message flagged COMPRESSED was decoded as if it were not: the framer is handed %d bytes it cannot open, and the tunnel comes up carrying nothing", len(got))
		}
		if !strings.Contains(err.Error(), "compressed") {
			t.Errorf("the error does not say what happened, so the operator cannot tell which knob to turn: %v", err)
		}
	})

	// A length-only reading of the header cannot tell these two apart, so this pins that the flag —
	// not the length — is what decides.
	t.Run("the flag decides, not the length", func(t *testing.T) {
		var hdr [5]byte
		hdr[0] = 2 // any non-zero value is a compression algorithm id
		binary.BigEndian.PutUint32(hdr[1:5], 0)
		g := &grpcDeframingReader{r: bytes.NewReader(hdr[:])}
		if _, err := io.ReadAll(g); err == nil {
			t.Error("a zero-length message with the compressed flag set was accepted")
		}
	})
}
