//go:build linux

package packet

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

type sink struct {
	net.Conn
	buf    bytes.Buffer
	writes int
}

func (s *sink) Write(p []byte) (int, error)      { s.writes++; return s.buf.Write(p) }
func (s *sink) SetWriteDeadline(time.Time) error { return nil }

const batchPSK = "batch-psk-0123456789abcdef"

func clearFramer() (*connFramer, *sink) {
	sk := &sink{}
	return &connFramer{conn: sk, psk: batchPSK}, sk
}

func TestABatchWritesTheSameBytesAsOneAtATime(t *testing.T) {
	pkts := [][]byte{[]byte("first packet"), []byte("second"), bytes.Repeat([]byte{7}, 900)}

	one, oneSink := clearFramer()
	for _, p := range pkts {
		if err := one.writeFrame(typeData, p); err != nil {
			t.Fatalf("writeFrame: %v", err)
		}
	}

	many, manySink := clearFramer()
	var frames [][]byte
	for _, p := range pkts {
		f, err := many.frame(typeData, p)
		if err != nil {
			t.Fatalf("frame: %v", err)
		}
		frames = append(frames, f)
	}
	if err := many.writeAll(frames); err != nil {
		t.Fatalf("writeAll: %v", err)
	}

	if !bytes.Equal(oneSink.buf.Bytes(), manySink.buf.Bytes()) {
		t.Fatalf("the batch put different bytes on the wire\n one at a time: %x\n batched:       %x",
			oneSink.buf.Bytes(), manySink.buf.Bytes())
	}
	if oneSink.writes != len(pkts) {
		t.Fatalf("the one-at-a-time framer made %d writes for %d packets", oneSink.writes, len(pkts))
	}
	if manySink.writes != 1 {
		t.Fatalf("the batch made %d writes, want 1 -- that is the whole point", manySink.writes)
	}
}

func TestABatchOfOneIsTheOldPath(t *testing.T) {
	one, oneSink := clearFramer()
	if err := one.writeFrame(typeData, []byte("only")); err != nil {
		t.Fatal(err)
	}
	many, manySink := clearFramer()
	f, err := many.frame(typeData, []byte("only"))
	if err != nil {
		t.Fatal(err)
	}
	if err := many.writeAll([][]byte{f}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oneSink.buf.Bytes(), manySink.buf.Bytes()) {
		t.Fatalf("a batch of one differs: %x vs %x", oneSink.buf.Bytes(), manySink.buf.Bytes())
	}
	if manySink.writes != 1 {
		t.Fatalf("%d writes for one packet", manySink.writes)
	}
}

func TestAPeerReadsBackEveryFrameOfAnObfsBatch(t *testing.T) {
	sc, err := crypto.NewSealer(crypto.CipherChaCha, batchPSK, true)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := crypto.NewSealer(crypto.CipherChaCha, batchPSK, false)
	if err != nil {
		t.Fatal(err)
	}
	sk := &sink{}
	w := &connFramer{conn: sk, obfs: true, psk: batchPSK, sealer: sc}
	if err := w.sendSalt(); err != nil {
		t.Fatal(err)
	}

	pkts := [][]byte{[]byte("alpha"), []byte("beta"), bytes.Repeat([]byte{9}, 700), []byte("delta")}
	var frames [][]byte
	for _, p := range pkts {
		f, err := w.frame(typeData, p)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, f)
	}
	if err := w.writeAll(frames); err != nil {
		t.Fatal(err)
	}
	if sk.writes != 1 {
		t.Fatalf("the batch made %d writes, want 1 (the salt has to ride it)", sk.writes)
	}

	r := &connFramer{r: bufio.NewReader(bytes.NewReader(sk.buf.Bytes())), obfs: true, psk: batchPSK, sealer: ss}
	for i, want := range pkts {
		typ, _, _, got, err := r.readFrame()
		if err != nil {
			t.Fatalf("frame %d did not read back: %v", i, err)
		}
		if typ != typeData || !bytes.Equal(got, want) {
			t.Fatalf("frame %d came back as type %d %q, want %q", i, typ, got, want)
		}
	}
}
