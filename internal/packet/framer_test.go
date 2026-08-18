package packet

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

func TestWriteFrameOversizeIsDroppable(t *testing.T) {
	for _, obfs := range []bool{false, true} {
		client, _, done := cfPair(t, obfs, "framer-oversize-psk-1234567890")
		big := make([]byte, maxFrame)
		if err := client.writeFrame(typeData, big); !errors.Is(err, errFrameTooBig) {
			t.Fatalf("obfs=%v: oversize writeFrame err = %v, want errFrameTooBig", obfs, err)
		}
		done()
	}
}

func errfmt(format string, a ...any) error { return fmt.Errorf(format, a...) }

func cfPair(t *testing.T, obfs bool, psk string) (client, server *connFramer, cleanup func()) {
	t.Helper()
	c, s := net.Pipe()
	sc, err := crypto.NewSealer(crypto.CipherChaCha, psk, true)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := crypto.NewSealer(crypto.CipherChaCha, psk, false)
	if err != nil {
		t.Fatal(err)
	}
	client = &connFramer{conn: c, r: bufio.NewReaderSize(c, maxFrame+2), sealer: sc, obfs: obfs, psk: psk}
	server = &connFramer{conn: s, r: bufio.NewReaderSize(s, maxFrame+2), sealer: ss, obfs: obfs, psk: psk}
	return client, server, func() { c.Close(); s.Close() }
}

func TestConnFramerNonObfsRoundTrip(t *testing.T) {
	client, server, done := cfPair(t, false, "framer-nonobfs-psk")
	defer done()

	type got struct {
		typ byte
		seq uint64
		pt  []byte
		err error
	}
	rc := make(chan got, 1)
	go func() {
		typ, _, seq, pt, err := server.readFrame()
		rc <- got{typ, seq, append([]byte(nil), pt...), err}
	}()
	if err := client.writeFrame(typeData, []byte("payload-one")); err != nil {
		t.Fatal(err)
	}
	g := <-rc
	if g.err != nil || g.typ != typeData || !bytes.Equal(g.pt, []byte("payload-one")) {
		t.Fatalf("data frame: %+v", g)
	}
	if g.seq != 1 {
		t.Fatalf("first seq = %d, want 1", g.seq)
	}

	go func() {
		typ, _, seq, pt, err := server.readFrame()
		rc <- got{typ, seq, append([]byte(nil), pt...), err}
	}()
	if err := client.writeFrame(typePing, nil); err != nil {
		t.Fatal(err)
	}
	g = <-rc
	if g.err != nil || g.typ != typePing {
		t.Fatalf("ping frame: %+v", g)
	}
	if g.seq != 2 {
		t.Fatalf("ping seq = %d, want 2 (control frames must be sealed+counted)", g.seq)
	}
}

func TestConnFramerObfsHandshake(t *testing.T) {
	client, server, done := cfPair(t, true, "framer-obfs-psk-abcdef")
	defer done()

	srvDone := make(chan error, 1)
	go func() {

		typ, _, seq, _, err := server.readFrame()
		if err != nil {
			srvDone <- err
			return
		}
		if typ != typePing || seq != 1 {
			srvDone <- errfmt("server got typ=%d seq=%d", typ, seq)
			return
		}
		if err := server.sendSalt(); err != nil {
			srvDone <- err
			return
		}
		if err := server.writeFrame(typePong, nil); err != nil {
			srvDone <- err
			return
		}
		srvDone <- nil
	}()

	if err := client.sendSalt(); err != nil {
		t.Fatal(err)
	}
	if err := client.writeFrame(typePing, nil); err != nil {
		t.Fatal(err)
	}
	typ, _, _, _, err := client.readFrame()
	if err != nil {
		t.Fatalf("client read pong: %v", err)
	}
	if typ != typePong {
		t.Fatalf("client got typ=%d, want pong", typ)
	}
	select {
	case err := <-srvDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server side hung")
	}
}
