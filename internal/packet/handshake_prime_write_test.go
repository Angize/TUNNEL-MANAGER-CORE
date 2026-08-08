package packet

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestHandshakeAndPrimeFailsWhenThePrimeWriteFails pins that the client handshake path still has a
// CHECKED write on it. sendSalt only fills saltPend now, so the prime ping is the only I/O left — and a
// discarded error would return SUCCESS for a connection whose first byte never left, which the caller
// then adopts as the live carrier. crypto and obfs are off, so the ping is the only thing this does.
func TestHandshakeAndPrimeFailsWhenThePrimeWriteFails(t *testing.T) {
	b := &TCP{isClient: true, cryptoOn: false, obfs: false}

	t.Run("write lands", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer cli.Close()
		defer srv.Close()
		read := make(chan int, 1)
		go func() {
			buf := make([]byte, 512)
			srv.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _ := srv.Read(buf)
			read <- n
		}()

		cf, err := b.handshakeAndPrime(cli)
		if err != nil || cf == nil {
			t.Fatalf("handshakeAndPrime on a live conn: cf=%v err=%v, want a framer and no error", cf, err)
		}
		select {
		case n := <-read:
			if n == 0 {
				t.Fatal("the peer received nothing; the prime ping never reached the wire")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the peer never saw the prime ping")
		}
	})

	t.Run("write fails", func(t *testing.T) {
		cli, srv := net.Pipe()
		srv.Close() // the peer end is gone: every write on cli fails at once
		defer cli.Close()

		cf, err := b.handshakeAndPrime(cli)
		if err == nil {
			t.Fatal("handshakeAndPrime reported SUCCESS for a connection whose prime ping could not be " +
				"written — the caller adopts that carrier, logs a connect, and the tunnel is green on a " +
				"socket that has never carried a byte")
		}
		if err != io.ErrClosedPipe {
			t.Logf("prime write failed with %v (any write error is fine; this only records which)", err)
		}
		if cf != nil {
			t.Fatal("a failed handshakeAndPrime must return a nil framer")
		}
	})
}
