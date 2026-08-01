package packet

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestHandshakeAndPrimeFailsWhenThePrimeWriteFails pins that the client handshake path still has a
// CHECKED write on it.
//
// Before the obfs salt started riding the next frame, sendSalt() did the write itself and returned
// its error, and the client's `if err := cf.sendSalt(); err != nil` covered real I/O. sendSalt now
// only fills saltPend and can fail on RNG/cipher errors alone, so the only I/O left on this path is
// the prime ping — whose error was discarded. handshakeAndPrime then returned (cf, nil), i.e.
// SUCCESS, for a connection whose first byte never left: dialLoop adopts it and logs a connect, and
// buildWarm PARKS it as the warm standby, so a carrier that was dead when it was built waits to
// replace a healthy one.
//
// crypto and obfs are off so the prime ping is the ONLY thing this function does — the test cannot
// accidentally pass on some other guard. Both arms are needed: the failure arm alone would also pass
// if handshakeAndPrime rejected everything.
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
				"written — the caller adopts that carrier, logs a connect, and a warm standby parks it " +
				"as the replacement for a healthy one")
		}
		if err != io.ErrClosedPipe {
			t.Logf("prime write failed with %v (any write error is fine; this only records which)", err)
		}
		if cf != nil {
			t.Fatal("a failed handshakeAndPrime must return a nil framer")
		}
	})
}
