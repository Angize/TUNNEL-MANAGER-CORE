package packet

import (
	"io"
	"net"
	"testing"
	"time"
)

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
		srv.Close()
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
