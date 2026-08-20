//go:build linux

package packet

import (
	"os"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

func joinCarrier(t *testing.T) (*TCP, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	b := &TCP{dev: tun.FromFile(w, "wsq"), isClient: true}
	t.Cleanup(func() { b.writers().close() })
	return b, r
}

func arrives(t *testing.T, r *os.File, n int) bool {
	t.Helper()
	done := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, n)
		if _, err := r.Read(buf); err == nil {
			done <- struct{}{}
		}
	}()
	select {
	case <-done:
		return true
	case <-time.After(700 * time.Millisecond):
		return false
	}
}

func TestTheStreamCarrierWritesThroughTheJoiningWriter(t *testing.T) {
	b, r := joinCarrier(t)

	first := b.writers()
	if b.writers() != first {
		t.Fatal("a fresh writer set per call: every packet would start a goroutine and leak it")
	}

	pkt := flowPkt(t, "10.0.0.1", "10.0.0.2", 6, 1234, 443)
	b.handleFrame(nil, typeData, pkt)
	if !arrives(t, r, len(pkt)) {
		t.Fatal("the packet never reached the carrier's own device")
	}
}

// A carrier that still wrote to the device itself would pass the test above unchanged -- the packet
// arrives either way. What separates the two is WHOSE hands it goes through: once the writer set is
// closed, a packet handed to the carrier must go nowhere, because the only path to the device is
// through it. Writing around it would deliver the packet anyway.
func TestTheStreamCarrierHasNoPathAroundItsWriter(t *testing.T) {
	b, r := joinCarrier(t)
	pkt := flowPkt(t, "10.0.0.1", "10.0.0.2", 6, 1234, 443)

	b.handleFrame(nil, typeData, pkt)
	if !arrives(t, r, len(pkt)) {
		t.Fatal("the packet never reached the device while the writer was open")
	}

	b.writers().close()
	b.handleFrame(nil, typeData, pkt)
	if arrives(t, r, len(pkt)) {
		t.Fatal("a packet reached the device after the writer set was closed: the carrier is writing " +
			"around it, so nothing it does can ever be joined")
	}
}
