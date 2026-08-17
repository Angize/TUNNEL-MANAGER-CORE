//go:build linux

package packet

import (
	"testing"
	"time"
)

// TestUnbindableSourceLeavesRotation pins ONE rule across every carrier and every shape of the same
// event: a source IP the kernel will not let this host send from leaves rotation. Behavioural check:
// after the path has seen it, a rotate must not land there.
func TestUnbindableSourceLeavesRotation(t *testing.T) {
	const gone = "203.0.113.9" // TEST-NET-3: never a local address
	const good = "127.0.0.1"

	// newPool builds a source pool with the cursor already on the unusable entry, which is where a
	// rotation (or a jump) leaves it before the carrier tries to adopt it.
	newPool := func(t *testing.T) *PeerPool {
		t.Helper()
		sp := NewPeerPool([]string{good, gone}, 0, "")
		if a, moved := sp.rotateOnce(); !moved || a != gone {
			t.Fatalf("pool setup: rotateOnce = %q/%v, want %s/true", a, moved, gone)
		}
		return sp
	}

	for _, tc := range []struct {
		name  string
		adopt func(t *testing.T, sp *PeerPool)
	}{
		{"tcp dial", func(t *testing.T, sp *PeerPool) {
			b := &TCP{isClient: true}
			b.SetSourcePool(sp)
			_ = b.dialer(time.Second) // sourceIP -> canBindSource -> dropUnusableSource
			if s := b.lastSourceUsed(); s != "" {
				t.Fatalf("dialer reported binding %q, but that IP is not on this host", s)
			}
		}},
		{"raw seed", func(t *testing.T, sp *PeerPool) {
			r := &Raw{isClient: true, fakeFd: -1}
			r.link = &directLink{r: r}
			r.SetSourcePool(sp) // seeds localIP from sp.current(), or burns it
			if ip := r.localIP.Load(); ip != nil && ip.IP.String() == gone {
				t.Fatalf("the raw seed stamped %s, which this host cannot send from", gone)
			}
		}},
		{"raw jump", func(t *testing.T, sp *PeerPool) {
			r := &Raw{isClient: true, fakeFd: -1, sp: sp}
			r.link = &directLink{r: r}
			r.adoptSourceRaw()
			if ip := r.localIP.Load(); ip != nil && ip.IP.String() == gone {
				t.Fatalf("the raw jump stamped %s, which this host cannot send from", gone)
			}
		}},
		{"flux seed", func(t *testing.T, sp *PeerPool) {
			f := &Flux{isClient: true}
			f.SetSourcePool(sp)
			if ip := f.localIP.Load(); ip != nil && ip.IP.String() == gone {
				t.Fatalf("the flux seed stamped %s, which this host cannot send from", gone)
			}
		}},
		{"flux jump", func(t *testing.T, sp *PeerPool) {
			f := &Flux{isClient: true, sp: sp}
			f.adoptSourceFlux()
			if ip := f.localIP.Load(); ip != nil && ip.IP.String() == gone {
				t.Fatalf("the flux jump stamped %s, which this host cannot send from", gone)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := newPool(t)
			tc.adopt(t, sp)

			if cur := sp.current(); cur != good {
				t.Fatalf("after the unusable source was seen, the pool still points at %q; it must have "+
					"advanced onto %s", cur, good)
			}
			if a, moved := sp.rotateOnce(); moved {
				t.Fatalf("the next rotation went straight back to %q. An IP the kernel refuses cannot "+
					"carry anything, so leaving it in rotation is the defect — and on the raw udp/tcp "+
					"profiles it is a silent blackout", a)
			}
		})
	}
}
