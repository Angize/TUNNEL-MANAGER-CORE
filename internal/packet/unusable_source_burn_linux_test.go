//go:build linux

package packet

import (
	"testing"
	"time"
)

func TestUnbindableSourceLeavesRotation(t *testing.T) {
	const gone = "203.0.113.9"
	const good = "127.0.0.1"

	newPool := func(t *testing.T) *PeerPool {
		t.Helper()
		sp := NewPeerPool([]string{good, gone}, 0)
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
			_ = b.dialer(time.Second)
			if s := b.lastSourceUsed(); s != "" {
				t.Fatalf("dialer reported binding %q, but that IP is not on this host", s)
			}
		}},
		{"raw seed", func(t *testing.T, sp *PeerPool) {
			r := &Raw{isClient: true, fakeFd: -1}
			r.link = &directLink{r: r}
			r.SetSourcePool(sp)
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
