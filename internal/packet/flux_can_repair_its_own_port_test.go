//go:build linux

package packet

import (
	"net"
	"path/filepath"
	"testing"
)

func rigFlux(t *testing.T, dsts []string) (*Flux, *rotationController) {
	t.Helper()
	f := newFlux(nil, 0, true, true, "a-psk-for-the-flux-port", "aes-256-gcm", "udp", "random", 0,
		false, 0, 0, true)
	f.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	if len(dsts) > 0 {
		f.SetPeerPool(NewPeerPool(dsts, 0))
	}
	f.peer.Store(&net.IPAddr{IP: net.IPv4(198, 51, 100, 1)})
	rc := newRotationController(f.pp, f.sp)
	rc.session.setDrop(f.rehandshake)
	rc.port.setRoll(f.rollSourcePort)
	rc.attachStatus(f.st)
	f.st.setPair(rc.pairStatus)
	return f, rc
}

// flux's whole four-tuple is a pure function of (PSK, epoch, shape): deriveFluxShape is the only
// producer of sport, and the epoch turns over every flux_rotate_secs -- 600 s by default, up to a day
// if the operator picks a long interval. Source-port blocking was measured at 16% of the ephemeral
// range, deterministic and protocol-independent, so about one draw in six put the tunnel on a dead
// port; and flux had no repair of any kind for it. rollSourcePort/portRedrawn exist for raw and tcp;
// `grep portRedrawn` matched neither flux nor udp. The ladder's port rung was nil, so the first fail
// verdict went straight to the walk and burned destinations for a port none of them caused, and the
// tunnel stayed dark until the NEXT epoch happened to draw a live port -- with no log naming the port
// as the cause.
//
// Nothing validates the peer's source port -- it is used only on the send path -- so the client can
// redraw it unilaterally, wire-compatible, with no server change.
func TestFluxRedrawsItsSourcePortBeforeItBurnsAnything(t *testing.T) {
	f, rc := rigFlux(t, []string{"198.51.100.1", "198.51.100.2"})
	first := f.pp.current()
	seen := map[uint16]bool{uint16(f.sport.Load()): true}

	for i := 1; i <= portTries; i++ {
		low, high := rc.livePair()
		liveVerdict(t, rc.verdict, rc.st.pathEpoch(), poolCmd{Cmd: cmdFail, Low: low, High: high})
		rc.poll(f.rotatePeerFlux, f.rotateSourceFlux, nil, rc.st.pathEpoch)

		if burned := burnedIn(f.pp); len(burned) != 0 {
			t.Fatalf("draw %d of %d condemned %v before the free port rung was spent", i, portTries, burned)
		}
		if got := f.pp.current(); got != first {
			t.Fatalf("draw %d walked the destination pool to %s", i, got)
		}
		p := uint16(f.sport.Load())
		if seen[p] {
			t.Fatalf("draw %d did not move the source port off %d", i, p)
		}
		seen[p] = true
		if p < repairPortLo || p > repairPortHi {
			t.Errorf("draw %d landed on %d, outside the repair range %d..%d", i, p, repairPortLo, repairPortHi)
		}
	}
}

// The redrawn port has to reach the wire, or the rung spends itself on a number nobody sends from.
func TestARedrawnFluxPortIsOnTheWire(t *testing.T) {
	f, _ := rigFlux(t, nil)
	sh := f.curShape.Load()
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)

	before := f.carrierSeg([]byte("body"), sh, src, dst)
	if got := be16(before[0:2]); got != sh.sport {
		t.Fatalf("the first segment left from %d, want the epoch's %d", got, sh.sport)
	}
	if !f.rollSourcePort() {
		t.Fatal("the roll refused")
	}
	after := f.carrierSeg([]byte("body"), sh, src, dst)
	if got := be16(after[0:2]); got == sh.sport {
		t.Fatal("the segment still leaves from the epoch's source port")
	}
	if got := be16(after[2:4]); got != sh.dport {
		t.Fatalf("the roll moved the DESTINATION port to %d; only the source axis is ours to redraw", got)
	}
	if got, want := be16(after[0:2]), uint16(f.sport.Load()); got != want {
		t.Fatalf("the segment left from %d, and the status reports %d", got, want)
	}
}

// An epoch turnover is a fresh draw for both ends, so it must take the redrawn port back.
func TestAnEpochTurnoverTakesTheSourcePortBack(t *testing.T) {
	f, _ := rigFlux(t, nil)
	sh := f.curShape.Load()
	if !f.rollSourcePort() {
		t.Fatal("the roll refused")
	}
	if uint16(f.sport.Load()) == sh.sport {
		t.Fatal("setup: the roll drew the same port")
	}
	next := deriveFluxShape(f.psk, sh.epoch+1, f.shapeProf)
	f.curShape.Store(&next)
	f.logEp.Store(sh.epoch)
	f.applyEpochSport(&next)
	if got := uint16(f.sport.Load()); got != next.sport {
		t.Fatalf("after the epoch turned over the source port is %d, want the new epoch's %d", got, next.sport)
	}
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
