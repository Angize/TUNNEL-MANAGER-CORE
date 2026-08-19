//go:build linux

package packet

import (
	"net"
	"path/filepath"
	"testing"
)

type tuple struct {
	sport uint16
	seq   uint32
	ack   uint32
	ts    uint32
	bytes uint32
}

func (r *Raw) tuple() tuple {
	return tuple{sport: r.cport(), seq: r.tcpISN.Load(), ack: r.tcpAck.Load(),
		ts: r.tsBase.Load(), bytes: r.tcpBytes.Load()}
}

func movingRaw(t *testing.T, dsts, srcs []string) *Raw {
	t.Helper()
	dir := t.TempDir()
	r := &Raw{isClient: true, profile: "tcp", proto: protoTCP,
		port: 443, psk: "a-new-path-is-a-new-flow-psk-0123", cipher: "chacha20-poly1305",
		closeCh: make(chan struct{})}
	r.link = &capturingLink{r: r}
	r.setSportMode(true)
	if !r.sportRandom {
		t.Fatal("the tcp profile did not arm the source-port axis")
	}
	r.peer.Store(&net.IPAddr{IP: net.IPv4(10, 30, 0, 2)})
	r.localIP.Store(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if len(dsts) > 0 {
		r.SetPeerPool(NewPeerPool(dsts, 0, filepath.Join(dir, "d.json")))
	}
	if len(srcs) > 0 {
		r.sp = NewPeerPool(srcs, 0, filepath.Join(dir, "s.json"))
	}
	r.newTCPFlow()
	r.tcpBytes.Store(4096)
	return r
}

func TestEveryPathChangeStartsAFlowOfItsOwn(t *testing.T) {
	dsts := []string{"10.30.0.2", "10.30.0.3"}

	srcs := []string{"127.0.0.1", "127.0.0.2"}
	for _, tc := range []struct {
		name string
		move func(*testing.T, *Raw)
	}{
		{"the judge burns the destination and the walk advances", func(_ *testing.T, r *Raw) {
			r.rotatePeerRaw(false)
		}},
		{"the operator's timer advances the destination", func(_ *testing.T, r *Raw) {
			r.rotatePeerRaw(true)
		}},
		{"the operator pins a destination by hand", func(t *testing.T, r *Raw) {
			if !r.pp.selectEntry("10.30.0.3") {
				t.Fatal("could not pin the destination")
			}
			r.adoptPeerRaw()
		}},
		{"the walk advances the source", func(_ *testing.T, r *Raw) {
			r.rotateSourceRaw(false)
		}},
		{"the operator pins a source by hand", func(t *testing.T, r *Raw) {
			if !r.sp.selectEntry("127.0.0.2") {
				t.Fatal("could not pin the source")
			}
			r.adoptSourceRaw()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := movingRaw(t, dsts, srcs)
			was := r.tuple()

			tc.move(t, r)

			got := r.tuple()
			if got == was {
				t.Fatal("the path did not move at all, so this proves nothing")
			}
			if got.seq == was.seq {
				t.Errorf("the new path carries on the old flow's sequence (%d). An observer watching "+
					"both endpoints joins the two on one subtraction, which is the whole thing moving "+
					"off a burned address was supposed to prevent", got.seq)
			}
			if got.ts == was.ts {
				t.Errorf("the new path carries on the old flow's timestamp clock (%d) — the same join, "+
					"on a field that ticks in milliseconds and is even easier to line up", got.ts)
			}
			if got.ack == was.ack {
				t.Errorf("the new path acknowledges the same peer ISN (%d) as the old one", got.ack)
			}
			if got.bytes != 0 {
				t.Errorf("the byte counter carried %d bytes of the old flow into the new one, so the "+
					"first packet continues the old series however fresh the ISN is", got.bytes)
			}
			if got.sport == was.sport {
				t.Errorf("the new path kept the old source port (%d) — the last field the two flows "+
					"still have in common", got.sport)
			}
		})
	}
}

func TestPinningWhereWeAlreadyAreMovesNothing(t *testing.T) {
	r := movingRaw(t, []string{"10.30.0.2", "10.30.0.3"}, []string{"127.0.0.1", "127.0.0.2"})
	was := r.tuple()

	if !r.pp.selectEntry("10.30.0.2") {
		t.Fatal("could not pin the destination we are already on")
	}
	r.adoptPeerRaw()
	if !r.sp.selectEntry("127.0.0.1") {
		t.Fatal("could not pin the source we are already on")
	}
	r.adoptSourceRaw()

	if got := r.tuple(); got != was {
		t.Errorf("a pin onto the endpoint the tunnel is already on redrew the tuple (%+v -> %+v). "+
			"Nothing moved, so nothing is linkable that was not already — and the epoch bump it costs "+
			"makes the node throw away the verdict that straddles it", was, got)
	}
}

func TestAFixedPortTunnelKeepsItsPortAcrossAPathChange(t *testing.T) {
	r := movingRaw(t, []string{"10.30.0.2", "10.30.0.3"}, nil)
	r.setSportMode(false)
	r.cliPort.Store(uint32(rawClientPort))
	was := r.tuple()

	r.rotatePeerRaw(false)

	got := r.tuple()
	if got.sport != was.sport {
		t.Errorf("the operator turned the source-port axis off and the path change moved the port "+
			"anyway (%d -> %d)", was.sport, got.sport)
	}
	if got.seq == was.seq {
		t.Error("...but the flow itself must still restart: the port is not the only field the two " +
			"paths can be joined on")
	}
}
