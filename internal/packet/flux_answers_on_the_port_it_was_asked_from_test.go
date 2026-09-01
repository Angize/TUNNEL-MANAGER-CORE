//go:build linux

package packet

import (
	"net"
	"testing"
)

func fluxEnd(t *testing.T, isClient bool, carrier string) *Flux {
	t.Helper()
	f := newFlux(nil, 0, true, true, "a-psk-for-the-flux-pair", "aes-256-gcm", carrier, "random", 0,
		false, 0, 0, isClient)
	t.Cleanup(func() {
		if h := f.hold.Swap(nil); h != nil {
			h.Close()
		}
	})
	return f
}

func segPorts(seg []byte) (uint16, uint16) {
	return uint16(seg[0])<<8 | uint16(seg[1]), uint16(seg[2])<<8 | uint16(seg[3])
}

// flux built both directions from the same shape: carrierSeg wrote sh.sport -> sh.dport whether it was
// the client or the server talking, so a capture of one flux tunnel showed 34871 -> 443 in BOTH
// directions. No real UDP flow does that -- the answer comes back from the port that was asked, to the
// port that asked -- and it is a one-line rule for any DPI that keeps flow state, on a carrier whose
// whole purpose is to look like ordinary UDP.
//
// The client now sends from its own port to the carrier's well-known port and the server answers from
// the well-known port to the port the client was heard on, which is what the kernel would have done.
// Since the client owns the receive port now, it holds a real UDP socket on it -- that is what keeps
// the kernel from answering the server's frames with ICMP port-unreachable, and it also stops anything
// else on the node taking the port from underneath the tunnel.
func TestFluxAnswersOnThePortItWasAskedFrom(t *testing.T) {
	for _, carrier := range []string{"udp", "stun"} {
		cli := fluxEnd(t, true, carrier)
		srv := fluxEnd(t, false, carrier)
		sh := cli.curShape.Load()
		src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)

		up := cli.carrierSeg([]byte("body"), sh, src, dst)
		usp, udp := segPorts(up)
		if udp != sh.dportFor(carrier) {
			t.Errorf("%s: the client asked on port %d, want the carrier's %d", carrier, udp, sh.dportFor(carrier))
		}
		if usp != uint16(cli.sport.Load()) {
			t.Errorf("%s: the client sent from %d, and its status says %d", carrier, usp, cli.sport.Load())
		}

		srv.cliPort.Store(uint32(usp))
		down := srv.carrierSeg([]byte("body"), sh, dst, src)
		dsp, ddp := segPorts(down)
		if dsp != sh.dportFor(carrier) {
			t.Errorf("%s: the server answered from %d, want the port it was asked on, %d", carrier, dsp, sh.dportFor(carrier))
		}
		if ddp != usp {
			t.Errorf("%s: the server answered to %d, want the client's %d", carrier, ddp, usp)
		}
		if usp == dsp && udp == ddp {
			t.Errorf("%s: both directions still carry the same (%d, %d) pair", carrier, usp, udp)
		}
		if !cli.ourPort(ddp) {
			t.Errorf("%s: the client would drop the answer addressed to %d", carrier, ddp)
		}
	}
}

// Before it has heard from the client there is nothing to answer to, so the server falls back to the
// port the shape says the client should be on -- otherwise the very first response would go to port 0.
func TestAFluxServerAnswersTheShapeUntilItHasHeard(t *testing.T) {
	srv := fluxEnd(t, false, "udp")
	sh := srv.curShape.Load()
	_, dp := segPorts(srv.carrierSeg([]byte("body"), sh, net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1)))
	if dp != sh.sport {
		t.Fatalf("the first answer went to port %d, want the shape's %d", dp, sh.sport)
	}
}

// The port the client receives on is a port it holds: nothing else on the node can take it, and the
// kernel answers no ICMP for it.
func TestAFluxClientHoldsItsReceivePort(t *testing.T) {
	cli := fluxEnd(t, true, "udp")
	p := uint16(cli.sport.Load())
	if p == 0 {
		t.Fatal("the client claimed no port at all")
	}
	if h := cli.hold.Load(); h == nil {
		t.Fatal("the client holds no socket on its receive port")
	} else if got := h.LocalAddr().(*net.UDPAddr).Port; got != int(p) {
		t.Fatalf("the held socket is on %d and the tunnel sends from %d", got, p)
	}
	if _, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(p)}); err == nil {
		t.Fatalf("port %d was still free; another process could take the tunnel's receive port", p)
	}

	old := p
	if !cli.rollSourcePort() {
		t.Fatal("the roll refused")
	}
	if !cli.ourPort(old) {
		t.Fatal("the previous port was dropped immediately; answers already in flight are lost")
	}
	if h := cli.hold.Load(); h.LocalAddr().(*net.UDPAddr).Port != int(cli.sport.Load()) {
		t.Fatal("the roll moved the port but not the socket that holds it")
	}
}
