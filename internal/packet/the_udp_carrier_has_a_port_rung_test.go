package packet

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func rigUDP(t *testing.T, dsts []string) (*UDP, *rotationController) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	b := &UDP{isClient: true, cryptoOn: true, psk: "a-psk-for-the-rung",
		wake: make(chan struct{}, 1), closeCh: make(chan struct{})}
	b.conn.Store(c)
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	if len(dsts) > 0 {
		b.SetPeerPool(NewPeerPool(dsts, 0))
	}
	b.soloPeer.Store(&net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 5555})
	rc := b.newController()
	t.Cleanup(func() {
		if cc := b.conn.Load(); cc != nil {
			cc.Close()
		}
	})
	return b, rc
}

func spendThePortRung(t *testing.T, b *UDP, verdict func()) {
	t.Helper()
	for i := 0; i < portTries; i++ {
		was := udpSport(t, b)
		wasEpoch, _, _ := b.st.tracker.snapshot()
		verdict()
		waitUntil(t, "the free source-port draw to be spent", 20*time.Second, func() bool {
			p := udpSport(t, b)
			if p == was {
				return false
			}
			e, k, ready := b.st.tracker.snapshot()
			return ready && e != wasEpoch && int(k.Sport) == p
		})
	}
}

func udpSport(t *testing.T, b *UDP) int {
	t.Helper()
	la, ok := b.conn.Load().LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("no local addr")
	}
	return la.Port
}

// The udp carrier binds one kernel ephemeral source port in Dial and keeps it for the life of the
// process. Nothing but a source-IP rotation ever replaced the socket, so a client with no source pool
// -- the common shape -- had no source-port axis at all: rc.port.roll was nil, portRung.try()
// short-circuited, and the very first fail verdict went straight to the walk and started burning
// destinations for a port none of them caused.
//
// The 2026-08-17 sweep measured source-port blocking at 16% of the ephemeral range, deterministic,
// binary, and protocol-independent -- all 24 TCP-dead ports were also dead over UDP -- so a udp
// tunnel that draws a bad port on start never comes up at all and the ladder condemns the whole
// destination pool for it.
func TestTheUdpCarrierRedrawsItsSourcePortBeforeItBurnsAnything(t *testing.T) {
	b, rc := rigUDP(t, []string{"198.51.100.1:5555", "198.51.100.2:5555"})
	first := b.pp.current()
	start := udpSport(t, b)
	seen := map[int]bool{start: true}

	for i := 1; i <= portTries; i++ {
		low, high := rc.livePair()
		liveVerdict(t, rc.verdict, rc.st.pathEpoch(), poolCmd{Cmd: cmdFail, Low: low, High: high})
		rc.poll(b.rotatePeerUDP, b.rotateSourceUDP, nil, rc.st.pathEpoch)

		if burned := burnedIn(b.pp); len(burned) != 0 {
			t.Fatalf("draw %d of %d condemned %v — every free rung must be spent before a destination "+
				"is blamed for a dead source port", i, portTries, burned)
		}
		if got := b.pp.current(); got != first {
			t.Fatalf("draw %d walked the destination pool to %s", i, got)
		}
		p := udpSport(t, b)
		if seen[p] {
			t.Fatalf("draw %d did not move the source port off %d", i, p)
		}
		seen[p] = true
		lo, hi := SportBand()
		if int(p) < lo || int(p) > hi {
			t.Errorf("draw %d landed on port %d, outside the band %d..%d the tunnel is allowed",
				i, p, lo, hi)
		}
	}
}

// The socket must really be replaced, not just renamed: a roll that reports success without moving
// the port would spend the rung and change nothing.
func TestARedrawnUdpPortIsADifferentSocket(t *testing.T) {
	b, _ := rigUDP(t, nil)
	before := b.conn.Load()
	beforePort := udpSport(t, b)
	if !b.rollSourcePort() {
		t.Fatal("the roll refused")
	}
	after := b.conn.Load()
	if after == before {
		t.Fatal("the roll kept the same socket")
	}
	if udpSport(t, b) == beforePort {
		t.Fatal("the roll kept the same port")
	}
	if la := after.LocalAddr().(*net.UDPAddr); !la.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("the roll moved the source IP to %s; the port axis must not touch the IP axis", la.IP)
	}
}

// One band for every carrier, and it is the operator's. The default is the same 10000-59999 raw's
// rotation already used, chosen by the operator on 2026-09-09 over the narrower 32768-46999 the udp
// repair rung used to hard-code. The cost is on the record: the 2026-08-17 sweep measured 6.5% of
// ports dead below 47000 and 26% above it, and 26% of this band is above 47000, so a repair draw
// lands on a dead port about 11.5% of the time instead of 6.5%. A dead draw is invisible -- the port
// binds, the traffic does not flow -- so it costs the whole rung. An operator on a path with a low
// ceiling narrows the band on that tunnel.
func TestOneBandForEveryCarrierAndItIsTheOperators(t *testing.T) {
	t.Cleanup(func() { SetSportBand(0, 0) })

	if lo, hi := SportBand(); lo != SportBandLoDefault || hi != SportBandHiDefault {
		t.Fatalf("unset, the band is %d..%d, want the default %d..%d",
			lo, hi, SportBandLoDefault, SportBandHiDefault)
	}
	for i := 0; i < 20000; i++ {
		if p := drawSport(); int(p) < SportBandLoDefault || int(p) > SportBandHiDefault {
			t.Fatalf("draw %d landed on %d, outside the default band", i, p)
		}
	}

	SetSportBand(20000, 20999)
	if lo, hi := SportBand(); lo != 20000 || hi != 20999 {
		t.Fatalf("the band the operator set reads back as %d..%d", lo, hi)
	}
	for i := 0; i < 20000; i++ {
		if p := drawSport(); p < 20000 || p > 20999 {
			t.Fatalf("draw %d landed on %d, outside the band the operator set", i, p)
		}
	}

	SetSportBand(1023, 40000)
	if lo, hi := SportBand(); lo != SportBandLoDefault || hi != SportBandHiDefault {
		t.Errorf("a band starting below the privileged floor was taken as %d..%d; core validates the "+
			"config, but a carrier handed a bad band must still draw from something sane", lo, hi)
	}
}

// raw's rotation and every other carrier's repair rung read the SAME band now, so a tunnel that sets
// one number does not get two different answers depending on which mechanism moves its port.
func TestTheRotationAndTheRepairShareOneBand(t *testing.T) {
	t.Cleanup(func() { SetSportBand(0, 0) })
	SetSportBand(24000, 25999)
	lo, span := sportBand(24000, 25999)
	if bLo, bHi := SportBand(); int(lo) != bLo || int(lo+span-1) != bHi {
		t.Fatalf("the rotation resolves %d..%d and the repair draw %d..%d from the same two numbers",
			lo, lo+span-1, bLo, bHi)
	}
}
