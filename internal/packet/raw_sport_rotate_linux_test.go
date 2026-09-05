//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
)

func rotClient(every int, dports ...int) *Raw {
	r := &Raw{profile: "udp", isClient: true, port: rawServerPort}
	r.proto = protoUDP
	r.localIP.Store(&net.IPAddr{IP: testSrc})
	n := 0
	if len(dports) > 0 {
		n = dports[0]
	}
	r.setSportRotate(SportRotation{Every: every, Dports: n})
	return r
}

func rotServer(every int, learned uint16) *Raw {
	r := &Raw{profile: "udp", isClient: false, port: rawServerPort}
	r.proto = protoUDP
	r.localIP.Store(&net.IPAddr{IP: testSrc})
	r.setSportRotate(SportRotation{Every: every})
	r.cliPort.Store(uint32(learned))
	return r
}

// The source port on the wire is read out of the frame the carrier actually builds, so these tests
// exercise the emit path rather than the counter behind it.
func wireSport(r *Raw, cport uint16) uint16 {
	return binary.BigEndian.Uint16(r.wireTo([]byte("payload-payload"), testDst, cport)[0:2])
}

func wireDport(r *Raw, cport uint16) uint16 {
	return binary.BigEndian.Uint16(r.wireTo([]byte("payload-payload"), testDst, cport)[2:4])
}

// The whole point of raw_sport_rotate is that a fresh forged source port every N packets mints a new
// 5-tuple, and the measured middlebox gives each tuple a small fixed packet budget. This drives the
// frame builder every carrier write goes through and counts what lands on the wire, so it says
// something about the packets, not about the counter.
func TestSportRotateAdvancesEveryNPacketsOnTheClientWire(t *testing.T) {
	const every = 5
	r := rotClient(every)
	if !r.rotActive() {
		t.Fatal("rotActive() is false after setSportRotate on a udp client")
	}

	per := map[uint16]int{}
	var order []uint16
	for i := 0; i < every*40; i++ {
		p := wireSport(r, r.cport())
		if p < sportBandLo || p >= sportBandLo+sportBandSpan {
			t.Fatalf("packet %d: sport %d outside [%d,%d)", i, p, sportBandLo, sportBandLo+sportBandSpan)
		}
		if per[p] == 0 {
			order = append(order, p)
		}
		per[p]++
	}
	if len(order) != 40 {
		t.Fatalf("%d packets at every=%d used %d distinct ports, want 40", every*40, every, len(order))
	}
	for _, p := range order {
		if per[p] != every {
			t.Fatalf("port %d carried %d packets, want exactly %d", p, per[p], every)
		}
	}
	if dp := wireDport(r, r.cport()); dp != rawServerPort {
		t.Fatalf("client dest port %d changed; only the source may rotate (want %d)", dp, rawServerPort)
	}
}

// The download leg is capped too, so the server must rotate ITS OWN source while the port it sends TO
// stays whatever the client last used.
func TestSportRotateRotatesTheServerSourceNotItsReplyTarget(t *testing.T) {
	const every = 3
	r := rotServer(every, 41000)

	per := map[uint16]int{}
	for i := 0; i < every*20; i++ {
		pkt := r.wireTo([]byte("payload-payload"), testDst, r.cport())
		sp := binary.BigEndian.Uint16(pkt[0:2])
		dp := binary.BigEndian.Uint16(pkt[2:4])
		if sp < sportBandLo || sp >= sportBandLo+sportBandSpan {
			t.Fatalf("packet %d: server source %d outside the rotation band", i, sp)
		}
		if dp != 41000 {
			t.Fatalf("packet %d: server reply target moved to %d; it must stay the learned client port", i, dp)
		}
		per[sp]++
	}
	if len(per) != 20 {
		t.Fatalf("the server used %d distinct source ports over %d packets, want 20", len(per), every*20)
	}
	for p, n := range per {
		if n != every {
			t.Fatalf("server port %d carried %d packets, want exactly %d", p, n, every)
		}
	}
}

// Rotation needs a forged port pair, and is off unless asked.
func TestSportRotateNeedsPortsAndIsOffByDefault(t *testing.T) {
	for _, profile := range RawProfileNames() {
		r := &Raw{profile: profile, isClient: true, port: rawServerPort}
		r.proto = rawProfiles[profile]
		r.setSportRotate(SportRotation{Every: 5})
		if want := RawProfileHasPorts(profile); r.rotActive() != want {
			t.Errorf("raw/%s: rotActive()=%v, want %v", profile, r.rotActive(), want)
		}
	}

	ru := &Raw{profile: "udp", isClient: true, port: rawServerPort}
	ru.proto = protoUDP
	ru.localIP.Store(&net.IPAddr{IP: testSrc})
	ru.cliPort.Store(rawClientPort)
	if ru.rotActive() {
		t.Fatal("rotActive() is true with the knob unset")
	}
	for i := 0; i < 20; i++ {
		if p := wireSport(ru, ru.cport()); p != rawClientPort {
			t.Fatalf("packet %d: source moved to %d with rotation off (want %d)", i, p, rawClientPort)
		}
	}
}

// When rotation is on, the ephemeral source port is not a stable attribute of the path, so it must be
// kept out of the status path key -- otherwise the once-a-second sampler sees a new key every tick,
// churns the epoch, and the node's verdict is discarded as stale every time.
func TestSportRotateStaysOutOfThePathKey(t *testing.T) {
	r := rotClient(4)
	r.soloPeer.Store(&net.IPAddr{IP: testDst})
	k, _ := r.livePath()
	if k.Sport != 0 || k.Dport != 0 {
		t.Fatalf("rotating source leaked into the path key: %d->%d (want 0->0)", k.Sport, k.Dport)
	}
}

// A keepalive is a packet on the wire and spends the same per-tuple budget as a data packet, so it has
// to advance the rotation. It did not: the counter only moved on the TUN read path, so a tunnel with no
// user traffic sent every keepalive from ONE port until its budget was gone, and the first data after
// an idle gap went out on the exhausted tuple.
func TestEveryEmittedPacketAdvancesTheRotationNotOnlyTunData(t *testing.T) {
	const every = 5
	for _, tc := range []struct {
		name string
		emit func(*Raw)
	}{
		{"control frames (ping, pong, handshake)", func(r *Raw) { r.writeCtrlTo([]byte("ctrl"), &net.IPAddr{IP: testDst}, r.cport()) }},
		{"data frames", func(r *Raw) { r.writeOut(r.wire([]byte("payload-payload"), testDst), &net.IPAddr{IP: testDst}) }},
	} {
		r := rotClient(every)
		link := &capturingLink{r: r}
		r.link = link

		for i := 0; i < every*8; i++ {
			tc.emit(r)
		}
		if len(link.sent) != every*8 {
			t.Fatalf("%s: %d frames reached the link, want %d", tc.name, len(link.sent), every*8)
		}
		per := map[uint16]int{}
		for _, pkt := range link.sent {
			per[binary.BigEndian.Uint16(pkt[0:2])]++
		}
		if len(per) != 8 {
			t.Errorf("%s: %d packets at every=%d left from %d ports, want 8",
				tc.name, every*8, every, len(per))
		}
		for p, n := range per {
			if n != every {
				t.Errorf("%s: port %d carried %d packets, want exactly %d", tc.name, p, n, every)
			}
		}
	}
}

// rotSportNext reports the port the NEXT packet would draw, without spending a draw.
func rotSportNext(r *Raw) uint16 {
	return r.rotPerm.at(uint64(r.rotIdx) + r.txCount.Load()/uint64(r.sportEvery))
}

// The tunnel runs one tunToNet goroutine per tx queue (workers 1..4). The count and the port used to be
// two separate atomics with the port read later still, so a tuple could carry N+several packets -- and
// at N equal to the middlebox budget those extra packets are dropped. The port each packet uses is now
// a pure function of that packet's own index, so this must hold exactly at any width.
func TestEveryPortCarriesExactlyNPacketsUnderConcurrentQueues(t *testing.T) {
	for _, every := range []int{3, 5, 6} {
		for _, workers := range []int{1, 2, 4, 8} {
			// Kept under sportBandSpan*every so one pass covers the whole run: past that the walk
			// legitimately comes back around, and reuse-after-a-full-pass is what the test below is for.
			const perWorker = 3000
			r := rotClient(every)

			out := make([]map[uint16]int, workers)
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					local := map[uint16]int{}
					for i := 0; i < perWorker; i++ {
						local[wireSport(r, r.cport())]++
					}
					out[id] = local
				}(w)
			}
			wg.Wait()

			total := map[uint16]int{}
			for _, m := range out {
				for p, n := range m {
					total[p] += n
				}
			}
			sent := workers * perWorker
			// the run stops mid-group, so the last port legitimately carries the remainder
			full, rest := sent/every, sent%every
			wantPorts := full
			if rest > 0 {
				wantPorts++
			}
			if len(total) != wantPorts {
				t.Errorf("every=%d workers=%d: %d packets used %d ports, want %d",
					every, workers, sent, len(total), wantPorts)
			}
			short := 0
			for p, n := range total {
				if n == every {
					continue
				}
				if n == rest && short == 0 {
					short++
					continue
				}
				t.Errorf("every=%d workers=%d: port %d carried %d packets, want exactly %d",
					every, workers, p, n, every)
			}
		}
	}
}

// The desync decoys are real packets on the burned path and spend the same budget. They used to ride
// whatever port the rotation happened to be sitting on, so a handshake with fake_count decoys put
// fake_count+1 packets on one tuple.
func TestDecoysDrawTheirOwnPortRatherThanRidingTheCurrentOne(t *testing.T) {
	const every = 2
	r := rotClient(every)
	first := rotSportNext(r)

	// what sendFakes builds for each decoy, without the raw socket it would send them on
	seen := map[uint16]int{}
	for i := 0; i < 8; i++ {
		srv, cli := r.wirePorts(r.cport())
		pkt := rawEncap(r.profile, fakePayload(), testSrc, testDst, r.isClient, r.icmpID, srv, cli,
			0, 0, r.spi, 0, 0, tcpPshAck)
		seen[binary.BigEndian.Uint16(pkt[0:2])]++
	}
	if len(seen) != 8/every {
		t.Fatalf("8 decoys at every=%d used %d ports, want %d", every, len(seen), 8/every)
	}
	if seen[first] != every {
		t.Fatalf("the first port carried %d decoys, want %d", seen[first], every)
	}
}

// The band walk used to be a plain +1 ramp: every install stepped by exactly one and wrapped at the
// same two numbers, which is a two-packet signature an observer can match without knowing anything
// about the tunnel. The walk is now keyed by the PSK and the role, so it must still visit every port
// once before repeating -- that is what keeps a port off the wire for a whole pass -- while the step
// differs per tunnel and between the two ends of the same tunnel.
func TestTheBandWalkIsKeyedAndStillVisitsEveryPortOnce(t *testing.T) {
	perm := rotPermFrom("a-sufficiently-long-preshared-key", true)
	seen := make(map[uint16]bool, sportBandSpan)
	var steps = map[int]int{}
	prev := perm.at(0)
	for i := uint64(0); i < sportBandSpan; i++ {
		p := perm.at(i)
		if p < sportBandLo || p >= sportBandLo+sportBandSpan {
			t.Fatalf("index %d drew %d, outside [%d,%d)", i, p, sportBandLo, sportBandLo+sportBandSpan)
		}
		if seen[p] {
			t.Fatalf("port %d repeated after %d of %d draws; a port must stay off the wire for a whole pass",
				p, i, sportBandSpan)
		}
		seen[p] = true
		if i > 0 {
			steps[int(p)-int(prev)]++
		}
		prev = p
	}
	if len(seen) != sportBandSpan {
		t.Fatalf("a full pass covered %d ports, want %d", len(seen), sportBandSpan)
	}
	// A constant stride IS the fingerprint: an observer who sees two consecutive source ports predicts
	// every one after them. The affine walk this replaced had exactly two step values -- the stride, and
	// the stride minus the span at the one index where it wrapped -- so it passed a "more than one step"
	// check while staying trivially predictable. A keyed permutation has no stride to find.
	if len(steps) < sportBandSpan/4 {
		t.Fatalf("the walk took only %d distinct steps over %d draws — consecutive ports are predictable from the stride",
			len(steps), sportBandSpan)
	}

	// the two ends of one tunnel must not walk the same sequence
	srv := rotPermFrom("a-sufficiently-long-preshared-key", false)
	same := 0
	for i := uint64(0); i < 4096; i++ {
		if perm.at(i) == srv.at(i) {
			same++
		}
	}
	if same > 4096/1000 {
		t.Errorf("client and server drew the same port at %d of 4096 indexes; the role salt is not working", same)
	}

	// and two tunnels must not walk the same sequence either
	other := rotPermFrom("a-different-preshared-key-entirely", true)
	same = 0
	for i := uint64(0); i < 4096; i++ {
		if perm.at(i) == other.at(i) {
			same++
		}
	}
	if same > 4096/1000 {
		t.Errorf("two different PSKs drew the same port at %d of 4096 indexes", same)
	}
}

// The band is walked by cycle-walking a Feistel permutation over a power-of-two domain. The domain has
// to cover the band: if the band ever outgrew it, at() would spin for ever on the indexes past the end,
// and it would do it inside the per-packet send path.
func TestTheWalkDomainCoversTheWholeBand(t *testing.T) {
	if rotDomain < sportBandSpan {
		t.Fatalf("the permutation domain is %d but the band is %d ports wide", rotDomain, sportBandSpan)
	}
	if sportBandLo+sportBandSpan-1 > 65535 {
		t.Fatalf("the band ends at %d, past the last UDP port", sportBandLo+sportBandSpan-1)
	}
	if sportBandLo < 1024 {
		t.Fatalf("the band starts at %d, inside the privileged ports", sportBandLo)
	}
}

// The band is 10000 ports wide, so a busy tunnel spends all of it and comes back. The distance between
// one use of a port and the next is the whole feature: a port that returns before the middlebox has
// forgotten it (~45 s) is a tuple over its packet budget, which is the thing rotation exists to avoid.
// The walk must therefore come back EXACTLY one pass later, never sooner -- which is what a permutation
// buys over drawing at random, where the birthday bound puts the first repeat ~125 draws in.
func TestAPortComesBackOnlyAfterTheWholeBandHasBeenSpent(t *testing.T) {
	const every = 5
	r := rotClient(every)
	first := map[uint16]int{}
	for i := 0; i < sportBandSpan*every+every*4; i++ {
		p := wireSport(r, r.cport())
		draw := i / every
		if j, seen := first[p]; seen {
			if j == draw {
				continue
			}
			if gap := draw - j; gap != sportBandSpan {
				t.Fatalf("port %d came back %d draws later, want exactly %d (%d packets)",
					p, gap, sportBandSpan, sportBandSpan*every)
			}
			continue
		}
		first[p] = draw
	}
	if len(first) != sportBandSpan {
		t.Fatalf("a full pass used %d ports, want %d", len(first), sportBandSpan)
	}
}
