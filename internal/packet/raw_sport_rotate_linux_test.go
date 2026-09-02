//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

// The whole point of raw_sport_rotate is that a fresh forged source port every N packets mints a new
// 5-tuple, and the measured middlebox gives each tuple a small fixed packet budget. This proves the
// client's source port on the wire actually advances exactly every N data packets and never sooner,
// and that every drawn port sits in the wide ephemeral band a scan-resistant pool needs.
func TestSportRotateAdvancesEveryNPacketsOnTheClientWire(t *testing.T) {
	const every = 5
	r := &Raw{profile: "udp", isClient: true, port: rawServerPort}
	r.proto = protoUDP
	r.setSportRotate(every)
	if !r.rotActive() {
		t.Fatal("rotActive() is false after setSportRotate on a udp client")
	}

	seen := map[uint16]bool{}
	prev := r.cport()
	if prev < rotSportLo || prev >= rotSportLo+rotSportSpan {
		t.Fatalf("seed sport %d is outside [%d,%d)", prev, rotSportLo, rotSportLo+rotSportSpan)
	}
	changes := 0
	for i := 1; i <= every*40; i++ {
		r.rollTxSport()
		cur := r.cport()
		if cur < rotSportLo || cur >= rotSportLo+rotSportSpan {
			t.Fatalf("packet %d: sport %d outside [%d,%d)", i, cur, rotSportLo, rotSportLo+rotSportSpan)
		}
		if i%every == 0 {
			if cur == prev {
				t.Fatalf("packet %d (a multiple of %d): sport did not advance from %d", i, every, prev)
			}
			changes++
			prev = cur
			seen[cur] = true
		} else if cur != prev {
			t.Fatalf("packet %d: sport changed to %d between rotation points (want stable %d)", i, cur, prev)
		}
	}
	if changes != 40 {
		t.Fatalf("expected 40 rotations over %d packets, got %d", every*40, changes)
	}

	// the drawn port is what actually lands on the wire as the client source
	pkt := rawEncap("udp", []byte("data"), testSrc, testDst, true, 0, r.srvPort(), r.cport(),
		1, 0, 0, 0, 0, tcpPshAck)
	if got := binary.BigEndian.Uint16(pkt[0:2]); got != r.cport() {
		t.Fatalf("wire source port %d != current rotating cport %d", got, r.cport())
	}
	if dp := binary.BigEndian.Uint16(pkt[2:4]); dp != rawServerPort {
		t.Fatalf("client dest port %d changed; only the source must rotate (want %d)", dp, rawServerPort)
	}
}

// The download leg is capped too, so the server must rotate ITS OWN source (the srv coordinate), while
// the port it sends TO stays whatever the client last used. cport() on the server is that learned client
// port and must NOT be hijacked by rotation.
func TestSportRotateRotatesTheServerSourceNotItsReplyTarget(t *testing.T) {
	const every = 3
	r := &Raw{profile: "udp", isClient: false, port: rawServerPort}
	r.proto = protoUDP
	r.setSportRotate(every)
	r.cliPort.Store(41000) // the client port the server learned

	prev := r.srvPort()
	for i := 1; i <= every*10; i++ {
		r.rollTxSport()
		if i%every == 0 && r.srvPort() == prev {
			t.Fatalf("packet %d: server source port did not advance from %d", i, prev)
		}
		if i%every == 0 {
			prev = r.srvPort()
		}
		if r.cport() != 41000 {
			t.Fatalf("packet %d: server reply target moved to %d; it must stay the learned client port 41000", i, r.cport())
		}
	}

	pkt := rawEncap("udp", []byte("data"), testSrc, testDst, false, 0, r.srvPort(), r.cport(),
		1, 0, 0, 0, 0, tcpPshAck)
	if sp := binary.BigEndian.Uint16(pkt[0:2]); sp != r.srvPort() {
		t.Fatalf("server wire source %d != rotating srvPort %d", sp, r.srvPort())
	}
	if dp := binary.BigEndian.Uint16(pkt[2:4]); dp != 41000 {
		t.Fatalf("server wire dest %d != learned client port 41000", dp)
	}
}

// Rotation is udp-only and off unless asked. A tcp profile (coherent seq would break under rotation) and
// the unset knob must both leave the carrier on its normal single source port.
func TestSportRotateIsUDPOnlyAndOffByDefault(t *testing.T) {
	rt := &Raw{profile: "tcp", isClient: true, port: rawServerPort}
	rt.proto = protoTCP
	rt.setSportRotate(5)
	if rt.rotActive() || rt.sportEvery != 0 {
		t.Fatal("rotation must be a no-op on the tcp profile")
	}
	base := rt.cport()
	for i := 0; i < 20; i++ {
		rt.rollTxSport()
	}
	if rt.cport() != base {
		t.Fatalf("tcp source port moved from %d to %d without rotation", base, rt.cport())
	}

	ru := &Raw{profile: "udp", isClient: true, port: rawServerPort}
	ru.proto = protoUDP
	if ru.rotActive() {
		t.Fatal("rotActive() is true with the knob unset")
	}
}

// When rotation is on, the ephemeral source port is not a stable attribute of the path, so it must be
// kept out of the status path key -- otherwise the once-a-second sampler sees a new key every tick and
// churns the epoch and the status file forever.
func TestSportRotateStaysOutOfThePathKey(t *testing.T) {
	r := &Raw{profile: "udp", isClient: true, port: rawServerPort}
	r.proto = protoUDP
	r.setSportRotate(4)
	r.localIP.Store(&net.IPAddr{IP: testSrc})
	r.peer.Store(&net.IPAddr{IP: testDst})
	k, _ := r.livePath()
	if k.Sport != 0 || k.Dport != 0 {
		t.Fatalf("rotating source leaked into the path key: %d->%d (want 0->0)", k.Sport, k.Dport)
	}
}
