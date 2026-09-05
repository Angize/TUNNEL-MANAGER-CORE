package packet

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// «رندومِ واکنشی» and «چرخشِ پورتِ مبدأ» are the same machine at two speeds.
//
// The rotation walks a PSK-keyed permutation, one step every N packets, and BOTH ends move: the
// client stamps rotPerm.at(w) as its source and the server stamps its own. The reactive-random mode
// walked nothing -- the client drew a uniform port on each failover and the server answered from
// raw_port for the life of the tunnel, so of the two source ports on the wire only one ever moved.
//
// They share one path now. portStep() is the only difference: the rotation counts packets, the
// reactive mode counts failovers. A failover on the client is any call to usePort -- the ladder's
// port rung and freshTuple both funnel through it -- and on the server it is the client's port
// changing, which is the same event seen from the other side and needs no signalling.
//
// The client's DESTINATION follows dportAt(w) in both modes, which is raw_port until the operator
// configures raw_dports. That is deliberate: a host firewall filters inbound on the destination
// (`ufw allow 443/udp`), and moving it without being asked is what CORE #455 had to revert.

func rawEnd(isClient, sportRandom bool, every int) *Raw {
	r := &Raw{profile: "udp", proto: protoUDP, isClient: isClient, port: 443, psk: "a-psk"}
	r.setSportMode(sportRandom, 0)
	r.setSportRotate(SportRotation{Every: every})
	return r
}

// what the end actually stamps, read through the call the send path uses
func onWire(r *Raw) (sport, dport uint16) {
	srv, cli := r.wirePorts(r.cport())
	return rawPorts(r.isClient, srv, cli)
}

func TestBothEndsMoveTheirSourceOnAFailover(t *testing.T) {
	cli, srv := rawEnd(true, true, 0), rawEnd(false, true, 0)
	srv.learnClientPort(cli.cport())

	cs0, cd0 := onWire(cli)
	ss0, sd0 := onWire(srv)
	if cs0 == 443 || ss0 == 443 {
		t.Fatalf("neither end may still be on the configured port: client %d, server %d", cs0, ss0)
	}
	if sd0 != cs0 {
		t.Fatalf("the server answers to %d while the client sends from %d", sd0, cs0)
	}
	if cd0 != 443 {
		t.Fatalf("the client is sending to %d, not the configured 443", cd0)
	}

	// a failover: the ladder's port rung IS this call
	if !cli.rollSourcePort() {
		t.Fatal("the port rung refused")
	}
	srv.learnClientPort(cli.cport())

	cs1, cd1 := onWire(cli)
	ss1, sd1 := onWire(srv)
	if cs1 == cs0 {
		t.Fatalf("the client did not move on the failover (still %d)", cs1)
	}
	if ss1 == ss0 {
		t.Errorf("the client moved %d -> %d and the server stayed on %d: only one of the two source "+
			"ports on the wire changed, which is the whole point", cs0, cs1, ss0)
	}
	if sd1 != cs1 {
		t.Errorf("the server answers to %d while the client now sends from %d", sd1, cs1)
	}
	if cd1 != 443 {
		t.Errorf("the client's destination moved to %d without raw_dports being asked for", cd1)
	}
}

// The two modes must be one machine. Same permutation, same shape on the wire -- only the clock
// differs, and that is the one thing portStep decides.
func TestTheTwoModesAreOneMachineAtTwoSpeeds(t *testing.T) {
	rot, rnd := rawEnd(false, false, 2), rawEnd(false, true, 0)
	if !rot.rotActive() || rnd.rotActive() {
		t.Fatal("setup: one must be the rotation and the other must not")
	}
	if !rot.portsMove() || !rnd.portsMove() {
		t.Fatal("both modes move their ports")
	}

	// the rotation steps on packets and nothing else
	rnd.learnClientPort(40000)
	before, _ := onWire(rot)
	for i := 0; i < 3; i++ {
		onWire(rot)
	}
	if after, _ := onWire(rot); after == before {
		t.Errorf("the rotation did not step in %d packets with every=2", 5)
	}

	// the reactive mode does not move on packets at all
	rndBefore, _ := onWire(rnd)
	for i := 0; i < 50; i++ {
		onWire(rnd)
		rnd.learnClientPort(40000)
	}
	if after, _ := onWire(rnd); after != rndBefore {
		t.Errorf("fifty packets from one client port moved the reactive source %d -> %d — that is a "+
			"rotation, and it has its own knob and its own budget", rndBefore, after)
	}
	rnd.learnClientPort(40001)
	if after, _ := onWire(rnd); after == rndBefore {
		t.Error("a genuinely new client port did not move the reactive server")
	}
}

// «ثابت» means fixed: the operator picked 51820 to look like WireGuard, or 500 to look like IKE.
// Nothing on either side may move, in either direction.
func TestTheFixedModeMovesNothing(t *testing.T) {
	cli, srv := rawEnd(true, false, 0), rawEnd(false, false, 0)
	if cli.portsMove() || srv.portsMove() {
		t.Fatal("the fixed mode must not move any port")
	}
	cli.cliPort.Store(51820)
	srv.learnClientPort(51820)

	cs, cd := onWire(cli)
	ss, sd := onWire(srv)
	if cs != 51820 || cd != 443 || ss != 443 || sd != 51820 {
		t.Fatalf("fixed wire = client %d->%d, server %d->%d; want 51820->443 and 443->51820",
			cs, cd, ss, sd)
	}

	srv.learnClientPort(51821)
	if got, _ := onWire(srv); got != 443 {
		t.Errorf("the client's port changed and the server left its fixed port for %d", got)
	}
	cli.rollSourcePort()
	if got, _ := onWire(cli); got != 51820 {
		t.Errorf("the ladder redrew a FIXED source port (%d) — that is the disguise the operator "+
			"chose the number for", got)
	}
}

// Both ends walk a permutation, so a port is not reused until the band is exhausted. A uniform draw
// can hand back the port that was just condemned.
func TestTheReactiveModeWalksInsteadOfDrawing(t *testing.T) {
	cli := rawEnd(true, true, 0)
	seen := map[uint16]int{}
	for i := 0; i < 300; i++ {
		p, _ := onWire(cli)
		seen[p]++
		cli.rollSourcePort()
	}
	for p, n := range seen {
		if n > 1 {
			t.Fatalf("port %d came back after %d failovers — the walk is repeating inside one cycle", p, n)
		}
	}
	if len(seen) != 300 {
		t.Fatalf("300 failovers produced %d distinct ports", len(seen))
	}
}

// The two ends must not walk the same sequence, or one end's port predicts the other's.
func TestTheTwoEndsWalkDifferentSequences(t *testing.T) {
	cli, srv := rawEnd(true, true, 0), rawEnd(false, true, 0)
	cli.rotIdx, srv.rotIdx = 7, 7
	srv.learnClientPort(40000)
	same := 0
	for i := 0; i < 64; i++ {
		if cli.rotPerm.at(uint64(i)) == srv.rotPerm.at(uint64(i)) {
			same++
		}
	}
	if same > 4 {
		t.Errorf("the two ends walk the same permutation (%d/64 identical) — the role is supposed to "+
			"key it", same)
	}
}

// The card reads `rot`, and the node only forwards it when a source port is in it. The reactive mode
// published NOTHING -- rotSnapshot returned the zero value unless the packet-counting rotation was on
// -- so the operator watching a reactive tunnel saw one number that never moved. Both modes publish,
// and `every` is what tells them apart: a packet count, or zero for "on every failover".
func TestBothModesPublishWhatIsOnTheWire(t *testing.T) {
	cli, srv := rawEnd(true, true, 0), rawEnd(false, true, 0)
	srv.learnClientPort(cli.cport())

	for i := 0; i < 3; i++ {
		cs, cd := onWire(cli)
		ss, _ := onWire(srv)
		rc, rs := cli.rotSnapshot(), srv.rotSnapshot()
		if rc.Sport != cs || rs.Sport != ss {
			t.Fatalf("failover %d: the card shows client %d / server %d, the wire carries %d / %d",
				i, rc.Sport, rs.Sport, cs, ss)
		}
		if rc.Dport != cd {
			t.Errorf("failover %d: the card shows a destination of %d, the wire carries %d", i, rc.Dport, cd)
		}
		if rs.Dport != cs {
			t.Errorf("failover %d: the server's card shows it answering %d, the client sends from %d",
				i, rs.Dport, cs)
		}
		if rc.Every != 0 || rs.Every != 0 {
			t.Errorf("failover %d: the reactive mode reported a packet budget (%d/%d) — the card would "+
				"render «every N packets» for a mode that counts failovers", i, rc.Every, rs.Every)
		}
		if rc.Drawn != uint64(i+1) || rs.Drawn != uint64(i+1) {
			t.Errorf("after %d failovers the card says %d/%d ports have been used",
				i, rc.Drawn, rs.Drawn)
		}
		if rc.Lo == 0 || rc.Hi <= rc.Lo {
			t.Errorf("the band is %d-%d", rc.Lo, rc.Hi)
		}
		cli.rollSourcePort()
		srv.learnClientPort(cli.cport())
	}

	if got := rawEnd(true, false, 0).rotSnapshot(); got != (rotStatus{}) {
		t.Errorf("a FIXED port was published as a moving one: %+v", got)
	}
	if rot := rawEnd(false, false, 4).rotSnapshot(); rot.Every != 4 {
		t.Errorf("the rotation stopped reporting its packet budget: %+v", rot)
	}
}

// Sampling the card may not spend a packet of the rotation's budget. The status file is rewritten on
// a timer; if reading it moved the odometer, a quiet tunnel would rotate because someone was looking.
func TestReadingTheCardDoesNotMoveThePort(t *testing.T) {
	r := rawEnd(false, false, 2)
	before, _ := onWire(r)
	for i := 0; i < 100; i++ {
		r.rotSnapshot()
	}
	if after, _ := onWire(r); after != before {
		t.Errorf("a hundred reads of the card moved the port %d -> %d", before, after)
	}
	if got := r.rotSnapshot().Sport; got != before {
		t.Errorf("the card shows %d and the wire carries %d", got, before)
	}
}

// The report has to reach the FILE, which is the only thing the node can read. rotSnapshot returning
// the right numbers proves nothing on its own: the tracker that publishes them refused to install
// itself unless a packet budget was set, so the reactive mode computed two correct ports every second
// and wrote a block of zeros. The panel then drew a card with nothing on it.
func TestTheStatusFileCarriesWhateverMoves(t *testing.T) {
	statusRot := func(t *testing.T, r *Raw) rotStatus {
		t.Helper()
		r.closeCh = make(chan struct{})
		defer close(r.closeCh)
		r.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
		r.st.trackRot(r.rotSnapshot, r.closeCh)
		b, err := os.ReadFile(r.st.path)
		if err != nil {
			t.Fatalf("nothing was written at all: %v", err)
		}
		var got struct {
			Rot rotStatus `json:"rot"`
		}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		return got.Rot
	}

	for _, tc := range []struct {
		name string
		r    *Raw
	}{
		{"the reactive client", rawEnd(true, true, 0)},
		{"the reactive server", rawEnd(false, true, 0)},
		{"the packet rotation", rawEnd(true, false, 4)},
	} {
		want := tc.r.rotSnapshot()
		got := statusRot(t, tc.r)
		if got.Sport == 0 {
			t.Errorf("%s: the status file carries no source port (%+v) — the node reads this file and "+
				"nothing else, so the card has nothing to draw", tc.name, got)
		}
		if got != want {
			t.Errorf("%s: the file says %+v, the carrier says %+v", tc.name, got, want)
		}
	}

	if got := statusRot(t, rawEnd(true, false, 0)); got != (rotStatus{}) {
		t.Errorf("a FIXED port was published as a moving one: %+v", got)
	}
}

// The path key is what the port-roll line reads to name the port the tunnel came back on, and what
// the node forwards as sport_live. It was built from the CONFIGURED ports rather than the forged ones,
// so a reactive server published 443 while stamping a band port on every packet. The wire, the key and
// the card have to be one answer; wirePortsNow is that answer, read without spending a packet.
func TestThePathKeySaysWhatTheWireCarries(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    *Raw
	}{
		{"the reactive client", rawEnd(true, true, 0)},
		{"the reactive server", rawEnd(false, true, 0)},
		{"the fixed client", rawEnd(true, false, 0)},
		{"the fixed server", rawEnd(false, false, 0)},
	} {
		r := tc.r
		r.soloPeer.Store(&net.IPAddr{IP: net.IPv4(10, 0, 0, 2)})
		if !r.isClient {
			r.learnClientPort(40000)
		}
		wantS, wantD := onWire(r)
		k, _ := r.livePath()
		if k.Sport != wantS || k.Dport != wantD {
			t.Errorf("%s: the path key says %d->%d, the wire carries %d->%d",
				tc.name, k.Sport, k.Dport, wantS, wantD)
		}
		if rot := r.rotSnapshot(); rot.Sport != 0 && (rot.Sport != wantS || rot.Dport != wantD) {
			t.Errorf("%s: the card says %d->%d, the wire carries %d->%d",
				tc.name, rot.Sport, rot.Dport, wantS, wantD)
		}
	}
}
