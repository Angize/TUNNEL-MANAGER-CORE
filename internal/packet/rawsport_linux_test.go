//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

// The band itself: what the draw is allowed to return, and what must never come out of it. The 200-port
// table of well-known service ports this replaced put a SERVER port on a CLIENT packet, which is the
// one thing about the forgery that looked wrong to anyone reading a capture. A band is only an
// improvement if it also keeps clear of the ports measured dead on the path, so that is asserted here
// rather than left to whoever next edits the two constants.
func TestTheSourcePortBandIsWellFormed(t *testing.T) {
	lo, hi := int(sportBandLo), int(sportBandLo)+int(sportBandSpan)-1
	if lo < 1024 {
		t.Errorf("the band starts at %d, inside the privileged ports", lo)
	}
	if hi > 65535 {
		t.Errorf("the band ends at %d, past the last UDP port", hi)
	}

	// The width of the band IS the throughput ceiling, and that is the only reason to care how wide it
	// is. A port may not come back before the middlebox has forgotten the flow, so the fastest the
	// carrier may go is span*every/rotForgetSecs packets a second. Measured on the burned path
	// 2026-09-03, same tunnel and same minute: a 10000-port band gave 9.7 Mbit up, a 50000-port band
	// gave 209. Narrowing the band is therefore not a free "looks tidier" change; it is a throughput
	// cut, and this asserts the floor so the next narrowing has to argue with a number.
	pps := int(sportBandSpan) * 4 / rotForgetSecs
	if mbit := pps * 1400 * 8 / 1000000; mbit < 100 {
		t.Errorf("the band allows only %d packets/s at every=4 (%d Mbit at 1400B) before a port comes "+
			"back inside the ~%ds forget window", pps, mbit, rotForgetSecs)
	}

	// The ports a filter reaches for first, and the four MEASURED dead IR->DE (3 rounds each,
	// 2026-08-28). A draw that lands on one of these is a rung spent on nothing. Only 51820 is inside
	// a band this wide -- one draw in 50000, which is not worth carving a hole in a contiguous
	// permutation for, and the walk visits it once per full pass at most.
	inside := 0
	for _, bad := range []int{500, 1194, 1701, 1723, 4500, 51820, 9050, 9051, 9150,
		23, 25, 465, 3389} {
		if bad >= lo && bad <= hi {
			inside++
		}
	}
	if inside > 1 {
		t.Errorf("%d of the known-bad ports are inside [%d,%d]; at most one is tolerable", inside, lo, hi)
	}
}

func TestTheDrawStaysInTheBandAndSpreads(t *testing.T) {
	const draws = 4000
	lo, hi := uint32(sportBandLo), uint32(sportBandLo+sportBandSpan-1)
	seen := map[uint16]bool{}
	for i := 0; i < draws; i++ {
		p := uint32(rawRollSport())
		if p < lo || p > hi {
			t.Fatalf("draw %d returned %d, outside [%d,%d] — the anti-leak rule and the measured "+
				"block rates are both about the band", i, p, lo, hi)
		}
		seen[uint16(p)] = true
	}
	// 4000 draws over 10000 ports collide by the birthday bound; anything near 4000 distinct says the
	// draw is spreading, anything small says it is stuck on a few values.
	if len(seen) < draws*3/4 {
		t.Errorf("%d distinct ports in %d draws — the draw is not spreading over the band",
			len(seen), draws)
	}
}

func TestSportModeOnlyArmsWhereThereArePorts(t *testing.T) {
	for _, profile := range RawProfileNames() {
		r := &Raw{profile: profile, isClient: true}
		r.setSportMode(true, 0)
		want := RawProfileHasPorts(profile)
		if r.sportRandom != want {
			t.Errorf("%s: sportRandom=%v want %v", profile, r.sportRandom, want)
		}
		if want && r.cport() == 0 {
			t.Errorf("%s: armed but drew no opening port, so the tunnel would open on the fixed default "+
				"and only start moving one interval later", profile)
		}
		if !want && r.cport() != 0 {
			t.Errorf("%s: drew a port for a profile that forges none", profile)
		}
	}
}

func TestTheServerStampsBackTheClientsRolledPort(t *testing.T) {
	cli := &Raw{profile: "tcp", isClient: true}
	cli.setSportMode(true, 0)
	rolled := cli.cport()
	if rolled == 0 {
		t.Fatal("client did not draw an opening port")
	}
	srv := &Raw{profile: "tcp", isClient: false}
	srv.setSportMode(true, 0)
	if srv.cport() != 0 {
		t.Fatal("the server must not invent a client port; it learns one")
	}
	srv.learnClientPort(rolled)

	csp, cdp := rawPorts(true, 443, cli.cport())
	ssp, sdp := rawPorts(false, 443, srv.cport())
	if csp != rolled || cdp != 443 {
		t.Errorf("client stamps %d->%d, want %d->443", csp, cdp, rolled)
	}
	if ssp != 443 || sdp != rolled {
		t.Errorf("server stamps %d->%d, want 443->%d — a reply aimed at a port the client never sent "+
			"from reaches a stateful box as an unsolicited flow and is dropped", ssp, sdp, rolled)
	}
}

func TestTheClientNeverAdoptsThePeersPort(t *testing.T) {
	cli := &Raw{profile: "tcp", isClient: true}
	cli.setSportMode(true, 0)
	mine := cli.cport()
	cli.learnClientPort(443)
	if cli.cport() != mine {
		t.Errorf("client adopted the peer's port %d over its own %d — it would then stamp 443->443, "+
			"which is not a conversation", cli.cport(), mine)
	}
}

func TestNoPortIsLearnedWhereThereIsNoHeader(t *testing.T) {
	for _, profile := range RawProfileNames() {
		if RawProfileHasPorts(profile) {
			continue
		}
		srv := &Raw{profile: profile, isClient: false}
		srv.learnClientPort(40000)
		if srv.cport() != 0 {
			t.Errorf("%s: learned a port from a carrier that forges none", profile)
		}
	}
}

func TestDecapReadsTheSourcePortTheEncapWrote(t *testing.T) {
	const cport, srv = 45678, 8443
	for _, profile := range []string{"tcp", "udp"} {
		proto := rawProfiles[profile]
		l4 := rawEncap(profile, []byte("payload"), testSrc, testDst, true, 0, srv, cport, 7, 9, 0, 0, 0, tcpPshAck)
		for _, v := range []struct {
			name string
			pkt  []byte
		}{
			{"bare L4", l4},
			{"with an IPv4 header", prependIP4(testSrc, testDst, proto, l4)},
		} {
			body, sport, _, ok := rawDecap(profile, proto, v.pkt)
			if !ok {
				t.Fatalf("%s/%s: decap failed", profile, v.name)
			}
			if string(body) != "payload" {
				t.Errorf("%s/%s: body=%q", profile, v.name, body)
			}
			if sport != cport {
				t.Errorf("%s/%s: sport=%d want %d", profile, v.name, sport, cport)
			}
		}
	}

	for _, profile := range RawProfileNames() {
		if RawProfileHasPorts(profile) {
			continue
		}
		proto := rawProfiles[profile]
		pkt := rawEncap(profile, []byte("payload"), testSrc, testDst, true, 0, 0, 0, 7, 9, 0, 0, 0, tcpPshAck)
		if _, sport, _, ok := rawDecap(profile, proto, pkt); ok && sport != 0 {
			t.Errorf("%s: reported source port %d from a header that has none", profile, sport)
		}
	}
}

// The rule has to cover EVERY port the draw can return, and the draw can return any of 200. So it
// names the one end that never moves -- the server port -- and says nothing about the client's, which
// is what makes it hold across a redraw instead of going stale on it.
func TestTheAntiLeakRuleCoversEveryPortTheDrawCanReturn(t *testing.T) {
	for _, isClient := range []bool{true, false} {
		got := rawDropMatches(testDst, "tcp", 0, isClient, false)
		if len(got) != 1 {
			t.Fatalf("isClient=%v: %d rules, want exactly 1", isClient, len(got))
		}
		rule := strings.Join(got[0], " ")

		wantFlag := "--dport"
		if !isClient {
			wantFlag = "--sport"
		}
		if !strings.Contains(rule, wantFlag+" "+strconv.Itoa(rawServerPort)) {
			t.Errorf("isClient=%v: rule %q does not scope by %s %d", isClient, rule, wantFlag, rawServerPort)
		}
		for _, flag := range []string{"--sport", "--dport"} {
			if flag != wantFlag && strings.Contains(rule, flag) {
				t.Errorf("isClient=%v: rule %q pins the CLIENT port; the next draw moves it and the "+
					"kernel is then free to RST the peer", isClient, rule)
			}
		}
		for i := 0; i < 64; i++ {
			p := int(rawRollSport())
			if strings.Contains(rule, " "+strconv.Itoa(p)+" ") && p != rawServerPort {
				t.Errorf("isClient=%v: rule %q names band port %d, so it does not cover the others",
					isClient, rule, p)
			}
		}
	}

	for _, isClient := range []bool{true, false} {
		got := rawDropMatches(testDst, "udp", 0, isClient, false)
		if len(got) != 1 || strings.Contains(strings.Join(got[0], " "), "port ") {
			t.Errorf("udp isClient=%v: %v", isClient, got)
		}
	}
}

func TestTheHandshakeReplyGoesToTheRolledPort(t *testing.T) {
	const psk = "tVYafNLrHaId1AaEM80YebyPzXThOEr2adA27E6mbRc="
	const rolled = 54321

	srv := &Raw{profile: "tcp", isClient: false, psk: psk, cipher: "chacha20-poly1305"}
	srv.setSportMode(true, 0)
	cap := &capturingLink{r: srv}
	srv.link = cap
	srv.peer.Store(&net.IPAddr{IP: testSrc})
	srv.localIP.Store(&net.IPAddr{IP: testDst})

	ci, err := crypto.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	srv.tryHandshake(crypto.InitMsg(psk, ci), &net.IPAddr{IP: testSrc}, rolled)

	if srv.cport() != rolled {
		t.Fatalf("server did not learn the client's port from the authenticated init: got %d want %d",
			srv.cport(), rolled)
	}
	if len(cap.sent) != 1 {
		t.Fatalf("expected one handshake reply, got %d", len(cap.sent))
	}

	dport := binary.BigEndian.Uint16(cap.sent[0][2:4])
	if dport != rolled {
		t.Errorf("handshake reply is stamped for port %d, but the client sent from %d — a stateful box "+
			"drops that as an unsolicited flow and the tunnel never comes up", dport, rolled)
	}

	srv.tryHandshake(crypto.InitMsg(psk, ci), &net.IPAddr{IP: testSrc}, 40000)
	if srv.cport() != rolled {
		t.Errorf("a replayed init moved the learned port to %d", srv.cport())
	}

	if len(cap.sent) != 2 {
		t.Fatalf("expected the cached reply to be sent too, got %d frame(s)", len(cap.sent))
	}
	if dport := binary.BigEndian.Uint16(cap.sent[1][2:4]); dport != 40000 {
		t.Errorf("the cached handshake reply is stamped for port %d, but this init came from 40000 — "+
			"a client that rolled its port can never be answered, so the tunnel never recovers", dport)
	}
}

func TestAHandshakeAnswerGoesToTheSenderNotTheDataPath(t *testing.T) {
	const psk = "tVYafNLrHaId1AaEM80YebyPzXThOEr2adA27E6mbRc="

	for _, profile := range []string{"udp", "tcp"} {
		srv := &Raw{profile: profile, isClient: false, psk: psk, cipher: "chacha20-poly1305", port: 51820}
		srv.setSportMode(true, 0)
		cap := &capturingLink{r: srv}
		srv.link = cap
		srv.peer.Store(&net.IPAddr{IP: testSrc})
		srv.localIP.Store(&net.IPAddr{IP: testDst})

		ci, err := crypto.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		init := crypto.InitMsg(psk, ci)

		ports := []uint16{33016, 46649, 52384}
		for _, p := range ports {
			srv.tryHandshake(init, &net.IPAddr{IP: testSrc}, p)
		}
		if len(cap.sent) != len(ports) {
			t.Fatalf("%s: %d replies for %d inits", profile, len(cap.sent), len(ports))
		}
		for i, want := range ports {
			if got := binary.BigEndian.Uint16(cap.sent[i][2:4]); got != want {
				t.Errorf("%s: reply %d went to port %d, want %d", profile, i+1, got, want)
			}
		}

		if srv.cport() != ports[0] {
			t.Errorf("%s: a retransmit steered the data path to %d, want %d", profile, srv.cport(), ports[0])
		}
	}
}

type capturingLink struct {
	r    *Raw
	sent [][]byte
}

func (c *capturingLink) send(pkt []byte, _ *net.IPAddr) {
	c.sent = append(c.sent, append([]byte(nil), pkt...))
}
func (c *capturingLink) recvLoop() error                     { return nil }
func (c *capturingLink) replyTo(src *net.IPAddr) *net.IPAddr { return src }
func (c *capturingLink) filterSrc() bool                     { return true }
func (c *capturingLink) pinsSource() bool                    { return false }
func (c *capturingLink) fakeFD() int                         { return -1 }
func (c *capturingLink) header(realSrc net.IP, to *net.IPAddr) (net.IP, net.IP) {
	return realSrc, to.IP
}
func (c *capturingLink) close() {}
