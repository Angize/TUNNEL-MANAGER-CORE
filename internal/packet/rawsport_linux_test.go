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

func TestRolledSportIsInTheEphemeralRangeAndSpreads(t *testing.T) {
	const draws = 4000
	lowHalf, seen := 0, map[uint16]bool{}
	for i := 0; i < draws; i++ {
		p := rawRollSport()
		if p == 0 {
			t.Fatalf("draw %d failed", i)
		}
		if p < rawSportLo || p > rawSportHi {
			t.Fatalf("port %d outside the ephemeral range %d..%d — a port outside it is not what an "+
				"ordinary client's source port looks like, which is the whole point", p, rawSportLo, rawSportHi)
		}
		seen[p] = true
		if int(p) < rawSportLo+(rawSportHi-rawSportLo)/2 {
			lowHalf++
		}
	}

	if lowHalf < draws*2/5 || lowHalf > draws*3/5 {
		t.Errorf("%d/%d draws in the low half — the draw is skewed, so the port distribution is a tell",
			lowHalf, draws)
	}
	if len(seen) < draws/2 {
		t.Errorf("only %d distinct ports in %d draws — the rotation is not actually varying", len(seen), draws)
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

func TestTheAntiLeakRuleCoversTheWholeRotation(t *testing.T) {
	rng := strconv.Itoa(rawSportLo) + ":" + strconv.Itoa(rawSportHi)
	for _, isClient := range []bool{true, false} {
		got := rawDropMatches(testDst, "tcp", 0, 0, isClient, false, true)
		if len(got) != 1 {
			t.Fatalf("isClient=%v: %d rules, want exactly 1", isClient, len(got))
		}
		rule := strings.Join(got[0], " ")

		wantFlag := "--dport"
		if isClient {
			wantFlag = "--sport"
		}
		if !strings.Contains(rule, wantFlag+" "+rng) {
			t.Errorf("isClient=%v: rule %q does not carry %s %s — a rolled port outside it leaves the "+
				"kernel free to RST the peer", isClient, rule, wantFlag, rng)
		}
		if strings.Contains(rule, strconv.Itoa(rawClientPort)) {
			t.Errorf("isClient=%v: rule %q still pins the fixed client port", isClient, rule)
		}
	}

	for _, isClient := range []bool{true, false} {
		rule := strings.Join(rawDropMatches(testDst, "tcp", 0, 0, isClient, false, false)[0], " ")
		if strings.Contains(rule, ":") {
			t.Errorf("isClient=%v: fixed mode widened to a range: %q", isClient, rule)
		}
		if !strings.Contains(rule, strconv.Itoa(rawClientPort)) {
			t.Errorf("isClient=%v: fixed mode lost the client port: %q", isClient, rule)
		}
	}

	for _, random := range []bool{false, true} {
		for _, isClient := range []bool{true, false} {
			got := rawDropMatches(testDst, "udp", 0, 0, isClient, false, random)
			if len(got) != 1 || strings.Contains(strings.Join(got[0], " "), "port ") {
				t.Errorf("udp isClient=%v random=%v: %v", isClient, random, got)
			}
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
