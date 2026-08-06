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

// The client's forged source port may rotate for the life of the tunnel. Four things have to hold, and
// three of them are only visible on a real code path rather than in rawPorts alone:
//
//  1. a rolled port is inside Linux's ephemeral range, and the draw is not skewed to one end of it;
//  2. the port the CLIENT stamps as source is the one the SERVER stamps as destination;
//  3. the server adopts it only from an AUTHENTICATED frame -- the ports are attacker-controlled bytes;
//  4. the anti-leak rule covers every port the rotation can draw, with ONE rule that outlives them all.

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
	// A modulo over a 16-bit draw would bias the low ports; a histogram skewed to one end is itself a
	// tell. Allow generous slack — this is a bias check, not a randomness test.
	if lowHalf < draws*2/5 || lowHalf > draws*3/5 {
		t.Errorf("%d/%d draws in the low half — the draw is skewed, so the port distribution is a tell",
			lowHalf, draws)
	}
	if len(seen) < draws/2 {
		t.Errorf("only %d distinct ports in %d draws — the rotation is not actually varying", len(seen), draws)
	}
}

// setSportMode must refuse to arm on a profile with no ports, whatever it is told: there is nothing to
// roll, and arming would widen the anti-leak rule to a range the rule has no use for.
func TestSportModeOnlyArmsWhereThereArePorts(t *testing.T) {
	for _, profile := range RawProfileNames() {
		r := &Raw{profile: profile, isClient: true}
		r.setSportMode(true)
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

// The pair must REVERSE across the two ends. This is the property that makes the flow read as one
// conversation to a middlebox, and it is what breaks if either end forgets to carry the client's port.
func TestTheServerStampsBackTheClientsRolledPort(t *testing.T) {
	cli := &Raw{profile: "tcp", isClient: true}
	cli.setSportMode(true)
	rolled := cli.cport()
	if rolled == 0 {
		t.Fatal("client did not draw an opening port")
	}
	srv := &Raw{profile: "tcp", isClient: false}
	srv.setSportMode(true)
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

// A CLIENT must never adopt the peer's source port: on the client the field is its OWN rolling port,
// and the frames it receives carry the server's :443. Adopting it would make the client stamp 443->443.
func TestTheClientNeverAdoptsThePeersPort(t *testing.T) {
	cli := &Raw{profile: "tcp", isClient: true}
	cli.setSportMode(true)
	mine := cli.cport()
	cli.learnClientPort(443)
	if cli.cport() != mine {
		t.Errorf("client adopted the peer's port %d over its own %d — it would then stamp 443->443, "+
			"which is not a conversation", cli.cport(), mine)
	}
}

// A profile that forges no ports has no port to learn either: rawDecap reports 0 for it, and storing a 0
// would be harmless, but storing anything from a headerless carrier means reading bytes that are payload.
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

// rawDecap is where the port is read, and it must read it from the SAME bytes the header actually
// occupies -- including the case where the read came with an IPv4 header still attached.
func TestDecapReadsTheSourcePortTheEncapWrote(t *testing.T) {
	const cport, srv = 45678, 8443
	for _, profile := range []string{"tcp", "udp"} {
		proto := rawProfiles[profile]
		l4 := rawEncap(profile, []byte("payload"), testSrc, testDst, true, 0, srv, cport, 7, 9, 0)
		for _, v := range []struct {
			name string
			pkt  []byte
		}{
			{"bare L4", l4},
			{"with an IPv4 header", prependIP4(testSrc, testDst, proto, l4)},
		} {
			body, sport, ok := rawDecap(profile, proto, v.pkt)
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
	// ...and reports 0 for every profile that forges no ports, so nothing is learned from payload bytes.
	for _, profile := range RawProfileNames() {
		if RawProfileHasPorts(profile) {
			continue
		}
		proto := rawProfiles[profile]
		pkt := rawEncap(profile, []byte("payload"), testSrc, testDst, true, 0, 0, 0, 7, 9, 0)
		if _, sport, ok := rawDecap(profile, proto, pkt); ok && sport != 0 {
			t.Errorf("%s: reported source port %d from a header that has none", profile, sport)
		}
	}
}

// The rule must cover EVERY port the rotation can draw, and it must be ONE rule: re-installing it on
// each roll would leave a window with no rule at all, in which the kernel answers the peer -- the exact
// leak the rule exists to stop.
func TestTheAntiLeakRuleCoversTheWholeRotation(t *testing.T) {
	rng := strconv.Itoa(rawSportLo) + ":" + strconv.Itoa(rawSportHi)
	for _, isClient := range []bool{true, false} {
		got := rawDropMatches(testDst, "tcp", 0, isClient, false, true)
		if len(got) != 1 {
			t.Fatalf("isClient=%v: %d rules, want exactly 1", isClient, len(got))
		}
		rule := strings.Join(got[0], " ")
		// The CLIENT's port is our SOURCE on the client and our DESTINATION on the server.
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
	// Fixed mode keeps the exact match: a range there would swallow our own RSTs to that peer from any
	// ephemeral port, which is broader than this rule has any business being.
	for _, isClient := range []bool{true, false} {
		rule := strings.Join(rawDropMatches(testDst, "tcp", 0, isClient, false, false)[0], " ")
		if strings.Contains(rule, ":") {
			t.Errorf("isClient=%v: fixed mode widened to a range: %q", isClient, rule)
		}
		if !strings.Contains(rule, strconv.Itoa(rawClientPort)) {
			t.Errorf("isClient=%v: fixed mode lost the client port: %q", isClient, rule)
		}
	}
	// udp's rule is ICMP port-unreachable and carries no port at all, so rotation cannot affect it.
	for _, random := range []bool{false, true} {
		for _, isClient := range []bool{true, false} {
			got := rawDropMatches(testDst, "udp", 0, isClient, false, random)
			if len(got) != 1 || strings.Contains(strings.Join(got[0], " "), "port ") {
				t.Errorf("udp isClient=%v random=%v: %v", isClient, random, got)
			}
		}
	}
}

// The handshake RESP is the FIRST thing a server sends, and it goes out BEFORE any data frame has
// authenticated. If the server has not learned the client's rolled port by then it stamps the fixed
// default, and on a path with a stateful box that reply is an unsolicited flow that gets dropped -- the
// handshake never completes and the tunnel never comes up at all.
//
// A netns lab cannot see this: there is no stateful box between two namespaces, so the mis-addressed
// reply arrives anyway and the tunnel looks healthy. This drives the real tryHandshake instead.
func TestTheHandshakeReplyGoesToTheRolledPort(t *testing.T) {
	const psk = "tVYafNLrHaId1AaEM80YebyPzXThOEr2adA27E6mbRc="
	const rolled = 54321

	srv := &Raw{profile: "tcp", isClient: false, psk: psk, cipher: "chacha20-poly1305"}
	srv.setSportMode(true)
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
	// The reply's forged header must be addressed to the port the init came from.
	dport := binary.BigEndian.Uint16(cap.sent[0][2:4])
	if dport != rolled {
		t.Errorf("handshake reply is stamped for port %d, but the client sent from %d — a stateful box "+
			"drops that as an unsolicited flow and the tunnel never comes up", dport, rolled)
	}
	// A REPLAYED init served from the cache must NOT be able to steer where we send: it re-serves a
	// cached response without proving anything new.
	srv.tryHandshake(crypto.InitMsg(psk, ci), &net.IPAddr{IP: testSrc}, 40000)
	if srv.cport() != rolled {
		t.Errorf("a replayed init moved the learned port to %d", srv.cport())
	}
}

// capturingLink is a directLink that records what would go on the wire instead of opening a socket.
// The interface is the seam, so no production hook is needed to see the bytes a handshake sends.
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
