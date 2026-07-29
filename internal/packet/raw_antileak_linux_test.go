package packet

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// A tiny netfilter stand-in.
//
// The whole point of the raw anti-leak is that the rule must hit the KERNEL's answer and miss OUR
// OWN carrier frames. Those two are indistinguishable at a glance on the icmp profile — both are
// "ICMP echo reply to the peer" — which is exactly how the first design of this fix would have
// black-holed the download. So rather than restating the expected argv (a list that goes stale the
// moment someone edits a rule), these tests EVALUATE each rule against real packets: the kernel's
// measured answer, and the bytes rawEncap actually produces.
// ---------------------------------------------------------------------------

// nfPacket is an outgoing IPv4 packet as netfilter's OUTPUT chain sees it.
type nfPacket struct {
	what     string // for failure messages
	proto    int
	icmpType int // -1 when not ICMP
	sport    int // 0 when the protocol has no ports
	dport    int
	rst      bool
	mark     uint32
}

var icmpTypeByName = map[string]int{
	"echo-reply": 0,
	// port-unreachable is a sub-name of type 3; the type is all the matcher needs, since our
	// carrier never emits an ICMP type 3 at all.
	"port-unreachable":        3,
	"destination-unreachable": 3,
	"echo-request":            8,
}

// ruleMatches evaluates one rawDropMatches entry against p. It FAILS the test on any match
// argument it does not understand, so a new kind of match has to teach this matcher about itself
// instead of silently passing.
func ruleMatches(t *testing.T, m []string, p nfPacket) bool {
	t.Helper()
	hit := true
	for i := 0; i < len(m); i++ {
		switch m[i] {
		case "-d": // scoped to the peer; every rule here carries it, so it is not a discriminator
			i++
		case "-p":
			i++
			want := map[string]int{"icmp": protoICMP, "udp": protoUDP, "tcp": protoTCP}[m[i]]
			if want == 0 {
				t.Fatalf("rule %v: matcher does not know protocol %q", m, m[i])
			}
			hit = hit && p.proto == want
		case "--icmp-type":
			i++
			want, ok := icmpTypeByName[m[i]]
			if !ok {
				t.Fatalf("rule %v: matcher does not know icmp type %q", m, m[i])
			}
			hit = hit && p.icmpType == want
		case "--sport":
			i++
			hit = hit && m[i] == strconv.Itoa(p.sport)
		case "--dport":
			i++
			hit = hit && m[i] == strconv.Itoa(p.dport)
		case "--tcp-flags":
			if i+2 >= len(m) || m[i+1] != "RST" || m[i+2] != "RST" {
				t.Fatalf("rule %v: matcher only understands --tcp-flags RST RST", m)
			}
			i += 2
			hit = hit && p.rst
		case "-m":
			i++
			if m[i] != "mark" {
				t.Fatalf("rule %v: matcher does not know match extension %q", m, m[i])
			}
		case "!":
			if i+2 >= len(m) || m[i+1] != "--mark" {
				t.Fatalf("rule %v: matcher only understands a negated --mark", m)
			}
			want, err := strconv.ParseUint(m[i+2], 0, 32)
			if err != nil {
				t.Fatalf("rule %v: unparseable mark %q: %v", m, m[i+2], err)
			}
			i += 2
			hit = hit && uint64(p.mark) != want
		default:
			t.Fatalf("rule %v: matcher does not know argument %q", m, m[i])
		}
	}
	return hit
}

// ourFrame builds the packet THIS end puts on the wire for profile/role, straight out of rawEncap,
// so the test reads the real encapsulation instead of a copy of it.
func ourFrame(profile string, isClient, marked bool) nfPacket {
	body := []byte("sealed-frame-bytes-0123456789abcdef")
	src, dst := net.IPv4(10, 9, 0, 1), net.IPv4(10, 9, 0, 2)
	pkt := rawEncap(profile, body, src, dst, isClient, 0xBEEF, 7, 9, 0x11223344)
	role := "server"
	if isClient {
		role = "client"
	}
	p := nfPacket{what: "our own raw/" + profile + " " + role + " frame", proto: rawProfiles[profile], icmpType: -1}
	if marked {
		p.mark = rawSendMark
	}
	switch p.proto {
	case protoICMP:
		p.icmpType = int(pkt[0])
	case protoUDP:
		p.sport = int(binary.BigEndian.Uint16(pkt[0:2]))
		p.dport = int(binary.BigEndian.Uint16(pkt[2:4]))
	case protoTCP:
		p.sport = int(binary.BigEndian.Uint16(pkt[0:2]))
		p.dport = int(binary.BigEndian.Uint16(pkt[2:4]))
		p.rst = pkt[13]&0x04 != 0
	}
	return p
}

// kernelAnswers is the MEASURED behaviour this fix exists to suppress: 10 crafted carrier packets
// per profile in a veth namespace pair, both directions observed with tcpdump.
//
//	icmp  the receiving kernel mirrored all 10 echo requests back, carrying our own ciphertext
//	      (length 72). The other direction is silent: our echo replies provoke nothing.
//	udp   both kernels answered with "udp port 443 unreachable", which QUOTES the packet.
//	tcp   both kernels answered with a RST from 443 to 51820.
//
// The kernel's answer carries no mark of ours (mark 0) — that is the whole basis of the icmp rule.
var kernelAnswers = map[string][]nfPacket{
	"icmp": {{what: "the kernel mirroring our ciphertext back (icmp echo reply)", proto: protoICMP, icmpType: 0}},
	"udp":  {{what: "the kernel's icmp port-unreachable quoting our datagram", proto: protoICMP, icmpType: 3}},
	"tcp":  {{what: "the kernel's RST", proto: protoTCP, icmpType: -1, sport: rawDstPort, dport: rawSrcPort, rst: true}},
}

var leakPeer = net.IPv4(203, 0, 113, 7)

// TestRawAntiLeakNeverMatchesOurOwnFrames is the guard that the first design of this fix failed.
// On the icmp profile the server's DOWNSTREAM frames are echo replies to the peer — the same shape
// as the kernel's mirror — so a plain "--icmp-type echo-reply -d peer -j DROP" drops the tunnel's
// whole download direction. Measured before the fix: 10 of the server's 10 own frames dropped, and
// every send returned EPERM. No rule this carrier installs may match anything it sends.
func TestRawAntiLeakNeverMatchesOurOwnFrames(t *testing.T) {
	for profile := range rawProfiles {
		for _, isClient := range []bool{true, false} {
			for _, marked := range []bool{true, false} {
				ours := ourFrame(profile, isClient, marked)
				for _, m := range rawDropMatches(leakPeer, profile, isClient, marked) {
					if ruleMatches(t, m, ours) {
						t.Fatalf("raw/%s (isClient=%v marked=%v): the anti-leak rule %v matches %s — this silently black-holes the tunnel",
							profile, isClient, marked, m, ours.what)
					}
				}
			}
		}
	}
}

// TestRawAntiLeakSuppressesEveryMeasuredKernelAnswer is the other half: every answer the kernel was
// MEASURED to send must be matched by a rule we install, on the side that sends it.
func TestRawAntiLeakSuppressesEveryMeasuredKernelAnswer(t *testing.T) {
	for profile, answers := range kernelAnswers {
		for _, ans := range answers {
			// icmp is the one asymmetric case: only the server receives echo requests, so only the
			// server's kernel answers, and only the server installs the rule.
			roles := []bool{true, false}
			if profile == "icmp" {
				roles = []bool{false}
			}
			for _, isClient := range roles {
				covered := false
				for _, m := range rawDropMatches(leakPeer, profile, isClient, true) {
					if ruleMatches(t, m, ans) {
						covered = true
					}
				}
				if !covered {
					t.Fatalf("raw/%s (isClient=%v): nothing suppresses %s — the peer sees it on every carrier packet",
						profile, isClient, ans.what)
				}
			}
		}
	}
}

// TestRawIcmpRuleIsSkippedWithoutTheMark pins the fail-safe. SO_MARK needs CAP_NET_ADMIN while a
// raw socket only needs CAP_NET_RAW, so a container can have one and not the other. Without the
// mark the rule cannot exempt our own downstream frames, and installing it anyway would take the
// tunnel dark. Leaking is bad; going dark is worse.
func TestRawIcmpRuleIsSkippedWithoutTheMark(t *testing.T) {
	if got := rawDropMatches(leakPeer, "icmp", false, false); len(got) != 0 {
		t.Fatalf("an icmp server with no SO_MARK still installed %v — that drops its own downstream frames", got)
	}
	if got := rawDropMatches(leakPeer, "icmp", false, true); len(got) != 1 {
		t.Fatalf("an icmp server WITH the mark should install exactly one rule, got %v", got)
	}
	// The client sends echo requests, which no kernel answers — it must install nothing either way.
	for _, marked := range []bool{true, false} {
		if got := rawDropMatches(leakPeer, "icmp", true, marked); len(got) != 0 {
			t.Fatalf("an icmp CLIENT (marked=%v) installed %v; nothing answers its echo replies", marked, got)
		}
	}
}

// TestRawAntiLeakLeavesQuietProfilesAlone: bip/ipip/gre/esp have no kernel handler that answers,
// so they must not pay for an iptables rule (nor risk one that drops their traffic).
func TestRawAntiLeakLeavesQuietProfilesAlone(t *testing.T) {
	for _, profile := range []string{"bip", "ipip", "gre", "esp"} {
		for _, isClient := range []bool{true, false} {
			if got := rawDropMatches(leakPeer, profile, isClient, true); len(got) != 0 {
				t.Fatalf("raw/%s installed %v; no kernel handler answers that protocol", profile, got)
			}
		}
	}
}

// TestRawRotationPreScopesAntiLeak drives the REAL destination-rotation and pin entry points and
// asserts the rule is re-scoped there — on the caller's own goroutine — rather than being left for
// the receive loop to discover. It also pins the install-before-remove order: the endpoint we just
// left stays admitted for the frames still in flight, so a gap with no rule at all is exactly when
// the kernel leaks. Same contract the flux carrier already holds.
func TestRawRotationPreScopesAntiLeak(t *testing.T) {
	rec := &leakRecorder{}
	pool := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, false, 0, "")
	r := &Raw{profile: "udp", isClient: true, pp: pool, closeCh: make(chan struct{})}
	r.link = &directLink{r: r}
	r.localIP.Store(&net.IPAddr{IP: net.ParseIP("10.9.9.9")}) // learnLocalIP must not resolve a route
	r.leak.init(r.closeCh, rec.install)

	first := hostOnly(pool.current())
	r.rotatePeerRaw(true)
	second := hostOnly(pool.current())
	if second == first {
		t.Fatalf("the pool did not rotate (still %s) — the test proves nothing", first)
	}
	if ev := rec.events(); len(ev) != 1 || ev[0] != "add "+second {
		t.Fatalf("rotation did not pre-scope the anti-leak rule to %s: %v", second, ev)
	}

	// The first authenticated frame from the new destination now costs nothing.
	r.learnPeer(&net.IPAddr{IP: net.ParseIP(second)})
	time.Sleep(100 * time.Millisecond) // an async re-scope would have landed well inside this
	if ev := rec.events(); len(ev) != 1 {
		t.Fatalf("the receive path re-scoped a rule the rotation had already installed: %v", ev)
	}

	r.rotatePeerRaw(true)
	third := hostOnly(pool.current())
	ev := rec.events()
	addNew, delOld := evIndex(ev, "add "+third), evIndex(ev, "del "+second)
	if addNew < 0 || delOld < 0 {
		t.Fatalf("second rotation did not re-scope (want add %s then del %s): %v", third, second, ev)
	}
	if addNew > delOld {
		t.Fatalf("the old scope was removed before the new one was installed — a leak window: %v", ev)
	}

	pinTarget := "10.0.0.1"
	if pinTarget == third {
		pinTarget = "10.0.0.2"
	}
	if !pool.selectEntry(pinTarget) {
		t.Fatalf("selectEntry(%s) refused the pin", pinTarget)
	}
	r.adoptPeerRaw()
	if ev := rec.events(); evIndex(ev, "add "+pinTarget) < 0 {
		t.Fatalf("a pin did not pre-scope the anti-leak rule to %s: %v", pinTarget, ev)
	}
}

// TestRawLearnPeerNeverBlocksOnIptables: a raw SERVER only learns its peer from the first
// authenticated frame, which arrives on recvConnLoop's goroutine — the data path. Forking iptables
// there stalls the download for as long as the xtables lock is contended.
func TestRawLearnPeerNeverBlocksOnIptables(t *testing.T) {
	installing := make(chan struct{})
	rec := &leakRecorder{delay: 750 * time.Millisecond, tookTo: installing}
	r := &Raw{profile: "tcp", closeCh: make(chan struct{})}
	r.link = &directLink{r: r}
	r.localIP.Store(&net.IPAddr{IP: net.ParseIP("10.9.9.9")})
	r.leak.init(r.closeCh, rec.install)

	start := time.Now()
	r.learnPeer(&net.IPAddr{IP: net.ParseIP("10.0.0.42")})
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Fatalf("learnPeer held the receive goroutine for %v while iptables ran", el)
	}
	<-installing // the re-scope really did start, just not on the caller's goroutine
	waitFor(t, 5*time.Second, "the anti-leak rule was re-scoped off the receive path", func() bool {
		ev := rec.events()
		return len(ev) == 1 && strings.HasPrefix(ev[0], "add 10.0.0.42")
	})
}

// TestHandBuiltRawTouchesNoFirewall: every Raw a test constructs by hand leaves the installer nil,
// and each entry point must then be a no-op. DE runs these as root, so a regression here would put
// real rules in the host's OUTPUT chain.
func TestHandBuiltRawTouchesNoFirewall(t *testing.T) {
	pool := NewPeerPool([]string{"10.0.0.1", "10.0.0.2"}, false, 0, "")
	r := &Raw{profile: "icmp", isClient: true, pp: pool, closeCh: make(chan struct{})}
	r.link = &directLink{r: r}
	r.localIP.Store(&net.IPAddr{IP: net.ParseIP("10.9.9.9")})

	r.leak.scope(net.ParseIP("10.0.0.1"))
	r.rotatePeerRaw(true)
	r.adoptPeerRaw()
	r.learnPeer(&net.IPAddr{IP: net.ParseIP("10.0.0.2")})
	time.Sleep(50 * time.Millisecond)
	r.leak.teardown()

	if r.leak.cur.Load() != nil || r.leak.curIP != nil {
		t.Fatal("a hand-built Raw with no installer recorded an installed rule")
	}
}
