package packet

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

type nfPacket struct {
	what     string
	proto    int
	icmpType int
	sport    int
	dport    int
	rst      bool
	mark     uint32
}

var icmpTypeByName = map[string]int{
	"echo-reply": 0,

	"port-unreachable":        3,
	"destination-unreachable": 3,
	"echo-request":            8,
}

func ruleMatches(t *testing.T, m []string, p nfPacket) bool {
	t.Helper()
	hit := true
	for i := 0; i < len(m); i++ {
		switch m[i] {
		case "-d":
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

func ourFrame(profile string, isClient, marked bool) nfPacket {
	body := []byte("sealed-frame-bytes-0123456789abcdef")
	src, dst := net.IPv4(10, 9, 0, 1), net.IPv4(10, 9, 0, 2)
	pkt := rawEncap(profile, body, src, dst, isClient, 0xBEEF, 0, 0, 7, 9, 0x11223344, 0, 0, tcpPshAck)
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

func kernelAnswers(profile string, isClient bool) []nfPacket {
	switch profile {
	case "icmp":
		return []nfPacket{{what: "the kernel mirroring our ciphertext back (icmp echo reply)", proto: protoICMP, icmpType: 0}}
	case "udp":
		return []nfPacket{{what: "the kernel's icmp port-unreachable quoting our datagram", proto: protoICMP, icmpType: 3}}
	case "tcp":

		psp, pdp := rawPorts(!isClient, 0, 0)
		return []nfPacket{{what: "the kernel's RST", proto: protoTCP, icmpType: -1,
			sport: int(pdp), dport: int(psp), rst: true}}
	}
	return nil
}

var leakPeer = net.IPv4(203, 0, 113, 7)

func TestRawAntiLeakNeverMatchesOurOwnFrames(t *testing.T) {
	for profile := range rawProfiles {
		for _, isClient := range []bool{true, false} {
			for _, marked := range []bool{true, false} {
				ours := ourFrame(profile, isClient, marked)
				for _, m := range rawDropMatches(leakPeer, profile, 0, isClient, marked, false) {
					if ruleMatches(t, m, ours) {
						t.Fatalf("raw/%s (isClient=%v marked=%v): the anti-leak rule %v matches %s — this silently black-holes the tunnel",
							profile, isClient, marked, m, ours.what)
					}
				}
			}
		}
	}
}

func TestRawAntiLeakSuppressesEveryMeasuredKernelAnswer(t *testing.T) {
	for _, profile := range []string{"icmp", "udp", "tcp"} {

		roles := []bool{true, false}
		if profile == "icmp" {
			roles = []bool{false}
		}
		for _, isClient := range roles {
			for _, ans := range kernelAnswers(profile, isClient) {
				covered := false
				for _, m := range rawDropMatches(leakPeer, profile, 0, isClient, true, false) {
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

func TestRawIcmpRuleIsSkippedWithoutTheMark(t *testing.T) {
	if got := rawDropMatches(leakPeer, "icmp", 0, false, false, false); len(got) != 0 {
		t.Fatalf("an icmp server with no SO_MARK still installed %v — that drops its own downstream frames", got)
	}
	if got := rawDropMatches(leakPeer, "icmp", 0, false, true, false); len(got) != 1 {
		t.Fatalf("an icmp server WITH the mark should install exactly one rule, got %v", got)
	}

	for _, marked := range []bool{true, false} {
		if got := rawDropMatches(leakPeer, "icmp", 0, true, marked, false); len(got) != 0 {
			t.Fatalf("an icmp CLIENT (marked=%v) installed %v; nothing answers its echo replies", marked, got)
		}
	}
}

func TestRawPortedProfilesReverseTheFlow(t *testing.T) {
	ported := 0
	for profile := range rawProfiles {
		c, s := ourFrame(profile, true, false), ourFrame(profile, false, false)
		if c.sport == 0 && c.dport == 0 && s.sport == 0 && s.dport == 0 {
			continue
		}
		ported++
		if c.sport == c.dport {
			t.Fatalf("raw/%s: both ends of the pair are port %d, so reversing it is vacuous", profile, c.sport)
		}
		if c.sport != s.dport || c.dport != s.sport {
			t.Fatalf("raw/%s: the client sends %d->%d and the server sends %d->%d — a real flow reverses, and a middlebox drops the half it cannot pair",
				profile, c.sport, c.dport, s.sport, s.dport)
		}
	}
	if ported != 2 {
		t.Fatalf("measured %d profiles carrying L4 ports, want 2 (udp, tcp) — ourFrame is no longer reading them, so this test proves nothing", ported)
	}
}

func TestRawAntiLeakLeavesQuietProfilesAlone(t *testing.T) {
	for _, profile := range []string{"bare", "ipip", "gre", "esp"} {
		for _, isClient := range []bool{true, false} {
			if got := rawDropMatches(leakPeer, profile, 0, isClient, true, false); len(got) != 0 {
				t.Fatalf("raw/%s installed %v; no kernel handler answers that protocol", profile, got)
			}
		}
	}
}

func TestRawRotationPreScopesAntiLeak(t *testing.T) {
	defer func(d time.Duration) { antiLeakLinger = d }(antiLeakLinger)
	antiLeakLinger = 20 * time.Millisecond
	rec := &leakRecorder{}
	pool := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 0, "")
	r := &Raw{profile: "udp", isClient: true, pp: pool, closeCh: make(chan struct{})}
	r.link = &directLink{r: r}
	r.localIP.Store(&net.IPAddr{IP: net.ParseIP("10.9.9.9")})
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

	r.learnPeer(&net.IPAddr{IP: net.ParseIP(second)})
	time.Sleep(100 * time.Millisecond)
	if ev := rec.events(); len(ev) != 1 {
		t.Fatalf("the receive path re-scoped a rule the rotation had already installed: %v", ev)
	}

	r.rotatePeerRaw(true)
	third := hostOnly(pool.current())
	waitFor(t, 5*time.Second, "the rule for the endpoint we left was removed after its linger", func() bool {
		return evIndex(rec.events(), "del "+second) >= 0
	})
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
	<-installing
	waitFor(t, 5*time.Second, "the anti-leak rule was re-scoped off the receive path", func() bool {
		ev := rec.events()
		return len(ev) == 1 && strings.HasPrefix(ev[0], "add 10.0.0.42")
	})
}

func TestHandBuiltRawTouchesNoFirewall(t *testing.T) {
	pool := NewPeerPool([]string{"10.0.0.1", "10.0.0.2"}, 0, "")
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
