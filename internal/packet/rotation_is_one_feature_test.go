package packet

import (
	"strings"
	"testing"
)

// udp and tcp both forge a port pair, so the rotation must be one feature on two profiles rather
// than a udp feature that tcp happens not to have. Everything below runs the same assertions over
// both profiles; a difference in ANY cell is the drift this file exists to catch.

func rotEnd(profile string, isClient bool, every int, random bool) *Raw {
	proto := protoUDP
	if profile == "tcp" {
		proto = protoTCP
	}
	r := &Raw{profile: profile, proto: proto, isClient: isClient, port: 443, psk: "a-psk"}
	r.setSportMode(random, 0)
	r.setSportRotate(SportRotation{Every: every})
	return r
}

func wire(r *Raw) (sport, dport uint16) {
	srv, cli := r.wirePorts(r.cport())
	return rawPorts(r.isClient, srv, cli)
}

func TestTheRotationIsTheSameFeatureOnUdpAndTcp(t *testing.T) {
	for _, profile := range []string{"udp", "tcp"} {
		t.Run(profile, func(t *testing.T) {
			cli, srv := rotEnd(profile, true, 3, false), rotEnd(profile, false, 3, false)
			if !cli.rotActive() || !srv.rotActive() {
				t.Fatalf("the packet rotation is off on %s — it is offered on every profile that "+
					"forges a port pair, not on udp alone", profile)
			}
			cs0, cd0 := wire(cli)
			ss0, _ := wire(srv)
			if cs0 == 443 || ss0 == 443 {
				t.Fatalf("an end is still on the configured port: client %d server %d", cs0, ss0)
			}
			if cd0 != 443 {
				t.Errorf("the client's destination moved to %d without raw_dports", cd0)
			}
			moved := func(r *Raw) bool {
				before, _ := wire(r)
				for i := 0; i < 6; i++ {
					if got, _ := wire(r); got != before {
						return true
					}
				}
				return false
			}
			if !moved(cli) || !moved(srv) {
				t.Errorf("%s: a source port did not move within six packets at every=3", profile)
			}
		})
	}
}

// The profiles that build no L4 header have nowhere to put a port, so the rotation must stay off
// rather than walking a number nothing carries.
func TestARotationNeedsAProfileThatForgesPorts(t *testing.T) {
	for _, profile := range []string{"bare", "gre", "ipip", "esp", "ah", "icmp", "l2tpv3", "etherip", "ipcomp"} {
		r := &Raw{profile: profile, proto: rawProfiles[profile], port: 443, psk: "a-psk"}
		r.setSportRotate(SportRotation{Every: 3})
		if r.rotActive() || r.portsMove() {
			t.Errorf("raw:%s has no port pair to walk, yet the rotation is armed", profile)
		}
	}
}

// The tcp profile sends its fake handshake through sendTCPFlags and its data through wireTo. Those
// were two different port sources: the SYN-ACK left from raw_port while the data left from the walked
// band, so one client saw the server answer from two ports at once -- which no TCP conversation does.
func TestTheFakeHandshakeUsesTheSamePortsAsTheData(t *testing.T) {
	body := funcBody(t, "raw_linux.go", "func (r *Raw) sendTCPFlags(")
	if strings.Contains(body, "r.srvPort()") {
		t.Error("sendTCPFlags stamps r.srvPort() — the handshake would leave from the configured port " +
			"while the data leaves from the walked one")
	}
	if !strings.Contains(body, "r.wirePorts(") {
		t.Fatal("sendTCPFlags does not go through wirePorts, so nothing keeps it in step with the data")
	}
	for _, random := range []bool{true, false} {
		every := 3
		if random {
			every = 0
		}
		for _, isClient := range []bool{true, false} {
			r := rotEnd("tcp", isClient, every, random)
			hsSrv, hsCli := r.wirePorts(r.cport())
			hs, _ := rawPorts(r.isClient, hsSrv, hsCli)
			data, _ := wire(r)
			if hs == r.port || data == r.port {
				t.Errorf("isClient=%v random=%v: a packet still leaves from the configured port "+
					"(handshake %d, data %d)", isClient, random, hs, data)
			}
		}
	}
}

// The client's destination walks the dport set, so the server's kernel answers packets addressed to
// any of them and its RST leaves FROM that port. Naming only raw_port lets the rest out.
func TestTheServersRstGuardCoversEveryPortItIsAskedOn(t *testing.T) {
	dports := dportSet(443, 4, "a-psk")
	if len(dports) != 4 {
		t.Fatalf("setup: %d dports", len(dports))
	}
	l := rawLeak{peer: leakPeer, profile: "tcp", port: 443, dports: dports, portsMove: true}
	rules := rawDropMatches(l)
	for _, p := range dports {
		hit := false
		for _, m := range rules {
			if ruleMatches(t, m, nfPacket{what: "RST", proto: protoTCP, icmpType: -1,
				sport: int(p), dport: 40000, rst: true}) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("nothing suppresses the kernel's RST from %d — the client sends there, so the "+
				"server answers from there on every packet it cannot socket", p)
		}
	}
}

// Both ends compute the dport set. The server does not send to them, but it must know them to guard
// the RSTs they draw, and deriving the set twice from the same psk is what keeps the two in step.
func TestBothEndsKnowTheDportSet(t *testing.T) {
	cli := &Raw{profile: "tcp", proto: protoTCP, isClient: true, port: 443, psk: "a-psk"}
	srv := &Raw{profile: "tcp", proto: protoTCP, isClient: false, port: 443, psk: "a-psk"}
	cli.setSportRotate(SportRotation{Every: 3, Dports: 4})
	srv.setSportRotate(SportRotation{Every: 3, Dports: 4})
	if len(srv.dports) != len(cli.dports) {
		t.Fatalf("client knows %d dports, server knows %d", len(cli.dports), len(srv.dports))
	}
	for i := range cli.dports {
		if cli.dports[i] != srv.dports[i] {
			t.Fatalf("the two ends derived different dport sets: %v vs %v", cli.dports, srv.dports)
		}
	}
	for i := 0; i < 40; i++ {
		if _, dport := wire(srv); dport == 0 {
			t.Fatal("the server produced no destination")
		}
	}
	if got, _ := wire(srv); got == 0 {
		t.Fatal("the server produced no source port")
	}
}
