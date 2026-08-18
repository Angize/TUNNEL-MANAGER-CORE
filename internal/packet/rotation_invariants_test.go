package packet

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
)

// A stateful fuzz over BOTH pools. Every earlier test in this package fixes a scenario someone thought
// of; this one drives random legal operation sequences and checks the properties that must hold no
// matter what order they arrive in. The verdicts, the retests, the pins, the proactive rotation and the
// clock all move independently in production, and their interleavings are where the pool's bugs have
// actually lived.

// ---- direct pool -------------------------------------------------------------------------------

// peerInvariants is checked after EVERY operation. Each is a property, not a scenario.
func peerInvariants(t *testing.T, p *PeerPool, step int, log []string) {
	t.Helper()
	fail := func(format string, a ...any) {
		t.Helper()
		t.Fatalf("after step %d (%v): "+format, append([]any{step, log}, a...)...)
	}
	got := p.current()

	p.mu.Lock()
	defer p.mu.Unlock()

	// 1. current() only ever names an endpoint the pool holds, and leaves the cursor on it. A carrier
	//    dials what current() returns while the panel shows addrs[cur]; if they disagree the operator is
	//    looking at an endpoint the tunnel is not using.
	known := false
	for _, a := range p.addrs {
		if a == got {
			known = true
		}
	}
	if !known {
		fail("current() returned %q, which is not in the pool", got)
	}
	if p.addrs[p.cur] != got {
		fail("current() returned %q but the cursor names %q — the panel and the carrier disagree",
			got, p.addrs[p.cur])
	}

	// 2. A live pin is always what current() hands out. The whole point of the pin is that the operator's
	//    pick is what gets dialled; anything else means the jump silently did not happen.
	if p.pinKey != "" && got != p.pinKey {
		fail("pin is on %q but current() gave %q", p.pinKey, got)
	}

	// 3. chosen never points anywhere the cursor is not (its own doc's invariant).
	if p.chosen != "" && p.addrs[p.cur] != p.chosen {
		fail("chosen=%q while the cursor names %q", p.chosen, p.addrs[p.cur])
	}

	// 4. A pinned entry is never left burned: selectEntry clears it, and nothing may re-burn what the
	//    operator is actively asking to try.
	if p.pinKey != "" && !p.health.healthy(p.pinKey) {
		fail("the pinned endpoint %q is burned while the pin is in force", p.pinKey)
	}

	// 5. No record is ever tracked for an address the pool does not hold (a leak into the health map
	//    would keep an endpoint condemned by a name nothing can clear).
	for k := range p.health.recs {
		found := false
		for _, a := range p.addrs {
			if a == k {
				found = true
			}
		}
		if !found {
			fail("health map holds %q, which is not in the pool", k)
		}
	}

	// 6. The ladder never runs backwards: a tracked entry's fails stay within the schedule.
	for k, r := range p.health.recs {
		if r.fails < 0 || r.fails > len(suspectBackoff) {
			fail("%q sits at fails=%d, outside the schedule (0..%d)", k, r.fails, len(suspectBackoff))
		}
		if r.state != stateSuspect && r.state != stateDead {
			fail("%q is tracked in state %q", k, r.state)
		}
	}
}

func TestPeerPoolInvariantsUnderRandomSequences(t *testing.T) {
	for seed := int64(1); seed <= 60; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			size := 1 + rng.Intn(4)
			addrs := make([]string, size)
			for i := range addrs {
				addrs[i] = fmt.Sprintf("d%d", i+1)
			}
			clk := int64(1000)
			p := NewPeerPool(addrs, 0, filepath.Join(t.TempDir(), "p.json"))
			p.now = func() int64 { return clk }
			pick := func() string { return addrs[rng.Intn(len(addrs))] }

			var log []string
			for step := 1; step <= 120; step++ {
				op := rng.Intn(10)
				switch op {
				case 0:
					log = append(log, "fail")
					p.fail()
				case 1:
					log = append(log, "rotateOnce")
					p.rotateOnce()
				case 2:
					k := pick()
					log = append(log, "pin:"+k)
					p.selectEntry(k)
				case 3:
					k := pick()
					log = append(log, "landed:"+k)
					p.pinLandedOn(k)
				case 4:
					k := pick()
					log = append(log, "pinFailed:"+k)
					p.pinAttemptFailed(k)
				case 5:
					log = append(log, "releasePin")
					p.releasePin()
				case 6:
					// The dial loop asking where to go. It SELECTS — re-picking by health and committing
					// the cursor — so it belongs in the mix as a mutation, not as a read.
					log = append(log, "current")
					p.current()
				case 7:
					k := pick()
					log = append(log, "clearBurn:"+k)
					p.clearBurn(k)
				case 8:
					clk += int64(rng.Intn(4000))
					log = append(log, fmt.Sprintf("clock=%d", clk))
				case 9:
					log = append(log, "probeAllNow")
					p.probeAllNow()
				}
				peerInvariants(t, p, step, log)
			}
		})
	}
}

// ---- edge pool ---------------------------------------------------------------------------------

func edgeInvariants(t *testing.T, p *wsPool, step int, log []string) {
	t.Helper()
	fail := func(format string, a ...any) {
		t.Helper()
		t.Fatalf("after step %d (%v): "+format, append([]any{step, log}, a...)...)
	}
	ip, sni, ok := p.current()
	if !ok {
		fail("current() gave up on a non-empty pool")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	inIPs, inSNIs := false, false
	for _, v := range p.ips {
		if v == ip {
			inIPs = true
		}
	}
	for _, v := range p.snis {
		if v.host == sni.host {
			inSNIs = true
		}
	}
	if !inIPs || !inSNIs {
		fail("current() returned %s · %s, which is not a combination this pool holds", ip, sni.host)
	}

	// A live pin FORCES its axis. An unpinned axis is free to be anything the walk picked.
	if p.pinIP != "" && ip != p.pinIP {
		fail("ip pin is on %q but current() gave %q", p.pinIP, ip)
	}
	if p.pinSNI != "" && sni.host != p.pinSNI {
		fail("sni pin is on %q but current() gave %q", p.pinSNI, sni.host)
	}
	if p.pinIP != "" && !p.ipHealth.healthy(p.pinIP) {
		fail("the pinned edge %q is burned while the pin is in force", p.pinIP)
	}
	if p.pinSNI != "" && !p.sniHealth.healthy(p.pinSNI) {
		fail("the pinned domain %q is burned while the pin is in force", p.pinSNI)
	}

	// chosen must name a combination the cursor is really on, or currentLocked's pass 0 hands back
	// something the walk is not sitting at.
	if p.chosen != "" {
		at := activeLabel(p.ips[p.i%len(p.ips)], p.snis[p.j%len(p.snis)].host)
		if at != p.chosen {
			fail("chosen=%q while the cursor is on %q", p.chosen, at)
		}
	}

	for _, m := range []struct {
		name string
		set  healthSet
		keys []string
	}{
		{"ip", p.ipHealth, p.ips},
		{"sni", p.sniHealth, sniHosts(p.snis)},
	} {
		for k, r := range m.set.recs {
			found := false
			for _, v := range m.keys {
				if v == k {
					found = true
				}
			}
			if !found {
				fail("%s health map holds %q, which is not in the pool", m.name, k)
			}
			if r.fails < 0 || r.fails > len(suspectBackoff) {
				fail("%s:%s sits at fails=%d, outside the schedule", m.name, k, r.fails)
			}
		}
	}
}

func sniHosts(e []wsSNIEntry) []string {
	out := make([]string, len(e))
	for i, s := range e {
		out[i] = s.host
	}
	return out
}

func TestEdgePoolInvariantsUnderRandomSequences(t *testing.T) {
	for seed := int64(1); seed <= 60; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			ips := make([]string, 1+rng.Intn(3))
			for i := range ips {
				ips[i] = fmt.Sprintf("e%d", i+1)
			}
			hosts := make([]string, 1+rng.Intn(3))
			for i := range hosts {
				hosts[i] = fmt.Sprintf("s%d", i+1)
			}
			clk := int64(1000)
			p := newWSPool(ips, snis(hosts...), filepath.Join(t.TempDir(), "st.json"))
			p.now = func() int64 { return clk }
			b := &TCP{pool: p}
			axis := func() (string, string) {
				if rng.Intn(2) == 0 {
					return "ip", ips[rng.Intn(len(ips))]
				}
				return "sni", hosts[rng.Intn(len(hosts))]
			}

			var log []string
			for step := 1; step <= 120; step++ {
				switch rng.Intn(11) {
				case 0:
					log = append(log, "advance")
					p.advance()
				case 1:
					ip, sni, _ := p.current()
					p.setActive(activeLabel(ip, sni.host))
					log = append(log, "verdict:"+ip+"/"+sni.host)
					b.burnAdvanceWS(ip, sni.host)
				case 2:
					k, v := axis()
					log = append(log, "pin:"+k+":"+v)
					p.selectEntry(k, v)
				case 3:
					k, v := axis()
					log = append(log, "clearBurn:"+k+":"+v)
					p.clearBurn(k, v)
				case 4:
					k, v := axis()
					log = append(log, "retestOK:"+k+":"+v)
					p.retestResult(k, v, true)
				case 5:
					k, v := axis()
					log = append(log, "retestFail:"+k+":"+v)
					p.retestResult(k, v, false)
				case 6:
					clk += int64(rng.Intn(4000))
					log = append(log, fmt.Sprintf("clock=%d", clk))
				case 7:
					log = append(log, "advanceIP")
					p.advanceIP()
				case 8:
					log = append(log, "advanceEdgeFreshRow")
					p.advanceEdgeFreshRow()
				case 9:
					ip := ips[rng.Intn(len(ips))]
					log = append(log, "pinApplied:"+ip)
					p.pinApplied(ip, hosts[rng.Intn(len(hosts))])
				case 10:
					ip := ips[rng.Intn(len(ips))]
					log = append(log, "pinFailed:"+ip)
					p.pinAttemptFailed(ip, hosts[rng.Intn(len(hosts))])
				}
				edgeInvariants(t, p, step, log)
			}
		})
	}
}
