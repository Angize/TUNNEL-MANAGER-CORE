package packet

import (
	"fmt"
	"math/rand"
	"testing"
)

func peerInvariants(t *testing.T, p *PeerPool, step int, log []string) {
	t.Helper()
	fail := func(format string, a ...any) {
		t.Helper()
		t.Fatalf("after step %d (%v): "+format, append([]any{step, log}, a...)...)
	}
	got := p.current()

	p.mu.Lock()
	defer p.mu.Unlock()

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

	if p.pinKey != "" && got != p.pinKey {
		fail("pin is on %q but current() gave %q", p.pinKey, got)
	}

	if p.chosen != "" && p.addrs[p.cur] != p.chosen {
		fail("chosen=%q while the cursor names %q", p.chosen, p.addrs[p.cur])
	}

	if p.pinKey != "" && !p.health.healthy(p.pinKey) {
		fail("the pinned endpoint %q is burned while the pin is in force", p.pinKey)
	}

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
			p := NewPeerPool(addrs, 0)
			p.now = func() int64 { return clk }
			pick := func() string { return addrs[rng.Intn(len(addrs))] }

			var log []string
			for step := 1; step <= 120; step++ {
				op := rng.Intn(10)
				switch op {
				case 0:
					log = append(log, "fail")
					p.fail("tun-probe")
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
					p.pinCannotLand(k)
				case 5:
					log = append(log, "releasePin")
					p.releasePin()
				case 6:

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
					k := pick()
					log = append(log, "retest:"+k)
					p.retestNow(k)
				}
				peerInvariants(t, p, step, log)
			}
		})
	}
}

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
			b, p := edgeCarrier(t, ips, snis(hosts...))
			p.now = func() int64 { return clk }
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
					b.pretendConnected(ip, sni.host)
					log = append(log, "verdict:"+ip+"/"+sni.host)
					b.rc.fail(b.rotateLowTCP, b.rotateHighTCP)
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
					log = append(log, "dialFail:"+k+":"+v)
					p.markSuspect(k, v, "dial")
				case 5:
					k, v := axis()
					log = append(log, "retest:"+k+":"+v)
					p.retestNow(k, v)
				case 6:
					clk += int64(rng.Intn(4000))
					log = append(log, fmt.Sprintf("clock=%d", clk))
				case 7:
					log = append(log, "advanceIP")
					p.advanceIP()
				case 8:
					log = append(log, "advanceIP+restoreSNIs")
					p.advanceIP()
					p.restoreIPs()
				case 9:
					ip := ips[rng.Intn(len(ips))]
					log = append(log, "pinApplied:"+ip)
					p.pinLandedOn(ip, hosts[rng.Intn(len(hosts))])
				case 10:
					ip := ips[rng.Intn(len(ips))]
					log = append(log, "pinFailed:"+ip)
					p.pinCannotLand(ip)
				}
				edgeInvariants(t, p, step, log)
			}
		})
	}
}
