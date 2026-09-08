package packet

import (
	"fmt"
	"math/rand"
	"testing"
)

func peerInvariants(t *testing.T, p *PeerPool, step int, log []string) {
	t.Helper()
	p.mu.Lock()
	axis := p.axis
	p.mu.Unlock()
	if axis == "" {
		axis = "pool"
	}
	fail := func(format string, a ...any) {
		t.Helper()
		t.Fatalf("%s: after step %d (%v): "+format, append([]any{axis, step, log}, a...)...)
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

	if p.chosen != "" && p.addrs[p.cur] != p.chosen {
		fail("chosen=%q while the cursor names %q", p.chosen, p.addrs[p.cur])
	}

	if live := p.liveAddr(); live == nil || live.s != p.addrs[p.cur] {
		fail("the carrier is reading %+v while the cursor names %q — the address the packets "+
			"actually go to and the one the panel reports have come apart", live, p.addrs[p.cur])
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
				op := rng.Intn(7)
				switch op {
				case 0:
					log = append(log, "fail")
					p.fail("tun-probe")
				case 1:
					log = append(log, "rotateOnce")
					p.rotateOnce()
				case 2:
					k := pick()
					log = append(log, "jump:"+k)
					p.selectEntry(k)
				case 3:
					log = append(log, "current")
					p.current()
				case 4:
					k := pick()
					log = append(log, "clearBurn:"+k)
					p.clearBurn(k)
				case 5:
					clk += int64(rng.Intn(4000))
					log = append(log, fmt.Sprintf("clock=%d", clk))
				case 6:
					k := pick()
					log = append(log, "retest:"+k)
					p.retestNow(k)
				}
				peerInvariants(t, p, step, log)
			}
		})
	}
}

// Both edge axes are ordinary PeerPools now, so every pool invariant must hold on each of them, and on
// top of that the combo the dial path builds must be exactly the two cursors and the SNI host list must
// not drift away from the ech/path map beside it.
func edgeInvariants(t *testing.T, b *TCP, step int, log []string) {
	t.Helper()
	fail := func(format string, a ...any) {
		t.Helper()
		t.Fatalf("edge: after step %d (%v): "+format, append([]any{step, log}, a...)...)
	}

	ip, sni, ok := b.edgeCombo()
	if !ok {
		fail("edgeCombo() gave up on a pool holding %v and %v", b.pp.all(), b.sp.all())
	}
	if want := activeLabel(ip, sni.host); b.edgeAt() != want {
		fail("the status file says %q while the dial path would take %q", b.edgeAt(), want)
	}
	for _, h := range b.sp.all() {
		if b.sniEntry(h).path == "" {
			fail("the SNI pool holds %q but the metadata map has no entry for it — the host list and "+
				"the ech/path map beside it have come apart", h)
		}
	}

	peerInvariants(t, b.pp, step, log)
	peerInvariants(t, b.sp, step, log)
}

func TestBothEdgeAxesHoldTheirInvariantsUnderRandomSequences(t *testing.T) {
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
			b, pp, sp := edgeCarrier(t, ips, snis(hosts...))
			pp.now = func() int64 { return clk }
			sp.now = func() int64 { return clk }
			axis := func() (string, *PeerPool, string) {
				if rng.Intn(2) == 0 {
					return axisIP, pp, ips[rng.Intn(len(ips))]
				}
				return axisSNI, sp, hosts[rng.Intn(len(hosts))]
			}

			var log []string
			for step := 1; step <= 120; step++ {
				switch rng.Intn(11) {
				case 0:
					log = append(log, "walkEdge")
					b.walkEdge()
				case 1:
					ip, sni, _ := b.edgeCombo()
					b.pretendConnected(ip, sni.host)
					log = append(log, "verdict:"+ip+"/"+sni.host)
					b.rc.fail(b.rotateLowTCP, b.rotateHighTCP)
				case 2:
					kind, p, v := axis()
					log = append(log, "jump:"+kind+":"+v)
					p.selectEntry(v)
				case 3:
					kind, p, v := axis()
					log = append(log, "clearBurn:"+kind+":"+v)
					p.clearBurn(v)
				case 4:
					kind, p, v := axis()
					log = append(log, "dialFail:"+kind+":"+v)
					p.markSuspect(v, "dial")
				case 5:
					kind, p, v := axis()
					log = append(log, "retest:"+kind+":"+v)
					p.retestNow(v)
				case 6:
					clk += int64(rng.Intn(4000))
					log = append(log, fmt.Sprintf("clock=%d", clk))
				case 7:
					log = append(log, "rotateIP")
					pp.rotateOnce()
				case 8:
					log = append(log, "rotateIP+restoreAll")
					pp.rotateOnce()
					pp.restoreAll()
				case 9:
					log = append(log, "rotateSNI")
					sp.rotateOnce()
				}
				edgeInvariants(t, b, step, log)
			}
		})
	}
}
