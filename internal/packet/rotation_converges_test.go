package packet

import (
	"fmt"
	"testing"
)

const convergeRounds = 200

func TestTheDirectWalkFindsTheOnePairThatWorks(t *testing.T) {
	shapes := []struct {
		dests, srcs  int
		goodD, goodS int
	}{
		{3, 2, 3, 2},
		{3, 2, 1, 2},
		{4, 1, 4, 1},
		{1, 3, 1, 3},
		{2, 2, 2, 1},
	}
	for _, sh := range shapes {
		sh := sh
		t.Run(fmt.Sprintf("%dx%d_good=d%d.s%d", sh.dests, sh.srcs, sh.goodD, sh.goodS), func(t *testing.T) {
			dests := make([]string, sh.dests)
			for i := range dests {
				dests[i] = fmt.Sprintf("d%d", i+1)
			}
			srcs := make([]string, sh.srcs)
			for i := range srcs {
				srcs[i] = fmt.Sprintf("s%d", i+1)
			}
			goodD := fmt.Sprintf("d%d", sh.goodD)
			goodS := fmt.Sprintf("s%d", sh.goodS)

			clk := int64(1000)
			b := &TCP{isClient: true}
			b.SetPeerPool(NewPeerPool(dests, 0))
			b.SetSourcePool(NewPeerPool(srcs, 0))
			b.pp.now = func() int64 { return clk }
			b.sp.now = func() int64 { return clk }

			found := 0
			var seen []string
			for round := 1; round <= convergeRounds; round++ {
				d, s := b.pp.current(), b.sp.current()
				seen = append(seen, d+"/"+s)
				if d == goodD && s == goodS {

					b.pp.clearBurn(d)
					b.sp.clearBurn(s)
					found++
					if found >= 12 {
						return
					}
					continue
				}
				if found > 0 {
					t.Fatalf("the walk had settled on %s/%s and then left it for %s/%s — a carrying pair "+
						"must not be rotated off by a verdict about something else (round %d)",
						goodD, goodS, d, s, round)
				}
				tcpWalk(b)
				clk += 30
			}
			t.Fatalf("%d rounds and the walk never reached %s/%s. It visited: %v", convergeRounds,
				goodD, goodS, dedupeRun(seen))
		})
	}
}

// The edge carrier now walks the very same two PeerPools a direct one does -- edge IPs on the low axis,
// SNI hosts on the high axis -- so whatever the shape, the walk must reach the one combination that
// carries and then stay on it. The 1xN and Nx1 shapes are the interesting ones: an axis of one is no
// longer skipped, it is burned in place and the other axis is what moves.
func TestTheEdgeWalkFindsTheOneComboThatWorks(t *testing.T) {
	shapes := []struct {
		edges, hosts int
		goodE, goodH int
	}{
		{3, 1, 3, 1},
		{3, 2, 2, 2},
		{2, 3, 1, 3},
		{1, 4, 1, 4},
		{4, 4, 4, 4},
	}
	for _, sh := range shapes {
		sh := sh
		t.Run(fmt.Sprintf("%dx%d_good=e%d.s%d", sh.edges, sh.hosts, sh.goodE, sh.goodH), func(t *testing.T) {
			ips := make([]string, sh.edges)
			for i := range ips {
				ips[i] = fmt.Sprintf("e%d", i+1)
			}
			hosts := make([]string, sh.hosts)
			for i := range hosts {
				hosts[i] = fmt.Sprintf("s%d", i+1)
			}
			goodE := fmt.Sprintf("e%d", sh.goodE)
			goodH := fmt.Sprintf("s%d", sh.goodH)

			clk := int64(1000)
			b, pp, sp := edgeCarrier(t, ips, snis(hosts...))
			pp.now = func() int64 { return clk }
			sp.now = func() int64 { return clk }

			found := 0
			var seen []string
			for round := 1; round <= convergeRounds; round++ {
				ip, sni, _ := b.edgeCombo()
				b.pretendConnected(ip, sni.host)
				seen = append(seen, ip+"/"+sni.host)
				if ip == goodE && sni.host == goodH {
					pp.clearBurn(ip)
					sp.clearBurn(sni.host)
					found++
					if found >= 12 {
						return
					}
					continue
				}
				if found > 0 {
					t.Fatalf("the walk had settled on %s/%s and then left it for %s/%s (round %d)",
						goodE, goodH, ip, sni.host, round)
				}
				b.rc.fail(b.rotateLowTCP, b.rotateHighTCP)
				clk += 30
			}
			t.Fatalf("%d rounds and the walk never reached %s/%s. It visited: %v", convergeRounds,
				goodE, goodH, dedupeRun(seen))
		})
	}
}

func TestNothingWorksAndTheNodeHandsItAllBack(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		clk := int64(1000)
		b, pp, sp := peerCarrier(t, []string{"d1", "d2", "d3"}, []string{"s1", "s2"})
		pp.now = func() int64 { return clk }
		sp.now = func() int64 { return clk }
		for i := 0; i < 12; i++ {
			tcpWalk(b)
			clk += 30
		}
		for _, d := range []string{"d1", "d2", "d3"} {
			b.operatorRetest(t, "dst", d)
		}

		if n := pp.eligibleCount(); n != 3 {
			t.Fatalf("after the hand-back only %d of 3 destinations can be reached — the pool is still "+
				"condemned and the walk cannot resume", n)
		}
		moved := map[string]bool{}
		for i := 0; i < 6; i++ {
			a, _ := pp.rotateOnce()
			moved[a] = true
		}
		if len(moved) < 2 {
			t.Fatalf("the rotation only ever reached %v after the hand-back", moved)
		}
	})

	t.Run("edge", func(t *testing.T) {
		clk := int64(1000)
		b, pp, sp := edgeCarrier(t, []string{"e1", "e2", "e3"}, snis("s1", "s2"))
		pp.now = func() int64 { return clk }
		sp.now = func() int64 { return clk }
		for i := 0; i < 12; i++ {
			ip, sni, _ := b.edgeCombo()
			b.pretendConnected(ip, sni.host)
			b.rc.fail(b.rotateLowTCP, b.rotateHighTCP)
			clk += 30
		}
		for _, e := range []string{"e1", "e2", "e3"} {
			b.operatorRetest(t, axisIP, e)
		}
		for _, h := range []string{"s1", "s2"} {
			b.operatorRetest(t, axisSNI, h)
		}

		if n := pp.eligibleCount(); n != 3 {
			t.Fatalf("after the hand-back only %d of 3 edge IPs can be reached — the pool is still "+
				"condemned and the walk cannot resume", n)
		}
		combos := map[string]bool{}
		for i := 0; i < 12; i++ {
			b.stepEdge()
			combos[b.edgeAt()] = true
		}
		if len(combos) < 2 {
			t.Fatalf("after the hand-back the walk only ever reached %v — a pool that was handed back "+
				"whole must be able to rotate again", combos)
		}
	})
}

func dedupeRun(in []string) []string {
	out := make([]string, 0, len(in))
	for i, v := range in {
		if i == 0 || in[i-1] != v {
			out = append(out, v)
		}
	}
	return out
}
