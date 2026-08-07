package packet

import (
	"fmt"
	"path/filepath"
	"testing"
)

// The question the operator actually asks of a rotation pool is not "does it burn the right thing" but
// "does it FIND the one that works, and then stay there". Everything else in this package tests a single
// decision; this closes the loop and runs the whole experiment the way the fleet does -- the node judges
// whatever is live, the core burns and walks, and round after round the pool either converges or does
// not.
//
// It is also the only shape that can catch a walk that CYCLES: burn, move, burn, move, back onto the
// first one, forever. Each individual decision looks right in isolation there, and the tunnel never comes
// up.

const convergeRounds = 200

// TestTheDirectWalkFindsTheOnePairThatWorks drives the tcp odometer with a node that answers honestly:
// silence everywhere except one (destination, source) pair.
func TestTheDirectWalkFindsTheOnePairThatWorks(t *testing.T) {
	shapes := []struct {
		dests, srcs int
		goodD, goodS int
	}{
		{3, 2, 3, 2}, // the last pair — the walk has to cover the whole matrix to reach it
		{3, 2, 1, 2}, // first destination, second source: only a source move can reach it
		{4, 1, 4, 1}, // no source axis at all
		{1, 3, 1, 3}, // no destination axis at all — the source is the only thing that varies
		{2, 2, 2, 1},
	}
	for _, sh := range shapes {
		sh := sh
		t.Run(fmt.Sprintf("%dx%d_good=d%d.s%d", sh.dests, sh.srcs, sh.goodD, sh.goodS), func(t *testing.T) {
			dir := t.TempDir()
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
			b := &TCP{
				pp: NewPeerPool(dests, true, 0, filepath.Join(dir, "d.json")),
				sp: NewPeerPool(srcs, true, 0, filepath.Join(dir, "s.json")),
			}
			b.pp.now = func() int64 { return clk }
			b.sp.now = func() int64 { return clk }

			found := 0
			var seen []string
			for round := 1; round <= convergeRounds; round++ {
				d, s := b.pp.current(), b.sp.current()
				seen = append(seen, d+"/"+s)
				if d == goodD && s == goodS {
					// The node's probe sees traffic crossing and says so, naming both ends.
					b.pp.clearBurn(d)
					b.sp.clearBurn(s)
					found++
					if found >= 12 {
						return // it landed and it STAYED — twelve consecutive carrying rounds
					}
					continue
				}
				if found > 0 {
					t.Fatalf("the walk had settled on %s/%s and then left it for %s/%s — a carrying pair "+
						"must not be rotated off by a verdict about something else (round %d)",
						goodD, goodS, d, s, round)
				}
				b.burnAdvance(true) // the probe measured silence on this pair
				clk += 30           // sweeps are seconds apart; let the ladder age like it really does
			}
			t.Fatalf("%d rounds and the walk never reached %s/%s. It visited: %v", convergeRounds,
				goodD, goodS, dedupeRun(seen))
		})
	}
}

// TestTheEdgeWalkFindsTheOneComboThatWorks is the same experiment on the two-axis CDN pool, including the
// one-SNI shape the operator hit, where the EDGE is the only thing the walk can vary.
func TestTheEdgeWalkFindsTheOneComboThatWorks(t *testing.T) {
	shapes := []struct {
		edges, hosts int
		goodE, goodH int
	}{
		{3, 1, 3, 1}, // the operator's tunnel: one domain, three edges, the last one is the live one
		{3, 2, 2, 2},
		{2, 3, 1, 3},
		{1, 4, 1, 4}, // one edge, several domains — only the SNI varies
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
			p := newWSPool(ips, snis(hosts...), true, filepath.Join(t.TempDir(), "st.json"))
			p.now = func() int64 { return clk }
			b := &TCP{pool: p}

			found := 0
			var seen []string
			for round := 1; round <= convergeRounds; round++ {
				ip, sni, _ := p.current()
				p.setActive(activeLabel(ip, sni.host)) // what the node keys its verdict on
				seen = append(seen, ip+"/"+sni.host)
				if ip == goodE && sni.host == goodH {
					p.clearBurn("ip", ip)
					p.clearBurn("sni", sni.host)
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
				b.burnAdvanceWS(ip, sni.host)
				clk += 30
			}
			t.Fatalf("%d rounds and the walk never reached %s/%s. It visited: %v", convergeRounds,
				goodE, goodH, dedupeRun(seen))
		})
	}
}

// TestNothingWorksAndTheNodeHandsItAllBack is the other end of the same loop: when the whole matrix is
// dead the node stops judging and restores every entry (probeAllNow). The pool must come out of that
// usable -- rotating again, not frozen on a least-bad entry it can never leave.
func TestNothingWorksAndTheNodeHandsItAllBack(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		dir := t.TempDir()
		clk := int64(1000)
		b := &TCP{
			pp: NewPeerPool([]string{"d1", "d2", "d3"}, true, 0, filepath.Join(dir, "d.json")),
			sp: NewPeerPool([]string{"s1", "s2"}, true, 0, filepath.Join(dir, "s.json")),
		}
		b.pp.now = func() int64 { return clk }
		b.sp.now = func() int64 { return clk }
		for i := 0; i < 12; i++ {
			b.burnAdvance(true)
			clk += 30
		}
		b.ProbeAllNow() // the node: "everything tried and still dead — have them all back"

		if n := b.pp.eligibleCount(); n != 3 {
			t.Fatalf("after the hand-back only %d of 3 destinations can be reached — the pool is still "+
				"condemned and the walk cannot resume", n)
		}
		moved := map[string]bool{}
		for i := 0; i < 6; i++ {
			a, _ := b.pp.rotateOnce()
			moved[a] = true
		}
		if len(moved) < 2 {
			t.Fatalf("the rotation only ever reached %v after the hand-back", moved)
		}
	})

	t.Run("edge", func(t *testing.T) {
		clk := int64(1000)
		p := newWSPool([]string{"e1", "e2", "e3"}, snis("s1", "s2"), true, filepath.Join(t.TempDir(), "st.json"))
		p.now = func() int64 { return clk }
		b := &TCP{pool: p}
		for i := 0; i < 12; i++ {
			ip, sni, _ := p.current()
			p.setActive(activeLabel(ip, sni.host))
			b.burnAdvanceWS(ip, sni.host)
			clk += 30
		}
		p.probeAllNow()

		combos := map[string]bool{}
		for i := 0; i < 12; i++ {
			p.advance()
			ip, sni, _ := p.current()
			combos[activeLabel(ip, sni.host)] = true
		}
		if len(combos) < 2 {
			t.Fatalf("after the hand-back the walk only ever reached %v — a pool that was handed back "+
				"whole must be able to rotate again", combos)
		}
	})
}

// dedupeRun collapses consecutive repeats so a failure prints the ROUTE the walk took rather than two
// hundred copies of wherever it got stuck.
func dedupeRun(in []string) []string {
	out := make([]string, 0, len(in))
	for i, v := range in {
		if i == 0 || in[i-1] != v {
			out = append(out, v)
		}
	}
	return out
}
