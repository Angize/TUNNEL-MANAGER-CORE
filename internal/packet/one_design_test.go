package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestLoopWholeEdgeOutage drives a whole outage end to end — 2 edges x 2 SNIs, everything blocked, one
// verdict per round exactly as the node sends them, then one carrying round. It asserts the properties
// the DESIGN rests on rather than any single function: the walk covers the matrix, the high digit does
// turn, a carrying combination clears both axes, and the operator's pin still lands through the very
// same file the verdicts arrived on.
//
// Every unit test here can pass while this one fails: each checks one hop, and the bugs that actually
// shipped lived between hops.
func TestLoopWholeEdgeOutage(t *testing.T) {
	dir := t.TempDir()
	p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2"), filepath.Join(dir, "st.json"))
	clk := int64(10000)
	p.now = func() int64 { return clk }
	ip, sni, _ := p.current()
	p.setActive(activeLabel(ip, sni.host))
	b := &TCP{pool: p}

	send := func(c poolCmd) {
		d, _ := json.Marshal(c)
		if err := os.WriteFile(p.cmdPath(), d, 0o644); err != nil {
			t.Fatal(err)
		}
		b.pollWsCmd()
	}
	seen := map[string]int{}
	edges := map[string]bool{}
	for round := 1; round <= 4; round++ {
		ip, e, _ := p.current()
		p.setActive(activeLabel(ip, e.host))
		seen[ip+"|"+e.host]++
		edges[ip] = true
		send(poolCmd{Cmd: cmdFail, IP: ip, SNI: e.host})
	}
	if len(seen) < 3 {
		t.Fatalf("four rounds only reached %d combinations: %v — the walk is not covering the matrix", len(seen), seen)
	}
	if len(edges) < 2 {
		t.Fatalf("four rounds never left edge %v — the high digit never turned", edges)
	}

	// The node now says traffic is crossing on wherever it ended up. BOTH halves must go healthy.
	ip, e, _ := p.current()
	p.setActive(activeLabel(ip, e.host))
	p.markSuspect("ip", ip, "test")
	p.markSuspect("sni", e.host, "test")
	send(poolCmd{Cmd: cmdOK, IP: ip, SNI: e.host})
	p.mu.Lock()
	stillIP, stillSNI := !p.ipHealth.healthy(ip), !p.sniHealth.healthy(e.host)
	p.mu.Unlock()
	if stillIP || stillSNI {
		t.Fatalf("a carrying combination stayed condemned: ip=%v sni=%v", stillIP, stillSNI)
	}

	// A pin must still land, through the very same file the verdicts came on.
	send(poolCmd{Kind: "ip", Key: "e2"})
	if got, _, _ := p.current(); got != "e2" {
		t.Fatalf("the operator's pin did not land after a run of verdicts: current=%s", got)
	}
}

// TestLoopWholeDirectOutage is the same shape on the DIRECT pool, which is the claim the whole
// consolidation makes: one judge, one odometer, two carriers. If these two ever need different
// assertions, the pools have drifted apart again.
func TestLoopWholeDirectOutage(t *testing.T) {
	dir := t.TempDir()
	b := &TCP{
		pp: NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "d.json")),
		sp: NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json")),
	}
	dsts, srcs := map[string]bool{}, map[string]bool{}
	for round := 1; round <= 6; round++ {
		dsts[b.pp.current()] = true
		srcs[b.sp.current()] = true
		b.burnAdvance(true)
	}
	if len(dsts) < 3 {
		t.Fatalf("six rounds reached %d of 3 destinations: %v", len(dsts), dsts)
	}
	if len(srcs) < 2 {
		t.Fatalf("six rounds never moved the source: %v — the odometer's high digit is stuck", srcs)
	}
}
