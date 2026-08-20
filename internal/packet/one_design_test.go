package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoopWholeEdgeOutage(t *testing.T) {
	dir := t.TempDir()
	p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2"), filepath.Join(dir, "st.json"))
	clk := int64(10000)
	p.now = func() int64 { return clk }
	ip, sni, _ := p.current()
	p.setActive(activeLabel(ip, sni.host))
	b := &TCP{pool: p}
	armAndSpendTheFreeRungs(t, b)

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

	send(poolCmd{Kind: "ip", Key: "e2"})
	if got, _, _ := p.current(); got != "e2" {
		t.Fatalf("the operator's pin did not land after a run of verdicts: current=%s", got)
	}
}

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
