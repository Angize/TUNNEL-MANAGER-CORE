package packet

import (
	"path/filepath"
	"testing"
)

// core13's real shape on 2026-08-21: three edges, ONE domain. The walk varies the edge and turns the
// domain once the row is spent -- but turning it here means turning it onto itself, and condemning it
// leaves the operator a red row they cannot act on while currentLocked keeps handing it out anyway.
// The evidence belongs to the axis that actually varied.
func TestALoneDomainIsNeverCondemned(t *testing.T) {
	p := newWSPool([]string{"ip1", "ip2", "ip3"}, snis("cdn.example"))
	b := &TCP{isClient: true, ws: true, wsPath: "/", pool: p, closeCh: make(chan struct{})}
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	b.rc.port.setRoll(func() bool { return true })

	for round := 1; round <= 4*(portTries+1); round++ {
		ip, sni, _ := p.current()
		b.noteAttempt(ip, sni.host)
		low, high := b.livePairNow()
		b.rc.judge(poolCmd{Cmd: cmdFail, Low: low, High: high}, b.rotateLowTCP, b.rotateHighTCP, 0)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.sniHealth.healthy("cdn.example") {
		t.Error("the only domain the tunnel has was condemned. There is nothing to rotate to, the pool " +
			"keeps serving it from the fallback, and the panel tells the operator their domain is " +
			"blocked when what the probe measured was the edges")
	}
	burned := 0
	for _, k := range p.ips {
		if !p.ipHealth.healthy(k) {
			burned++
		}
	}
	if burned == 0 {
		t.Error("and nothing was condemned at all — the edges are the axis that varied, so they are " +
			"what the evidence is about")
	}
}

// The mirror: one edge, several domains. Now the edge is the axis with nowhere to go.
func TestALoneEdgeIsNeverCondemned(t *testing.T) {
	p := newWSPool([]string{"only.edge"}, snis("s1", "s2", "s3"))
	b := &TCP{isClient: true, ws: true, wsPath: "/", pool: p, closeCh: make(chan struct{})}
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	b.rc.port.setRoll(func() bool { return true })

	for round := 1; round <= 2*(portTries+1); round++ {
		ip, sni, _ := p.current()
		b.noteAttempt(ip, sni.host)
		low, high := b.livePairNow()
		b.rc.judge(poolCmd{Cmd: cmdFail, Low: low, High: high}, b.rotateLowTCP, b.rotateHighTCP, 0)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ipHealth.healthy("only.edge") {
		t.Error("the only edge was condemned — nothing can rotate to another one")
	}
	if p.sniHealth.healthy("s1") {
		t.Error("and the domain was not condemned either; with one edge the domain is the digit the " +
			"walk varies, so it is what a verdict names")
	}
}
