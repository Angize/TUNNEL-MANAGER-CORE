package packet

import (
	"path/filepath"
	"testing"
)

// core13's real shape on 2026-08-21: three edges, ONE domain. The walk varies the edge and turns the
// domain once the row is spent. Turning it here means turning it onto itself -- but the burn is still
// recorded, because a green domain under a dead tunnel is the one thing the operator must not be told.
func TestALoneDomainIsStillCondemned(t *testing.T) {
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
	if p.sniHealth.healthy("cdn.example") {
		t.Error("the only domain stayed green after every edge under it had failed — nothing rotates " +
			"away from it, but the panel then shows a healthy domain on a tunnel carrying nothing")
	}
	burned := 0
	for _, k := range p.ips {
		if !p.ipHealth.healthy(k) {
			burned++
		}
	}
	if burned == 0 {
		t.Error("and the edges — the axis that actually varied — were left green")
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
