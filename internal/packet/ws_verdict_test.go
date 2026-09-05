package packet

import "testing"

func wsBurned(p *wsPool, kind string) map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]bool{}
	for k, r := range p.healthMap(kind).recs {
		if r != nil {
			out[k] = true
		}
	}
	return out
}

func newVerdictPool(t *testing.T, ips, hosts []string) *TCP {
	t.Helper()
	b, p := edgeCarrier(t, ips, snis(hosts...))
	ip, sni, ok := p.current()
	if !ok {
		t.Fatal("fresh pool has no current edge")
	}
	b.pretendConnected(ip, sni.host)
	armAndSpendTheFreeRungs(t, b)
	return b
}

// Run() wires the rung on every client, so a hand-built carrier must too -- otherwise the test proves
// nothing about the path that has one. Spending the budget up front leaves these tests asking what they
// were written to ask: WHICH entry a verdict condemns, once the free steps are gone.
func armLikeRun(b *TCP) {
	b.rc.port.setRoll(b.rollSourcePort)
	b.rc.attachStatus(b.st)
}

func armAndSpendTheFreeRungs(t *testing.T, b *TCP) {
	t.Helper()
	armLikeRun(b)
	for i := 1; i <= portTries; i++ {
		if !b.rc.port.try() {
			t.Fatalf("free rung %d of %d would not spend", i, portTries)
		}
	}
}

func TestWSFailBurnsWhatItMeasured(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2"}, []string{"s1", "s2"})

	measuredLow, measuredHigh := b.livePairNow()
	b.pool.advance()
	ip, sni, _ := b.pool.current()
	b.pretendConnected(ip, sni.host)
	if ip == measuredLow {
		t.Fatalf("advance() did not change the edge (%s) — the test cannot show the stale case", ip)
	}

	b.tunFail(t, measuredLow, measuredHigh)

	burned := wsBurned(b.pool, "ip")
	if !burned[measuredLow] {
		t.Fatalf("the edge the probe MEASURED (%s) was not burned; burned=%v", measuredLow, burned)
	}
	if burned[ip] {
		t.Fatalf("burned %s — the combo the carrier moved TO, which nothing measured", ip)
	}
	if got, _, _ := b.pool.current(); got != ip {
		t.Fatalf("a stale verdict moved the pool off %s; it must stay put, got %s", ip, got)
	}
}

// Every edge under one domain, then the next domain. The edge is the cheap digit: it is what the
// filter blocks and it comes back on a ten-minute backoff. A domain is only condemned once every edge
// under it has failed, because losing a domain loses it on every edge at once.
func TestWSVerdictWalksTheMatrix(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2", "e3"}, []string{"s1", "s2"})
	_, startSNI, _ := b.pool.current()

	for i := 1; i <= 3; i++ {
		ip, sni, _ := b.pool.current()
		b.pretendConnected(ip, sni.host)
		if !b.tunFailUntilItMoves(t, ip, sni.host) {
			t.Fatalf("edge %d of 3 under %s: the pool would not move", i, startSNI.host)
		}
		if _, got, _ := b.pool.current(); i < 3 && got.host != startSNI.host {
			t.Fatalf("the domain turned after %d of 3 edges (%s -> %s) — it is convicted too early, and "+
				"a burned domain is burned on every edge at once", i, startSNI.host, got.host)
		}
	}
	if _, got, _ := b.pool.current(); got.host == startSNI.host {
		t.Fatalf("every edge under %s failed and the domain still did not turn", startSNI.host)
	}
}

func TestWSOKClearsBothAxes(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2"}, []string{"s1", "s2"})
	b.pool.markSuspect("ip", "e1", "test")
	b.pool.markSuspect("sni", "s1", "test")

	b.tunOK(t, "e1", "s1")

	if wsBurned(b.pool, "ip")["e1"] {
		t.Fatal("the edge stayed burned while the probe watched it carry")
	}
	if wsBurned(b.pool, "sni")["s1"] {
		t.Fatal("the SNI stayed burned while the probe watched it carry")
	}
}

func TestWSStaleOKClearsOnlyWhatItMeasured(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2"}, []string{"s1", "s2"})
	b.pool.markSuspect("sni", "s1", "test")
	b.pool.markSuspect("sni", "s2", "test")

	b.tunOK(t, "e1", "s1")

	if wsBurned(b.pool, "sni")["s1"] {
		t.Fatal("s1 was measured carrying and stayed burned")
	}
	if !wsBurned(b.pool, "sni")["s2"] {
		t.Fatal("s2 was cleared by a verdict that never measured it")
	}
}

func TestWSPinStillWorks(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2"}, []string{"s1", "s2"})

	b.operatorJump(t, "ip", "e2")

	if got, _, _ := b.pool.current(); got != "e2" {
		t.Fatalf("the panel's pin did not land: current edge is %s, want e2", got)
	}
}
