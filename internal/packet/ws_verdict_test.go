package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func wsVerdict(t *testing.T, b *TCP, c poolCmd) {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.pool.cmdPath(), data, 0o644); err != nil {
		t.Fatalf("write cmd: %v", err)
	}
	b.pollWsCmd()
}

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
	p := newWSPool(ips, snis(hosts...), filepath.Join(t.TempDir(), "status.json"))
	ip, sni, ok := p.current()
	if !ok {
		t.Fatal("fresh pool has no current edge")
	}
	p.setActive(activeLabel(ip, sni.host))
	b := &TCP{pool: p}
	armAndSpendTheFreeRungs(t, b)
	return b
}

// Run() wires the rung on every client, so a hand-built carrier must too -- otherwise the test proves
// nothing about the path that has one. Spending the budget up front leaves these tests asking what they
// were written to ask: WHICH entry a verdict condemns, once the free steps are gone.
func armAndSpendTheFreeRungs(t *testing.T, b *TCP) {
	t.Helper()
	b.port.setRoll(b.rollSourcePort)
	for i := 1; i <= portTries; i++ {
		if !b.port.try() {
			t.Fatalf("free rung %d of %d would not spend", i, portTries)
		}
	}
}

func TestWSFailBurnsWhatItMeasured(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2"}, []string{"s1", "s2"})

	measuredIP, measuredSNI := b.pool.activeCombo()
	b.pool.advance()
	ip, sni, _ := b.pool.current()
	b.pool.setActive(activeLabel(ip, sni.host))
	if sni.host == measuredSNI {
		t.Fatalf("advance() did not change the SNI (%s) — the test cannot show the stale case", sni.host)
	}

	wsVerdict(t, b, poolCmd{Cmd: cmdFail, IP: measuredIP, SNI: measuredSNI})

	burned := wsBurned(b.pool, "sni")
	if !burned[measuredSNI] {
		t.Fatalf("the SNI the probe MEASURED (%s) was not burned; burned=%v", measuredSNI, burned)
	}
	if burned[sni.host] {
		t.Fatalf("burned %s — the combo the carrier moved TO, which nothing measured", sni.host)
	}
	if got, _, _ := b.pool.current(); got != ip {
		t.Fatalf("a stale verdict moved the edge (%s -> %s); it must stay put", ip, got)
	}
}

func TestWSVerdictWalksTheMatrix(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2"}, []string{"s1", "s2", "s3"})
	startIP, _, _ := b.pool.current()

	for i := 1; i <= 3; i++ {
		ip, sni, _ := b.pool.current()
		b.pool.setActive(activeLabel(ip, sni.host))
		wsVerdict(t, b, poolCmd{Cmd: cmdFail, IP: ip, SNI: sni.host})
		if got, _, _ := b.pool.current(); i < 3 && got != startIP {
			t.Fatalf("the edge moved after %d of 3 SNIs (%s -> %s) — it is convicted too early", i, startIP, got)
		}
	}
	if got, _, _ := b.pool.current(); got == startIP {
		t.Fatalf("every SNI on %s failed and the edge still did not move", startIP)
	}
}

func TestWSOKClearsBothAxes(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2"}, []string{"s1", "s2"})
	b.pool.markSuspect("ip", "e1", "test")
	b.pool.markSuspect("sni", "s1", "test")

	wsVerdict(t, b, poolCmd{Cmd: cmdOK, IP: "e1", SNI: "s1"})

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

	wsVerdict(t, b, poolCmd{Cmd: cmdOK, IP: "e1", SNI: "s1"})

	if wsBurned(b.pool, "sni")["s1"] {
		t.Fatal("s1 was measured carrying and stayed burned")
	}
	if !wsBurned(b.pool, "sni")["s2"] {
		t.Fatal("s2 was cleared by a verdict that never measured it")
	}
}

func TestWSPinStillWorks(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2"}, []string{"s1", "s2"})

	wsVerdict(t, b, poolCmd{Kind: "ip", Key: "e2"})

	if got, _, _ := b.pool.current(); got != "e2" {
		t.Fatalf("the panel's pin did not land: current edge is %s, want e2", got)
	}
}
