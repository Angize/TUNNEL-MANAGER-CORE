package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// wsVerdict writes one command file exactly as the node does, then runs the poll that reads it. It goes
// through pollWsCmd on purpose: the keying this file is about lives in that switch, not in any pool
// method, so a test that called the pool directly would pass while the wire stayed broken.
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

// newVerdictPool is a client whose pool publishes an active combo, so activeCombo() answers the way it
// does in production (setActive is what the dial path calls once a connection is up).
func newVerdictPool(t *testing.T, ips, hosts []string) *TCP {
	t.Helper()
	p := newWSPool(ips, snis(hosts...), filepath.Join(t.TempDir(), "status.json"))
	ip, sni, ok := p.current()
	if !ok {
		t.Fatal("fresh pool has no current edge")
	}
	p.setActive(activeLabel(ip, sni.host))
	return &TCP{pool: p}
}

// TestWSFailBurnsWhatItMeasured is the whole class, and the exact mirror of the direct pool's
// TestAStaleFailBurnsWhatItMeasured. Between the node measuring and this core reading the command the
// carrier's OWN rotation can move — the probe takes seconds and the poller is a one-second ticker — so
// an unkeyed verdict would condemn the combo the rotation just arrived at and advance off it, dropping
// the tunnel straight back onto the one the probe actually found dead.
func TestWSFailBurnsWhatItMeasured(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2"}, []string{"s1", "s2"})

	measuredIP, measuredSNI := b.pool.activeCombo() // where the node's probe found nothing crossing
	b.pool.advance()
	ip, sni, _ := b.pool.current()
	b.pool.setActive(activeLabel(ip, sni.host)) // the carrier moved on its own timer, under the verdict
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

// TestWSVerdictWalksTheMatrix is the odometer: each fail on the live combo burns the SNI, and only once
// every SNI that could be tried on this edge has been does the EDGE move. Convicting the edge on the
// first failure would throw away a perfectly good one whenever a single SNI is the blocked thing.
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

// TestWSOKClearsBothAxes: a probe that finds traffic crossing proves the whole combo, so both halves go
// healthy at once. Without this a burned entry the rotation later lands on stays condemned while it is
// visibly carrying, until its retest ladder happens to lapse.
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

// TestWSStaleOKClearsOnlyWhatItMeasured: the heal is keyed too. A green verdict that crossed with a
// rotation must not clear the burn on an entry the tunnel has already moved onto and never measured.
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

// TestWSPinStillWorks: pin and verdict share one command file, and the fail arm deliberately sits in the
// same switch case as the burn. A pin must still reach SelectEdge rather than being eaten by it.
func TestWSPinStillWorks(t *testing.T) {
	b := newVerdictPool(t, []string{"e1", "e2"}, []string{"s1", "s2"})

	wsVerdict(t, b, poolCmd{Kind: "ip", Key: "e2"})

	if got, _, _ := b.pool.current(); got != "e2" {
		t.Fatalf("the panel's pin did not land: current edge is %s, want e2", got)
	}
}
