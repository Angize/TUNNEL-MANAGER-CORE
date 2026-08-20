package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func snis(hosts ...string) []wsSNIEntry {
	out := make([]wsSNIEntry, len(hosts))
	for i, h := range hosts {
		out[i] = wsSNIEntry{host: h, path: "/"}
	}
	return out
}

func clockPool(ips []string, snis []wsSNIEntry, statusPath string) (*wsPool, *int64) {
	p := newWSPool(ips, snis, statusPath)
	var now int64 = 1000
	p.now = func() int64 { return now }
	return p, &now
}

func TestARotationMovesOffTheLiveEdgeAndVariesBothAxes(t *testing.T) {

	p := newWSPool([]string{"a", "b"}, snis("x"), "")
	for round := 0; round < 20; round++ {
		before, _, ok := p.current()
		if !ok {
			t.Fatal("current() returned not-ok on a healthy 2-IP pool")
		}
		p.setActive(activeLabel(before, "x"))
		if !p.advance() {
			t.Fatalf("round %d: a healthy 2-IP pool reported no move", round)
		}
		if got, _, _ := p.current(); got == before {
			t.Fatalf("round %d: the rotation landed back on the live edge %q", round, got)
		}
	}

	p2 := newWSPool([]string{"a", "b"}, snis("x", "y"), "")
	seenIP, seenSNI := map[string]bool{}, map[string]bool{}
	for round := 0; round < 8; round++ {
		beforeIP, beforeSNI, _ := p2.current()
		p2.setActive(activeLabel(beforeIP, beforeSNI.host))
		if !p2.advance() {
			t.Fatalf("round %d: a healthy 2x2 pool reported no move", round)
		}
		ip, sni, ok := p2.current()
		if !ok {
			t.Fatal("current() returned not-ok on a healthy 2x2 pool")
		}
		if activeLabel(ip, sni.host) == activeLabel(beforeIP, beforeSNI.host) {
			t.Fatalf("round %d: the rotation resolved back onto the live combo %q", round, p2.active)
		}
		seenIP[ip] = true
		seenSNI[sni.host] = true
	}
	if !seenIP["a"] || !seenIP["b"] {
		t.Fatalf("the rotation never varied the IP axis; saw %v", seenIP)
	}
	if !seenSNI["x"] || !seenSNI["y"] {
		t.Fatalf("the rotation never varied the SNI axis; saw %v", seenSNI)
	}

	p3 := newWSPool([]string{"a", "b"}, snis("x", "y"), "")
	p3.markSuspect("sni", "y", "test")
	for round := 0; round < 4; round++ {
		p3.advance()
		if _, sni, _ := p3.current(); sni.host != "x" {
			t.Fatalf("round %d: burned domain y was selected (%q)", round, sni.host)
		}
	}
}

func TestPoolAdvanceReportsRealMove(t *testing.T) {

	p := newWSPool([]string{"a", "b"}, snis("x", "y"), "")
	for i := 0; i < 4; i++ {
		if !p.advance() {
			t.Fatalf("healthy 2x2 pool: advance() must report a move (step %d)", i)
		}
	}

	p2 := newWSPool([]string{"a", "b", "c"}, snis("x"), "")
	p2.markSuspect("ip", "b", "test")
	p2.markSuspect("ip", "c", "test")
	ipBefore, _, ok := p2.current()
	if !ok || ipBefore != "a" {
		t.Fatalf("only a is healthy; got ip=%q ok=%v", ipBefore, ok)
	}
	for i := 0; i < 5; i++ {
		if p2.advance() {
			t.Fatalf("single healthy edge: advance() must report no move (step %d)", i)
		}
		if ip, _, _ := p2.current(); ip != "a" {
			t.Fatalf("single healthy edge: must stay on a, got %q", ip)
		}
	}

	p2.retestResult("ip", "b", true)
	if !p2.advance() {
		t.Fatal("after edge b healed, advance() must report a move again")
	}

	p3 := newWSPool([]string{"a"}, snis("x"), "")
	if p3.advance() {
		t.Fatal("1x1 pool: advance() must report no move")
	}

	p4 := newWSPool(nil, nil, "")
	if p4.advance() {
		t.Fatal("empty pool: advance() must report no move")
	}
}

func TestPoolRotatesAllCombos(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), "")
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		ip, sni, ok := p.current()
		if !ok {
			t.Fatal("pool empty unexpectedly")
		}
		seen[ip+"|"+sni.host] = true
		p.advance()
	}
	for _, want := range []string{"a|x", "a|y", "b|x", "b|y"} {
		if !seen[want] {
			t.Fatalf("combo %s never selected; got %v", want, seen)
		}
	}
}

func TestPoolUpdateECHTransitionGate(t *testing.T) {
	p := newWSPool([]string{"a"}, snis("x", "y"), "")
	fresh := []byte{1, 2, 3}

	if !p.updateECH("x", fresh) {
		t.Fatal("first updateECH should report a change")
	}
	if _, sni, _ := p.current(); string(sni.ech) != string(fresh) {
		t.Fatalf("current() should carry the persisted key, got %v", sni.ech)
	}

	if p.updateECH("x", fresh) {
		t.Fatal("repeat updateECH with an unchanged key must report no change (suppresses repeat events)")
	}

	if !p.updateECH("x", []byte{9, 9}) {
		t.Fatal("updateECH with a rotated key should report a change")
	}

	if p.updateECH("zzz", fresh) {
		t.Fatal("updateECH for an absent host must report no change")
	}

	if p.snis[1].host != "y" || p.snis[1].ech != nil {
		t.Fatalf("sibling SNI y should be untouched, got %#v", p.snis[1])
	}
}

func TestPoolDownReconnectPairing(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), "")

	p.setActive("a · x")
	if len(p.events) != 0 {
		t.Fatalf("initial connect must emit no event, got %+v", p.events)
	}

	p.down("reset", "a · x")
	p.setActive("b · x")
	if len(p.events) != 2 || p.events[0].Kind != "down" || p.events[1].Kind != "up" || p.events[1].Code != "reconnect" {
		t.Fatalf("want down then up/reconnect, got %+v", p.events)
	}

	p.setActive("a · x")
	if len(p.events) != 2 {
		t.Fatalf("rotation without a pending down must be silent, got %d events", len(p.events))
	}

	p.down("throttle", "a · x")
	p.setActive("a · x")
	if len(p.events) != 4 || p.events[3].Kind != "up" {
		t.Fatalf("a same-edge reconnect after a down must still emit up, got %+v", p.events)
	}
}

func TestMarkSuspectPullsFromRotation(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), "")
	p.markSuspect("ip", "a", "test")
	if r := p.ipHealth.recs["a"]; r == nil || r.state != stateSuspect || r.fails != 0 {
		t.Fatalf("a should be suspect with fails=0, got %#v", r)
	}
	for i := 0; i < 5; i++ {
		ip, _, ok := p.current()
		if !ok || ip != "b" {
			t.Fatalf("suspect a must be skipped while b is healthy; got ip=%q ok=%v", ip, ok)
		}
		p.advance()
	}
}

func TestSuspectBackoffThenDead(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x"), "")
	p.markSuspect("ip", "a", "test")
	if got := p.ipHealth.recs["a"].nextRetest; got != *now+suspectBackoff[0] {
		t.Fatalf("entry retest should be now+%d, got %d (now=%d)", suspectBackoff[0], got, *now)
	}
	wantNext := suspectBackoff[1:]
	for i, w := range wantNext {
		p.retestResult("ip", "a", false)
		r := p.ipHealth.recs["a"]
		if r.state != stateSuspect {
			t.Fatalf("retest %d: still suspect expected, got %q", i+1, r.state)
		}
		if r.fails != i+1 {
			t.Fatalf("retest %d: fails=%d, want %d", i+1, r.fails, i+1)
		}
		if r.nextRetest != *now+w {
			t.Fatalf("retest %d: nextRetest=%d, want %d", i+1, r.nextRetest, *now+w)
		}
	}

	p.retestResult("ip", "a", false)
	r := p.ipHealth.recs["a"]
	if r.state != stateDead || r.nextRetest != *now+deadRetest {
		t.Fatalf("expected dead at now+%d, got state=%q next=%d", deadRetest, r.state, r.nextRetest)
	}

	*now = 5000
	p.retestResult("ip", "a", false)
	if r := p.ipHealth.recs["a"]; r.state != stateDead || r.nextRetest != 5000+deadRetest {
		t.Fatalf("dead entry should stay dead at 5000+%d, got state=%q next=%d", deadRetest, r.state, r.nextRetest)
	}
}

func TestARetestNeverHealsAnEdge(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x"), "")
	p.markSuspect("ip", "a", "test")
	base := len(p.events)

	p.retestResult("ip", "a", false)
	if len(p.events) != base {
		t.Fatalf("a failed retest must not emit an event, got %+v", p.events[base:])
	}

	p.retestResult("ip", "a", true)
	if p.ipHealth.rec("a") == nil {
		t.Fatal("a passing retest CLEARED the burn — only the tun probe, which watches DATA cross, may " +
			"readmit an edge")
	}
	if !p.ipHealth.due("a") {
		t.Fatal("a passing retest must at least make the edge DUE, or the rotation never hands it live " +
			"traffic and the tun probe never gets to judge it")
	}
	for _, e := range p.events[base:] {
		if e.Kind == "heal" {
			t.Fatalf("a retest announced a heal: %+v", e)
		}
	}
	if len(p.events) != base+1 || p.events[base].Kind != "pool" || p.events[base].Code != "restored" {
		t.Fatalf("want exactly one pool/restored — the rotation can reach both edges again — got %+v",
			p.events[base:])
	}

	n := len(p.events)
	p.retestResult("ip", "a", true)
	if len(p.events) != n {
		t.Fatalf("a repeat retest must be silent, got %+v", p.events[n:])
	}
}

func TestASuccessfulRetestOffersALiveTryItDoesNotHeal(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x"), "")
	p.markSuspect("ip", "a", "test")
	p.retestResult("ip", "a", false)
	if p.ipHealth.due("a") {
		t.Fatal("a FAILED retest must push the wait out, not leave it due")
	}
	p.retestResult("ip", "a", true)
	if p.ipHealth.recs["a"] == nil {
		t.Fatal("a passing probe healed the entry — only the tun probe may do that; a control handshake " +
			"says nothing about whether DATA crosses")
	}
	if !p.ipHealth.due("a") {
		t.Fatal("a passing probe must leave the entry DUE, so current()'s pass 2 can offer it live traffic")
	}

	p.clearBurn("ip", "a")
	if p.ipHealth.recs["a"] != nil {
		t.Fatal("clearBurn is the tun probe's cmdOK path and must clear outright")
	}
	_ = now
}

func TestCurrentFallbackLeastBad(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x", "y"), "")

	p.ipHealth.recs["a"] = &healthRec{state: stateDead, nextRetest: 1005}
	p.ipHealth.recs["b"] = &healthRec{state: stateSuspect, nextRetest: 1100}
	p.sniHealth.recs["x"] = &healthRec{state: stateSuspect, nextRetest: 1050}
	p.sniHealth.recs["y"] = &healthRec{state: stateDead, nextRetest: 1010}
	ip, sni, ok := p.current()
	if !ok {
		t.Fatal("fallback must still return a combo")
	}
	if ip != "b" || sni.host != "x" {
		t.Fatalf("least-bad should prefer suspect over dead: want b/x, got %s/%s", ip, sni.host)
	}

	p.ipHealth.recs["a"] = &healthRec{state: stateSuspect, nextRetest: 1005}
	p.ipHealth.recs["b"] = &healthRec{state: stateSuspect, nextRetest: 1100}
	if ip, _, _ := p.current(); ip != "a" {
		t.Fatalf("same-tier tiebreak should pick soonest retest a, got %s", ip)
	}
}

func TestStatusSnapshotStates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "st.json")
	p, now := clockPool([]string{"a", "b"}, snis("x"), path)
	p.current()
	p.markSuspect("ip", "a", "test")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("status file not written: %v", err)
	}
	var st struct {
		Active string `json:"active"`
		Health []struct {
			Key        string `json:"key"`
			Kind       string `json:"kind"`
			State      string `json:"state"`
			Fails      int    `json:"fails"`
			NextRetest int64  `json:"next_retest_unix"`
		} `json:"health"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("bad status json: %v", err)
	}
	got := map[string]string{}
	var aNext int64
	for _, h := range st.Health {
		got[h.Kind+":"+h.Key] = h.State
		if h.Kind == "ip" && h.Key == "a" {
			aNext = h.NextRetest
		}
	}
	if got["ip:a"] != stateSuspect || got["ip:b"] != "healthy" || got["sni:x"] != "healthy" {
		t.Fatalf("health states wrong: %v", got)
	}
	if aNext != *now+suspectBackoff[0] {
		t.Fatalf("suspect a next_retest_unix=%d, want %d", aNext, *now+suspectBackoff[0])
	}
	if len(st.Health) != 3 {
		t.Fatalf("health should list every pool entry (2 ips + 1 sni), got %d", len(st.Health))
	}
}

func TestDueRetestsAndProbeAllNow(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x", "y"), "")
	p.markSuspect("ip", "a", "test")
	if due := p.dueRetests(); len(due) != 0 {
		t.Fatalf("nothing should be due yet, got %v", due)
	}
	p.probeAllNow()
	due := p.dueRetests()
	if len(due) != 1 || due[0].kind != "ip" || due[0].key != "a" {
		t.Fatalf("probeAllNow should make the suspect due, got %v", due)
	}
	if due[0].ip != "a" {
		t.Fatalf("retest spec should dial the entry itself, got %q", due[0].ip)
	}
	if p.sniHealth.recs[due[0].sni.host] != nil {
		t.Fatalf("retest partner SNI must be healthy, got %q", due[0].sni.host)
	}

	p2, now2 := clockPool([]string{"a"}, snis("x"), "")
	p2.markSuspect("ip", "a", "test")
	*now2 = *now + suspectBackoff[0] + 1
	if due := p2.dueRetests(); len(due) != 1 {
		t.Fatalf("entry should be due once its backoff elapses, got %v", due)
	}
}

func TestSelectEntryPinsAndClears(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), "")
	p.markSuspect("ip", "b", "test")
	if !p.selectEntry("ip", "b") {
		t.Fatal("selectEntry should find b")
	}
	if p.ipHealth.recs["b"] != nil {
		t.Fatal("selecting b must clear its suspect mark")
	}
	if ip, _, ok := p.current(); !ok || ip != "b" {
		t.Fatalf("current() should now return the selected b, got %q ok=%v", ip, ok)
	}
	if p.selectEntry("ip", "does-not-exist") {
		t.Fatal("selectEntry must return false for an unknown key")
	}
}

func TestPinOneShot(t *testing.T) {
	p, _ := clockPool([]string{"a", "b", "c"}, snis("x", "y"), "")
	p.markSuspect("sni", "x", "test")
	p.markSuspect("ip", "a", "test")
	if !p.selectEntry("ip", "c") {
		t.Fatal("selectEntry should find c")
	}
	if !p.isPinned() {
		t.Fatal("pool should report pinned right after selectEntry")
	}

	for i := 0; i < 6; i++ {
		if ip, _, ok := p.current(); !ok || ip != "c" {
			t.Fatalf("pin must force ip=c on dial %d, got %q ok=%v", i, ip, ok)
		}
		p.advance()
		p.advanceIP()
	}
	p.markSuspect("ip", "b", "test")
	if ip, _, _ := p.current(); ip != "c" {
		t.Fatalf("a burn of a non-pinned edge must not override the pin, got %q", ip)
	}

	for i := 1; i < pinFailRelease; i++ {
		p.pinAttemptFailed("c", "")
		if !p.isPinned() {
			t.Fatalf("attempt %d of %d released the pin — one failure is not evidence", i, pinFailRelease)
		}
	}
	p.pinAttemptFailed("c", "")
	if p.isPinned() {
		t.Fatalf("after %d failed attempts the pin must no longer be honoured", pinFailRelease)
	}
	p.current()
	if p.pinIP != "" {
		t.Fatalf("expired pin not cleared: pinIP=%q", p.pinIP)
	}
}

func TestPinReleasesOnProvenBlock(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x"), "")
	if !p.selectEntry("ip", "b") {
		t.Fatal("selectEntry should find b")
	}
	if ip, _, _ := p.current(); ip != "b" {
		t.Fatalf("pin must force b, got %q", ip)
	}

	p.markSuspect("ip", "b", "tun-probe")
	if !p.isPinned() {
		t.Fatal("one burn released the pin — the operator's pick costs a second opinion to override")
	}

	p.releasePin()
	if p.isPinned() || p.pinIP != "" {
		t.Fatalf("pin state not cleared: pinIP=%q", p.pinIP)
	}

	if ip, _, ok := p.current(); !ok || ip != "a" {
		t.Fatalf("after the pin released, current() must fall back to healthy a, got %q ok=%v", ip, ok)
	}

	got := 0
	p.mu.Lock()
	for _, e := range p.events {
		if e.Kind == "pool" && e.Code == "pin_dropped" {
			got++
		}
	}
	p.mu.Unlock()
	if got != 1 {
		t.Fatalf("want exactly one pool/pin_dropped event, got %d", got)
	}
}

func TestPinHeldOnGuiltyPartnerAxis(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x", "y"), "")
	if !p.selectEntry("ip", "b") {
		t.Fatal("selectEntry should find b")
	}
	p.markSuspect("sni", "x", "sni_blocked")
	if !p.isPinned() || p.pinIP != "b" {
		t.Fatalf("burning the free (SNI) axis must not release an IP pin: pinIP=%q pinned=%v", p.pinIP, p.isPinned())
	}
	if ip, sni, _ := p.current(); ip != "b" || sni.host == "x" {
		t.Fatalf("current() must keep pinned ip=b and heal off the guilty sni x, got ip=%q sni=%q", ip, sni.host)
	}
}

func TestAdvanceIPAndSNIIndependently(t *testing.T) {
	p := newWSPool([]string{"a", "b", "c"}, snis("x", "y"), "")
	ip0, sni0, _ := p.current()
	if ip0 != "a" || sni0.host != "x" {
		t.Fatalf("start = %s/%s, want a/x", ip0, sni0.host)
	}
	p.advanceIP()
	ip1, sni1, _ := p.current()
	if ip1 != "b" || sni1.host != "x" {
		t.Fatalf("after advanceIP = %s/%s, want b/x (SNI unchanged)", ip1, sni1.host)
	}
	p.advanceSNI()
	ip2, sni2, _ := p.current()
	if ip2 != "b" || sni2.host != "y" {
		t.Fatalf("after advanceSNI = %s/%s, want b/y (IP unchanged)", ip2, sni2.host)
	}
	p.advanceIP()
	p.advanceIP()
	ip3, _, _ := p.current()
	if ip3 != "a" {
		t.Fatalf("after wrap = %s, want a", ip3)
	}
}
