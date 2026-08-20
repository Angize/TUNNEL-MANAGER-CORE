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

	p2.clearBurn("ip", "b")
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

func TestABurnDeepensOnlyOnceThePreviousWaitIsSpent(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x"), "")
	p.markSuspect("ip", "a", "test")
	if got := p.ipHealth.recs["a"].nextRetest; got != *now+suspectBackoff[0] {
		t.Fatalf("entry retest should be now+%d, got %d (now=%d)", suspectBackoff[0], got, *now)
	}

	p.markSuspect("ip", "a", "test")
	if r := p.ipHealth.recs["a"]; r.fails != 0 || r.nextRetest != *now+suspectBackoff[0] {
		t.Fatalf("a second verdict inside the SAME wait deepened the backoff (fails=%d next=%d): the "+
			"edge would reach dead in seconds on one outage", r.fails, r.nextRetest-*now)
	}

	for i, w := range suspectBackoff[1:] {
		*now = p.ipHealth.recs["a"].nextRetest
		p.markSuspect("ip", "a", "test")
		r := p.ipHealth.recs["a"]
		if r.state != stateSuspect {
			t.Fatalf("burn %d: still suspect expected, got %q", i+1, r.state)
		}
		if r.fails != i+1 {
			t.Fatalf("burn %d: fails=%d, want %d", i+1, r.fails, i+1)
		}
		if r.nextRetest != *now+w {
			t.Fatalf("burn %d: nextRetest=%d, want %d", i+1, r.nextRetest-*now, w)
		}
	}

	*now = p.ipHealth.recs["a"].nextRetest
	p.markSuspect("ip", "a", "test")
	r := p.ipHealth.recs["a"]
	if r.state != stateDead || r.nextRetest != *now+deadRetest {
		t.Fatalf("expected dead at now+%d, got state=%q next=%d", deadRetest, r.state, r.nextRetest-*now)
	}

	*now = r.nextRetest
	p.markSuspect("ip", "a", "test")
	if r := p.ipHealth.recs["a"]; r.state != stateDead || r.nextRetest != *now+deadRetest {
		t.Fatalf("dead entry should stay dead at now+%d, got state=%q next=%d", deadRetest, r.state,
			r.nextRetest-*now)
	}
}

func TestNothingButTheTunProbeReadmitsABurnedEdge(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x"), "")
	p.markSuspect("ip", "a", "test")
	base := len(p.events)

	if p.ipHealth.due("a") {
		t.Fatal("a fresh burn must not be due -- the wait is the whole point of the backoff")
	}

	*now += suspectBackoff[0] + 1
	if p.ipHealth.healthy("a") {
		t.Fatal("the wait elapsing HEALED the edge. Nothing inside the pool may readmit an edge on a " +
			"clock: only the tun probe, which watches DATA cross, has evidence")
	}
	if !p.ipHealth.due("a") {
		t.Fatal("the wait elapsed and the edge is still not due, so the rotation never hands it live " +
			"traffic and the tun probe never gets to judge it")
	}
	if len(p.events) != base {
		t.Fatalf("time passing announced something: %+v", p.events[base:])
	}

	if !p.clearBurn("ip", "a") {
		t.Fatal("clearBurn is the tun probe's cmdOK path and must report it cleared something")
	}
	if !p.ipHealth.healthy("a") {
		t.Fatal("clearBurn left the record behind")
	}
	if n := len(p.events); n != base+1 || p.events[base].Kind != "pool" || p.events[base].Code != "restored" {
		t.Fatalf("want exactly one pool/restored -- the rotation can reach both edges again -- got %+v",
			p.events[base:])
	}
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

func TestProbeAllNowEndsEveryWait(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x", "y"), "")
	p.markSuspect("ip", "a", "test")
	p.markSuspect("sni", "x", "test")
	if p.ipHealth.due("a") || p.sniHealth.due("x") {
		t.Fatal("nothing should be due yet")
	}

	p.probeAllNow()
	if !p.ipHealth.due("a") || !p.sniHealth.due("x") {
		t.Fatal("probeAllNow must end the wait on BOTH axes -- it is the operator saying try everything now")
	}
	if p.ipHealth.healthy("a") || p.sniHealth.healthy("x") {
		t.Fatal("probeAllNow CLEARED a burn; it may only end the wait, and the tun probe decides the rest")
	}

	p2, now2 := clockPool([]string{"a"}, snis("x"), "")
	p2.markSuspect("ip", "a", "test")
	*now2 = *now + suspectBackoff[0] + 1
	if !p2.ipHealth.due("a") {
		t.Fatal("entry should be due once its backoff elapses")
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
	if !p.ipHealth.healthy("b") {
		t.Fatal("the burn landed on the pinned edge; while the pin is in force the pin's own counter is " +
			"what ends it")
	}

	p.releasePin()
	if p.isPinned() || p.pinIP != "" {
		t.Fatalf("pin state not cleared: pinIP=%q", p.pinIP)
	}

	p.markSuspect("ip", "b", "tun-probe")
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
