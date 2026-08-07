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

// clockPool builds a pool with an injectable clock so the FSM's scheduling is deterministic.
// The returned pointer is the "now" value; bump it to advance time.
func clockPool(ips []string, snis []wsSNIEntry, autoBurn bool, statusPath string) (*wsPool, *int64) {
	p := newWSPool(ips, snis, autoBurn, statusPath)
	var now int64 = 1000
	p.now = func() int64 { return now }
	return p, &now
}

// TestWSPoolStandbyNeverCollidesWithActive checks the warm-standby edge selection: however many times the
// standby is rebuilt — a CDN reaps the idle one, over and over — it is always aimed at a DIFFERENT IP
// than the live active edge, so a proactive rotation always moves to a real, distinct edge instead of
// silently promoting onto the active's own. Regression for "rotation stopped / both edges are the same".
func TestWSPoolStandbyNeverCollidesWithActive(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), true, "")
	standbyIP := func() string { // mimic warmEstablish(standby): aim, then read the edge via current()
		p.aimStandby()
		ip, _, ok := p.current()
		if !ok {
			t.Fatal("current() returned not-ok on a healthy 2-IP pool")
		}
		return ip
	}
	for _, active := range []string{"a", "b"} {
		p.setActive(activeLabel(active, "x"))
		for round := 0; round < 20; round++ { // the CDN keeps reaping + rebuilding the idle standby
			if got := standbyIP(); got == active {
				t.Fatalf("active=%s: standby collided with the active edge on rebuild %d", active, round)
			}
		}
	}
	// Three IPs: the standby must still never be the active, and should still be a healthy edge.
	p3 := newWSPool([]string{"a", "b", "c"}, snis("x"), true, "")
	for _, active := range []string{"a", "b", "c"} {
		p3.setActive(activeLabel(active, "x"))
		for round := 0; round < 12; round++ {
			p3.aimStandby()
			ip, _, ok := p3.current()
			if !ok || ip == active {
				t.Fatalf("3-IP active=%s: standby landed on the active (%q) on rebuild %d", active, ip, round)
			}
		}
	}
}

// TestWSPoolStandbyVariesSNI: with warm standby on a HEALTHY pool, successive standby builds must
// exercise the SNI axis as well as the IP axis. aimStandby's IP-anchoring path used to write only the
// IP cursor and return, so the domain never changed and rotation silently degraded to IP-only — a
// flagged domain could never be rotated off, and the one reused SNI stayed a stable fingerprint.
func TestWSPoolStandbyVariesSNI(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
	p.setActive(activeLabel("a", "x")) // live edge: IP a, domain x
	seen := map[string]bool{}
	for round := 0; round < 8; round++ { // the CDN keeps reaping + rebuilding the idle standby
		p.aimStandby()
		ip, sni, ok := p.current()
		if !ok {
			t.Fatal("current() returned not-ok on a healthy 2x2 pool")
		}
		if ip == "a" {
			t.Fatalf("round %d: standby collided with the active IP", round)
		}
		seen[sni.host] = true
	}
	if !seen["x"] || !seen["y"] {
		t.Fatalf("standby never varied the SNI axis; saw %v", seen)
	}

	// A burned domain must be skipped, not parked on: with y suspect, every build stays on x.
	p2 := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
	p2.setActive(activeLabel("a", "x"))
	p2.markSuspect("sni", "y", "test")
	for round := 0; round < 4; round++ {
		p2.aimStandby()
		if _, sni, _ := p2.current(); sni.host != "x" {
			t.Fatalf("round %d: burned domain y was selected (%q)", round, sni.host)
		}
	}
}

// TestPoolAdvanceReportsRealMove pins advance()'s contract: it reports whether the edge the carrier would
// actually DIAL changed, not whether the raw cursor moved — the cursor always moves. The rotation timer
// uses this to avoid tearing a healthy connection down when every other combination is burned, the common
// "one edge survived the filter" state, where a blind close costs a re-dial every interval for nothing.
func TestPoolAdvanceReportsRealMove(t *testing.T) {
	// Healthy multi-edge pool: a step reaches a different combo, so advance() reports a real move.
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
	for i := 0; i < 4; i++ {
		if !p.advance() {
			t.Fatalf("healthy 2x2 pool: advance() must report a move (step %d)", i)
		}
	}

	// Burn everything except one IP: every step resolves back to that same survivor, so advance()
	// must report NO move and the timer must leave the live connection alone.
	p2 := newWSPool([]string{"a", "b", "c"}, snis("x"), true, "")
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

	// A burned ws edge is offered live traffic again once its wait elapses — current() has the same
	// "a DUE burned entry gets a live retry" pass PeerPool does, because that live try is the only way
	// the tun probe can ever judge it. A passing retest just brings that moment forward.
	p2.retestResult("ip", "b", true)
	if !p2.advance() {
		t.Fatal("after edge b healed, advance() must report a move again")
	}

	// A single-combo pool can never move.
	p3 := newWSPool([]string{"a"}, snis("x"), true, "")
	if p3.advance() {
		t.Fatal("1x1 pool: advance() must report no move")
	}

	// An empty pool is not a move either (and must not panic).
	p4 := newWSPool(nil, nil, true, "")
	if p4.advance() {
		t.Fatal("empty pool: advance() must report no move")
	}
}

func TestPoolRotatesAllCombos(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
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

// updateECH persists a self-healed ECH key onto the matching pool SNI and reports a real change
// exactly once, so the self-heal event fires per rotation (first heal) not per reconnect (repeats).
func TestPoolUpdateECHTransitionGate(t *testing.T) {
	p := newWSPool([]string{"a"}, snis("x", "y"), true, "")
	fresh := []byte{1, 2, 3}
	// first heal on x: stored key (nil) differs -> change reported, key persisted
	if !p.updateECH("x", fresh) {
		t.Fatal("first updateECH should report a change")
	}
	if _, sni, _ := p.current(); string(sni.ech) != string(fresh) {
		t.Fatalf("current() should carry the persisted key, got %v", sni.ech)
	}
	// same key again (next reconnect uses the fresh key, or a concurrent healer) -> no change, no event
	if p.updateECH("x", fresh) {
		t.Fatal("repeat updateECH with an unchanged key must report no change (suppresses repeat events)")
	}
	// a later rotation delivers a different key -> change reported again
	if !p.updateECH("x", []byte{9, 9}) {
		t.Fatal("updateECH with a rotated key should report a change")
	}
	// unknown host -> no change (never panics, never mislabels)
	if p.updateECH("zzz", fresh) {
		t.Fatal("updateECH for an absent host must report no change")
	}
	// the other SNI stays untouched
	if p.snis[1].host != "y" || p.snis[1].ech != nil {
		t.Fatalf("sibling SNI y should be untouched, got %#v", p.snis[1])
	}
}

// A genuine pool down must be balanced by exactly one paired "up"/reconnect on the next
// successful (re)connect, while the initial connect and plain rotations stay silent — so the panel
// never shows an unbalanced "disconnected" for a tunnel that recovered.
func TestPoolDownReconnectPairing(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), true, "")

	p.setActive("a · x") // initial connect: no prior down -> silent
	if len(p.events) != 0 {
		t.Fatalf("initial connect must emit no event, got %+v", p.events)
	}

	p.down("reset", "a · x") // genuine drop
	p.setActive("b · x")     // reconnect on a new edge -> paired up
	if len(p.events) != 2 || p.events[0].Kind != "down" || p.events[1].Kind != "up" || p.events[1].Code != "reconnect" {
		t.Fatalf("want down then up/reconnect, got %+v", p.events)
	}

	p.setActive("a · x") // a plain rotation (no pending down) must NOT emit an up
	if len(p.events) != 2 {
		t.Fatalf("rotation without a pending down must be silent, got %d events", len(p.events))
	}

	p.down("throttle", "a · x") // a second drop
	p.setActive("a · x")        // reconnect on the SAME edge still pairs
	if len(p.events) != 4 || p.events[3].Kind != "up" {
		t.Fatalf("a same-edge reconnect after a down must still emit up, got %+v", p.events)
	}
}

// A verdict of IP_GUILTY (applied via markSuspect) moves a healthy IP into suspect, and
// current() then skips it while a healthy alternative remains.
func TestMarkSuspectPullsFromRotation(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), true, "")
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

// The suspect backoff walks the whole configured schedule (as nextRetest deltas), one step per failed
// retest, then drops to dead when it runs off the end (the initial markSuspect is failure #1). Read off
// suspectBackoff rather than its literals, so retuning the schedule cannot look like a regression here.
func TestSuspectBackoffThenDead(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x"), true, "")
	p.markSuspect("ip", "a", "test")
	if got := p.ipHealth.recs["a"].nextRetest; got != *now+suspectBackoff[0] {
		t.Fatalf("entry retest should be now+%d, got %d (now=%d)", suspectBackoff[0], got, *now)
	}
	wantNext := suspectBackoff[1:] // deltas after each failed retest, up to the last step
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
	// One more failed retest runs off the end of the schedule -> dead on the slow interval.
	p.retestResult("ip", "a", false)
	r := p.ipHealth.recs["a"]
	if r.state != stateDead || r.nextRetest != *now+deadRetest {
		t.Fatalf("expected dead at now+%d, got state=%q next=%d", deadRetest, r.state, r.nextRetest)
	}
	// A dead entry's failed retest stays dead and reschedules on the slow interval from now.
	*now = 5000
	p.retestResult("ip", "a", false)
	if r := p.ipHealth.recs["a"]; r.state != stateDead || r.nextRetest != 5000+deadRetest {
		t.Fatalf("dead entry should stay dead at 5000+%d, got state=%q next=%d", deadRetest, r.state, r.nextRetest)
	}
}

// A background retest is no longer a verdict: it decides only WHEN an entry is next worth a live try. So a
// passing one must not heal anything — the probe completes TCP, TLS and the WebSocket upgrade, and a path
// that passes all three can still carry nothing, which is the exact signal this pool spent its history
// mistaking for health. What it may do is make the entry DUE, so the rotation hands it real traffic and
// the node's tun probe decides. The pool-level "the rotation can reach two edges again" transition is
// still logged, because that is a fact about the POOL, not a claim about the edge.
func TestARetestNeverHealsAnEdge(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x"), true, "")
	p.markSuspect("ip", "a", "test") // emits burn + pool/degraded
	base := len(p.events)

	p.retestResult("ip", "a", false) // failed retest — nothing to say
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
	// A repeat says nothing new: the entry was already due.
	n := len(p.events)
	p.retestResult("ip", "a", true)
	if len(p.events) != n {
		t.Fatalf("a repeat retest must be silent, got %+v", p.events[n:])
	}
}

// A successful retest does NOT heal. The probe completes the control path -- TCP, TLS, the WebSocket
// upgrade -- and a path that passes all three can still carry nothing, which is the exact signal this
// pool spent its history mistaking for health. So it only says "worth a live try": the entry stays
// tracked and becomes DUE, current()'s pass 2 offers it real traffic, and the tun probe decides.
func TestASuccessfulRetestOffersALiveTryItDoesNotHeal(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x"), true, "")
	p.markSuspect("ip", "a", "test")
	p.retestResult("ip", "a", false) // suspect, fails=1 -> a longer wait
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
	// ...and the ONLY thing that heals it is the node's verdict.
	p.clearBurn("ip", "a")
	if p.ipHealth.recs["a"] != nil {
		t.Fatal("clearBurn is the tun probe's cmdOK path and must clear outright")
	}
	_ = now
}

// current() never dead-ends: with nothing fully healthy it returns the least-bad combo —
// suspect preferred over dead, then soonest nextRetest.
func TestCurrentFallbackLeastBad(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x", "y"), true, "")
	// a dead (sooner) vs b suspect (later); x suspect (later) vs y dead (sooner).
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
	// Within the same tier, the soonest nextRetest wins.
	p.ipHealth.recs["a"] = &healthRec{state: stateSuspect, nextRetest: 1005}
	p.ipHealth.recs["b"] = &healthRec{state: stateSuspect, nextRetest: 1100}
	if ip, _, _ := p.current(); ip != "a" {
		t.Fatalf("same-tier tiebreak should pick soonest retest a, got %s", ip)
	}
}

// The status snapshot carries the full per-entry FSM state — key/kind/state/fails/next_retest — which
// is everything the node and panel read.
func TestStatusSnapshotStates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "st.json")
	p, now := clockPool([]string{"a", "b"}, snis("x"), true, path)
	p.current() // sets active
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
	got := map[string]string{} // key -> state
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

// dueRetests reports only entries whose backoff has elapsed; once it has, the entry becomes due and is
// paired with a healthy partner on the other axis. probeAllNow is the operator's way to pull that
// forward (the panel's control arrives as a signal, which carries no key).
func TestDueRetestsAndProbeAllNow(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x", "y"), true, "")
	p.markSuspect("ip", "a", "test") // due at now+30
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
	// After the backoff elapses on the clock, it is due with no operator action at all.
	p2, now2 := clockPool([]string{"a"}, snis("x"), true, "")
	p2.markSuspect("ip", "a", "test")
	*now2 = *now + suspectBackoff[0] + 1
	if due := p2.dueRetests(); len(due) != 1 {
		t.Fatalf("entry should be due once its backoff elapses, got %v", due)
	}
}

// altHealthy* feed the differential probe: they return a healthy partner on the other axis,
// excluding the failed one, and report false when none exists.
func TestAltHealthyLookups(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
	if s, ok := p.altHealthySNI("x"); !ok || s.host != "y" {
		t.Fatalf("altHealthySNI(x) = %q ok=%v, want y", s.host, ok)
	}
	if ip, ok := p.altHealthyIP("a"); !ok || ip != "b" {
		t.Fatalf("altHealthyIP(a) = %q ok=%v, want b", ip, ok)
	}
	p.markSuspect("sni", "y", "test") // now y is not healthy
	if _, ok := p.altHealthySNI("x"); ok {
		t.Fatal("no healthy SNI other than x should remain")
	}
}

// selectEntry pins a specific edge: it moves the index onto that entry and clears any
// suspect/dead mark so current() picks it, even if it was blocked a moment ago.
func TestSelectEntryPinsAndClears(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), true, "")
	p.markSuspect("ip", "b", "test") // b was blocked
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

// TestPinOneShot locks down a pin as a ONE-SHOT exact jump: while it is in force it FORCES exactly the
// chosen edge — no drift onto a neighbour, even across advance() or a suspect partner — and once the
// core has disproven it, it clears so normal rotation resumes. It does NOT lock forever. A PROVEN burn of
// the pinned edge is covered separately by TestPinReleasesOnProvenBlock.
func TestPinOneShot(t *testing.T) {
	p, _ := clockPool([]string{"a", "b", "c"}, snis("x", "y"), true, "")
	p.markSuspect("sni", "x", "test") // messy partner axis
	p.markSuspect("ip", "a", "test")
	if !p.selectEntry("ip", "c") {
		t.Fatal("selectEntry should find c")
	}
	if !p.isPinned() {
		t.Fatal("pool should report pinned right after selectEntry")
	}
	// Within the window: current() forces c every time, across rotation attempts — the pin does not
	// drift onto a neighbour just because advance()/advanceIP() stepped the index or the partner axis
	// is suspect. (Burning a DIFFERENT edge must also not move it off c.)
	for i := 0; i < 6; i++ {
		if ip, _, ok := p.current(); !ok || ip != "c" {
			t.Fatalf("pin must force ip=c on dial %d, got %q ok=%v", i, ip, ok)
		}
		p.advance()
		p.advanceIP()
	}
	p.markSuspect("ip", "b", "test") // burning a non-pinned edge must not disturb the pin
	if ip, _, _ := p.current(); ip != "c" {
		t.Fatalf("a burn of a non-pinned edge must not override the pin, got %q", ip)
	}
	// It is not sticky-forever: without a land, the core's own failed attempts release it (c was never
	// burned, so this is the cannot-land path; the proven-block one is TestPinReleasesOnProvenBlock).
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

// TestPinReleasesOnProvenBlock locks in the pin-safety rule at the POOL level: pinning an edge that
// turns out to be genuinely blocked must not hang the tunnel for the whole pinTTL. WHEN that release
// happens is the verdict path's call and is asserted in pin_is_a_preference_test.go (after
// pinFailRelease proven-dead rounds, the same second opinion every other carrier asks for). What this
// one pins is the release itself: both axes cleared, the fallback immediate, and exactly one event.
//
// It used to assert that markSuspect released the pin by itself, which made ONE measurement override the
// operator while udp/raw/flux wanted two.
func TestPinReleasesOnProvenBlock(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x"), true, "")
	if !p.selectEntry("ip", "b") { // operator jumps onto b
		t.Fatal("selectEntry should find b")
	}
	if ip, _, _ := p.current(); ip != "b" {
		t.Fatalf("pin must force b, got %q", ip)
	}
	// A burn ALONE must not break the operator's pick any more.
	p.markSuspect("ip", "b", "tun-probe")
	if !p.isPinned() {
		t.Fatal("one burn released the pin — the operator's pick costs a second opinion to override")
	}

	p.releasePin() // what the verdict path calls once the pin has absorbed its rounds
	if p.isPinned() || p.pinIP != "" {
		t.Fatalf("pin state not cleared: pinIP=%q", p.pinIP)
	}
	// Recovery is immediate: current() now returns the healthy edge a, not the blocked pinned b.
	if ip, _, ok := p.current(); !ok || ip != "a" {
		t.Fatalf("after the pin released, current() must fall back to healthy a, got %q ok=%v", ip, ok)
	}
	// The release is surfaced to the operator as a pool/pin_dropped event.
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

// TestPinHeldOnGuiltyPartnerAxis proves the release is axis-precise: an IP-pin must SURVIVE a burn
// of a guilty SNI (the free axis), so current() keeps the pinned IP and just heals the SNI around it.
func TestPinHeldOnGuiltyPartnerAxis(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x", "y"), true, "")
	if !p.selectEntry("ip", "b") {
		t.Fatal("selectEntry should find b")
	}
	p.markSuspect("sni", "x", "sni_blocked") // the SNI is guilty, not the pinned IP
	if !p.isPinned() || p.pinIP != "b" {
		t.Fatalf("burning the free (SNI) axis must not release an IP pin: pinIP=%q pinned=%v", p.pinIP, p.isPinned())
	}
	if ip, sni, _ := p.current(); ip != "b" || sni.host == "x" {
		t.Fatalf("current() must keep pinned ip=b and heal off the guilty sni x, got ip=%q sni=%q", ip, sni.host)
	}
}

func TestAutoBurnOffNoTracking(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), false, "") // manual-only
	p.markSuspect("ip", "a", "test")                         // must NOT track
	if p.ipHealth.recs["a"] != nil {
		t.Fatalf("autoBurn=off must not sideline an entry, got %#v", p.ipHealth.recs["a"])
	}
	got := map[string]bool{}
	for i := 0; i < 4; i++ {
		ip, _, ok := p.current()
		if !ok {
			t.Fatal("pool empty with autoBurn off")
		}
		got[ip] = true
		p.advance()
	}
	if !got["a"] || !got["b"] {
		t.Fatalf("autoBurn=off should keep all IPs; got %v", got)
	}
}

// TestAdvanceIPAndSNIIndependently checks the manual per-dimension "rotate now": advanceIP
// steps the IP while the SNI stays put, and advanceSNI does the reverse.
func TestAdvanceIPAndSNIIndependently(t *testing.T) {
	p := newWSPool([]string{"a", "b", "c"}, snis("x", "y"), true, "")
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
