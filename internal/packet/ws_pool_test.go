package packet

import (
	"testing"
)

func snis(hosts ...string) []wsSNIEntry {
	out := make([]wsSNIEntry, len(hosts))
	for i, h := range hosts {
		out[i] = wsSNIEntry{host: h, path: "/"}
	}
	return out
}

// An edge carrier whose BOTH pools read one fake clock, so a backoff can be walked without sleeping.
func clockPool(ips []string, snis []wsSNIEntry) (*TCP, *int64) {
	b := edgeTCP(ips, snis, 0)
	var now int64 = 1000
	b.pp.now = func() int64 { return now }
	b.sp.now = func() int64 { return now }
	return b, &now
}

func TestARotationMovesOffTheLiveEdgeAndVariesBothAxes(t *testing.T) {

	b := edgeTCP([]string{"a", "b"}, snis("x"), 0)
	for round := 0; round < 20; round++ {
		before, _, ok := b.edgeCombo()
		if !ok {
			t.Fatal("edgeCombo() returned not-ok on a healthy 2-IP pool")
		}
		if !b.walkEdge() {
			t.Fatalf("round %d: a healthy 2-IP pool reported no move", round)
		}
		if got := b.pp.current(); got == before {
			t.Fatalf("round %d: the rotation landed back on the live edge %q", round, got)
		}
	}

	b2 := edgeTCP([]string{"a", "b"}, snis("x", "y"), 0)
	seenIP, seenSNI := map[string]bool{}, map[string]bool{}
	for round := 0; round < 8; round++ {
		before := b2.edgeAt()
		if !b2.walkEdge() {
			t.Fatalf("round %d: a healthy 2x2 pool reported no move", round)
		}
		ip, sni, ok := b2.edgeCombo()
		if !ok {
			t.Fatal("edgeCombo() returned not-ok on a healthy 2x2 pool")
		}
		if activeLabel(ip, sni.host) == before {
			t.Fatalf("round %d: the rotation resolved back onto the live combo %s", round,
				activeLabel(ip, sni.host))
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

	b3 := edgeTCP([]string{"a", "b"}, snis("x", "y"), 0)
	b3.sp.markSuspect("y", "test")
	for round := 0; round < 4; round++ {
		b3.walkEdge()
		if _, sni, _ := b3.edgeCombo(); sni.host != "x" {
			t.Fatalf("round %d: burned domain y was selected (%q)", round, sni.host)
		}
	}
}

func TestPoolAdvanceReportsRealMove(t *testing.T) {

	b := edgeTCP([]string{"a", "b"}, snis("x", "y"), 0)
	for i := 0; i < 4; i++ {
		if !b.walkEdge() {
			t.Fatalf("healthy 2x2 pool: the walk must report a move (step %d)", i)
		}
	}

	b2 := edgeTCP([]string{"a", "b", "c"}, snis("x"), 0)
	b2.pp.markSuspect("b", "test")
	b2.pp.markSuspect("c", "test")
	if ipBefore := b2.pp.current(); ipBefore != "a" {
		t.Fatalf("only a is healthy; got ip=%q", ipBefore)
	}
	for i := 0; i < 5; i++ {
		if b2.walkEdge() {
			t.Fatalf("single healthy edge: the walk must report no move (step %d)", i)
		}
		if ip := b2.pp.current(); ip != "a" {
			t.Fatalf("single healthy edge: must stay on a, got %q", ip)
		}
	}

	b2.pp.clearBurn("b")
	if !b2.walkEdge() {
		t.Fatal("after edge b healed, the walk must report a move again")
	}

	b3 := edgeTCP([]string{"a"}, snis("x"), 0)
	if b3.walkEdge() {
		t.Fatal("1x1 pool: the walk must report no move")
	}

	// 1x1 is the SMALLEST edge pool there is now. An axis with no entries at all is not a pool that
	// reports no move any more -- it is a pool that cannot be built, and the constructor is where that
	// is settled, before anything can index an empty axis.
	if _, err := DialWSPoolCfg(nil, false, false, "", "", nil, []WSPoolSNI{{Host: "x"}}, 0, false, ""); err == nil {
		t.Fatal("an edge pool with no IP was accepted")
	}
	if _, err := DialWSPoolCfg(nil, false, false, "", "", []string{"a"}, nil, 0, false, ""); err == nil {
		t.Fatal("an edge pool with no SNI was accepted")
	}
}

func TestPoolRotatesAllCombos(t *testing.T) {
	b := edgeTCP([]string{"a", "b"}, snis("x", "y"), 0)
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		ip, sni, ok := b.edgeCombo()
		if !ok {
			t.Fatal("pool empty unexpectedly")
		}
		seen[ip+"|"+sni.host] = true
		b.walkEdge()
	}
	for _, want := range []string{"a|x", "a|y", "b|x", "b|y"} {
		if !seen[want] {
			t.Fatalf("combo %s never selected; got %v", want, seen)
		}
	}
}

func TestPoolUpdateECHTransitionGate(t *testing.T) {
	b := edgeTCP([]string{"a"}, snis("x", "y"), 0)
	fresh := []byte{1, 2, 3}

	if !b.setSNIECH("x", fresh) {
		t.Fatal("first setSNIECH should report a change")
	}
	if _, sni, _ := b.edgeCombo(); string(sni.ech) != string(fresh) {
		t.Fatalf("the live combo should carry the persisted key, got %v", sni.ech)
	}

	if b.setSNIECH("x", fresh) {
		t.Fatal("repeat setSNIECH with an unchanged key must report no change (suppresses repeat events)")
	}

	if !b.setSNIECH("x", []byte{9, 9}) {
		t.Fatal("setSNIECH with a rotated key should report a change")
	}

	if b.setSNIECH("zzz", fresh) {
		t.Fatal("setSNIECH for an absent host must report no change")
	}

	if e := b.sniEntry("y"); e.host != "y" || e.ech != nil {
		t.Fatalf("sibling SNI y should be untouched, got %#v", e)
	}
}

func TestPoolDownReconnectPairing(t *testing.T) {
	b, _, _ := edgeCarrier(t, []string{"a", "b"}, snis("x"))
	evs := func() []coreEvent {
		b.st.mu.Lock()
		defer b.st.mu.Unlock()
		return append([]coreEvent(nil), b.st.events...)
	}

	b.st.setActive("a · x")
	if len(evs()) != 0 {
		t.Fatalf("initial connect must emit no event, got %+v", evs())
	}

	b.st.down("reset", "a · x")
	b.st.reconnected("b · x")
	e := evs()
	if len(e) != 2 || e[0].Kind != "down" || e[1].Kind != "up" || e[1].Code != "reconnect" {
		t.Fatalf("want down then up/reconnect, got %+v", e)
	}

	b.st.reconnected("a · x")
	if len(evs()) != 2 {
		t.Fatalf("rotation without a pending down must be silent, got %d events", len(evs()))
	}

	b.st.down("throttle", "a · x")
	b.st.reconnected("a · x")
	if e = evs(); len(e) != 4 || e[3].Kind != "up" {
		t.Fatalf("a same-edge reconnect after a down must still emit up, got %+v", e)
	}
}

func TestMarkSuspectPullsFromRotation(t *testing.T) {
	b := edgeTCP([]string{"a", "b"}, snis("x"), 0)
	b.pp.markSuspect("a", "test")
	b.pp.mu.Lock()
	r := b.pp.health.recs["a"]
	b.pp.mu.Unlock()
	if r == nil || r.state != stateSuspect || r.fails != 0 {
		t.Fatalf("a should be suspect with fails=0, got %#v", r)
	}
	for i := 0; i < 5; i++ {
		if ip := b.pp.current(); ip != "b" {
			t.Fatalf("suspect a must be skipped while b is healthy; got ip=%q", ip)
		}
		b.walkEdge()
	}
}

func TestABurnDeepensOnlyOnceThePreviousWaitIsSpent(t *testing.T) {
	b, now := clockPool([]string{"a", "b"}, snis("x"))
	rec := func() healthRec {
		b.pp.mu.Lock()
		defer b.pp.mu.Unlock()
		return *b.pp.health.recs["a"]
	}

	b.pp.markSuspect("a", "test")
	if got := rec().nextRetest; got != *now+suspectBackoff[0] {
		t.Fatalf("entry retest should be now+%d, got %d (now=%d)", suspectBackoff[0], got, *now)
	}

	b.pp.markSuspect("a", "test")
	if r := rec(); r.fails != 0 || r.nextRetest != *now+suspectBackoff[0] {
		t.Fatalf("a second verdict inside the SAME wait deepened the backoff (fails=%d next=%d): the "+
			"edge would reach dead in seconds on one outage", r.fails, r.nextRetest-*now)
	}

	for i, w := range suspectBackoff[1:] {
		*now = rec().nextRetest
		b.pp.markSuspect("a", "test")
		r := rec()
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

	*now = rec().nextRetest
	b.pp.markSuspect("a", "test")
	r := rec()
	if r.state != stateDead || r.nextRetest != *now+deadRetest {
		t.Fatalf("expected dead at now+%d, got state=%q next=%d", deadRetest, r.state, r.nextRetest-*now)
	}

	*now = r.nextRetest
	b.pp.markSuspect("a", "test")
	if r := rec(); r.state != stateDead || r.nextRetest != *now+deadRetest {
		t.Fatalf("dead entry should stay dead at now+%d, got state=%q next=%d", deadRetest, r.state,
			r.nextRetest-*now)
	}
}

func TestNothingButTheTunProbeReadmitsABurnedEdge(t *testing.T) {
	b, pp, _ := edgeCarrier(t, []string{"a", "b"}, snis("x"))
	var now int64 = 1000
	pp.now = func() int64 { return now }
	evs := func() []coreEvent {
		b.st.mu.Lock()
		defer b.st.mu.Unlock()
		return append([]coreEvent(nil), b.st.events...)
	}
	due := func(key string) bool {
		pp.mu.Lock()
		defer pp.mu.Unlock()
		return pp.health.due(key)
	}
	healthy := func(key string) bool {
		pp.mu.Lock()
		defer pp.mu.Unlock()
		return pp.health.healthy(key)
	}
	pp.markSuspect("a", "test")
	base := len(evs())

	if due("a") {
		t.Fatal("a fresh burn must not be due -- the wait is the whole point of the backoff")
	}

	now += suspectBackoff[0] + 1
	if healthy("a") {
		t.Fatal("the wait elapsing HEALED the edge. Nothing inside the pool may readmit an edge on a " +
			"clock: only the tun probe, which watches DATA cross, has evidence")
	}
	if !due("a") {
		t.Fatal("the wait elapsed and the edge is still not due, so the rotation never hands it live " +
			"traffic and the tun probe never gets to judge it")
	}
	if len(evs()) != base {
		t.Fatalf("time passing announced something: %+v", evs()[base:])
	}

	if !pp.clearBurn("a") {
		t.Fatal("clearBurn is the tun probe's cmdOK path and must report it cleared something")
	}
	if !healthy("a") {
		t.Fatal("clearBurn left the record behind")
	}
	// Two, and both are true: the entry itself is readmitted, and with it the pool can rotate again.
	e := evs()[base:]
	if len(e) != 2 {
		t.Fatalf("want a heal and a pool/restored, got %+v", e)
	}
	if e[0].Kind != "heal" || e[0].Detail != "ip:a" {
		t.Fatalf("the pool must name the entry it readmitted, got %+v", e[0])
	}
	if e[1].Kind != "pool" || e[1].Code != "restored" {
		t.Fatalf("and then say the rotation can reach both edges again, got %+v", e[1])
	}
}

func TestCurrentFallbackLeastBad(t *testing.T) {
	b, _ := clockPool([]string{"a", "b"}, snis("x", "y"))

	b.pp.mu.Lock()
	b.pp.health.recs["a"] = &healthRec{state: stateDead, nextRetest: 1005}
	b.pp.health.recs["b"] = &healthRec{state: stateSuspect, nextRetest: 1100}
	b.pp.mu.Unlock()
	b.sp.mu.Lock()
	b.sp.health.recs["x"] = &healthRec{state: stateSuspect, nextRetest: 1050}
	b.sp.health.recs["y"] = &healthRec{state: stateDead, nextRetest: 1010}
	b.sp.mu.Unlock()

	ip, sni, ok := b.edgeCombo()
	if !ok {
		t.Fatal("fallback must still return a combo")
	}
	if ip != "b" || sni.host != "x" {
		t.Fatalf("least-bad should prefer suspect over dead: want b/x, got %s/%s", ip, sni.host)
	}

	b.pp.mu.Lock()
	b.pp.health.recs["a"] = &healthRec{state: stateSuspect, nextRetest: 1005}
	b.pp.health.recs["b"] = &healthRec{state: stateSuspect, nextRetest: 1100}
	b.pp.mu.Unlock()
	if ip := b.pp.current(); ip != "a" {
		t.Fatalf("same-tier tiebreak should pick soonest retest a, got %s", ip)
	}
}

func TestStatusSnapshotStates(t *testing.T) {
	b, pp, _ := edgeCarrier(t, []string{"a", "b"}, snis("x"))
	var now int64 = 1000
	pp.now = func() int64 { return now }
	pp.current()
	pp.markSuspect("a", "test")

	rows := b.readStatus(t).Health
	got := map[string]string{}
	var aNext int64
	for _, h := range rows {
		got[h.Kind+":"+h.Key] = h.State
		if h.Kind == "ip" && h.Key == "a" {
			aNext = h.NextRetest
		}
	}
	if got["ip:a"] != stateSuspect || got["ip:b"] != "healthy" || got["sni:x"] != "healthy" {
		t.Fatalf("health states wrong: %v", got)
	}
	if aNext != now+suspectBackoff[0] {
		t.Fatalf("suspect a next_retest_unix=%d, want %d", aNext, now+suspectBackoff[0])
	}
	if len(rows) != 3 {
		t.Fatalf("health should list every pool entry (2 ips + 1 sni), got %d", len(rows))
	}
}

func TestRetestEndsOneWaitAndOnlyThatOne(t *testing.T) {
	b, now := clockPool([]string{"a", "b"}, snis("x", "y"))
	ipDue := func() bool {
		b.pp.mu.Lock()
		defer b.pp.mu.Unlock()
		return b.pp.health.due("a")
	}
	sniDue := func() bool {
		b.sp.mu.Lock()
		defer b.sp.mu.Unlock()
		return b.sp.health.due("x")
	}

	b.pp.markSuspect("a", "test")
	b.sp.markSuspect("x", "test")
	if ipDue() || sniDue() {
		t.Fatal("nothing should be due yet")
	}

	if !b.pp.retestNow("a") {
		t.Fatal("retest did not report that it ended a's wait")
	}
	if !ipDue() {
		t.Fatal("the entry the operator named is still waiting")
	}
	if sniDue() {
		t.Fatal("ending one entry's wait ended the OTHER axis's too — the operator asked for one row, " +
			"and zeroing the rest makes their backoff a lie")
	}
	b.pp.mu.Lock()
	healed := b.pp.health.healthy("a")
	b.pp.mu.Unlock()
	if healed {
		t.Fatal("retest CLEARED a burn; it may only end the wait, and the tun probe decides the rest")
	}

	b2, now2 := clockPool([]string{"a"}, snis("x"))
	b2.pp.markSuspect("a", "test")
	*now2 = *now + suspectBackoff[0] + 1
	b2.pp.mu.Lock()
	due := b2.pp.health.due("a")
	b2.pp.mu.Unlock()
	if !due {
		t.Fatal("entry should be due once its backoff elapses")
	}
}

func TestSelectEntryMovesAndClears(t *testing.T) {
	b := edgeTCP([]string{"a", "b"}, snis("x"), 0)
	b.pp.markSuspect("b", "test")
	if !b.pp.selectEntry("b") {
		t.Fatal("selectEntry should move onto b")
	}
	b.pp.mu.Lock()
	r := b.pp.health.recs["b"]
	b.pp.mu.Unlock()
	if r != nil {
		t.Fatal("selecting b must clear its suspect mark")
	}
	if ip := b.pp.current(); ip != "b" {
		t.Fatalf("current() should now return the selected b, got %q", ip)
	}
	if b.pp.selectEntry("does-not-exist") {
		t.Fatal("selectEntry must return false for an unknown key")
	}
}

// The operator names ONE axis. The other one has to be settled onto something usable in the same
// breath, or the jump lands on a combination the pool already knows is dead and the first dial fails
// for a reason that has nothing to do with what they asked for.
func TestAJumpSettlesTheOtherAxisOnSomethingUsable(t *testing.T) {
	b, _ := clockPool([]string{"a", "b"}, snis("x", "y"))
	b.sp.markSuspect("x", "sni_blocked")
	if !b.pp.selectEntry("b") {
		t.Fatal("selectEntry should move onto b")
	}
	ip, sni, ok := b.edgeCombo()
	if !ok || ip != "b" {
		t.Fatalf("the jump did not land: ip=%q ok=%v", ip, ok)
	}
	if sni.host == "x" {
		t.Fatal("the jump landed on the burned domain x — the first dial fails for a reason the " +
			"operator never chose")
	}

	b2, _ := clockPool([]string{"a", "b"}, snis("x", "y"))
	b2.pp.markSuspect("a", "test")
	if !b2.sp.selectEntry("y") {
		t.Fatal("selectEntry should move onto y")
	}
	ip2, sni2, _ := b2.edgeCombo()
	if sni2.host != "y" {
		t.Fatalf("the domain jump did not land: sni=%q", sni2.host)
	}
	if ip2 == "a" {
		t.Fatal("the domain jump left the cursor on the burned edge a")
	}
}

func TestAdvanceIPAndSNIIndependently(t *testing.T) {
	b := edgeTCP([]string{"a", "b", "c"}, snis("x", "y"), 0)
	ip0, sni0, _ := b.edgeCombo()
	if ip0 != "a" || sni0.host != "x" {
		t.Fatalf("start = %s/%s, want a/x", ip0, sni0.host)
	}
	if _, moved := b.pp.rotateOnce(); !moved {
		t.Fatal("the edge axis alone reported no move on a healthy 3-IP pool")
	}
	ip1, sni1, _ := b.edgeCombo()
	if ip1 != "b" || sni1.host != "x" {
		t.Fatalf("after one edge step = %s/%s, want b/x (SNI unchanged)", ip1, sni1.host)
	}
	// One step varies the EDGE and leaves the domain alone: the edge is the cheap digit.
	b.walkEdge()
	ip2, sni2, _ := b.edgeCombo()
	if ip2 != "c" || sni2.host != "x" {
		t.Fatalf("after one step = %s/%s, want c/x (the domain must not turn until the row is spent)",
			ip2, sni2.host)
	}
	if _, moved := b.pp.rotateOnce(); !moved {
		t.Fatal("the edge axis would not wrap")
	}
	ip3, _, _ := b.edgeCombo()
	if ip3 != "a" {
		t.Fatalf("after wrap = %s, want a", ip3)
	}
}
