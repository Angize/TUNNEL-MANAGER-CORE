package packet

import (
	"net"
	"testing"
)

func TestPeerPoolRotateCycles(t *testing.T) {
	p := NewPeerPool([]string{"a", "b", "c"}, 0)
	if p.current() != "a" {
		t.Fatalf("first current = %q, want a", p.current())
	}
	got := []string{}
	for i := 0; i < 4; i++ {
		a, moved := p.rotateOnce()
		if !moved {
			t.Fatal("rotateOnce should move in a 3-endpoint pool")
		}
		got = append(got, a)
	}

	want := []string{"b", "c", "a", "b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rotation order = %v, want %v", got, want)
		}
	}
}

func TestPeerPoolBurnSkipsAndAdvances(t *testing.T) {
	p := NewPeerPool([]string{"a", "b", "c"}, 0)

	if a, moved := p.fail("tun-probe"); a != "b" || !moved {
		t.Fatalf("after burning a, got %q moved=%v, want b true", a, moved)
	}

	if a, _ := p.fail("tun-probe"); a != "c" {
		t.Fatalf("after burning b, got %q, want c", a)
	}

	if a, moved := p.rotateOnce(); a != "c" || moved {
		t.Fatalf("only c is live: got %q moved=%v, want c false", a, moved)
	}
}

func TestPeerPoolParksButNeverDeadEndsWhenAllBurned(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, 0)
	p.fail("tun-probe")

	a, moved := p.fail("tun-probe")
	if moved {
		t.Fatalf("every endpoint is condemned and none is due, and the pool moved to %q anyway. Each "+
			"move costs a session teardown and a fresh handshake, and neither endpoint is any better than "+
			"the other", a)
	}
	if a == "" {
		t.Fatal("the pool handed back nothing at all — parking is not the same as dead-ending")
	}
	p.mu.Lock()
	na, nb := p.health.recs["a"] != nil, p.health.recs["b"] != nil
	p.mu.Unlock()
	if !na || !nb {
		t.Fatalf("both endpoints should stay burned (suspect) after all-burned, got a=%v b=%v", na, nb)
	}
}

func TestPeerPoolSuspectToDeadBackoff(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0)
	p.now = func() int64 { return clk }

	p.fail("tun-probe")
	rec := p.health.recs["a"]
	if rec == nil || rec.state != stateSuspect || rec.fails != 0 || rec.nextRetest != clk+suspectBackoff[0] {
		t.Fatalf("first fail should make a suspect at +%ds, got %+v", suspectBackoff[0], rec)
	}

	for i := 1; i < len(suspectBackoff); i++ {
		clk = rec.nextRetest
		p.mu.Lock()
		p.cur = 0
		p.mu.Unlock()
		p.fail("tun-probe")
		if rec.state != stateSuspect || rec.fails != i {
			t.Fatalf("after %d retest fails a should be suspect fails=%d, got %+v", i, i, rec)
		}
	}
	clk = rec.nextRetest
	p.mu.Lock()
	p.cur = 0
	p.mu.Unlock()
	p.fail("tun-probe")
	if rec.state != stateDead || rec.nextRetest != clk+deadRetest {
		t.Fatalf("running off the backoff should mark a dead at +%ds, got %+v", deadRetest, rec)
	}
}

func TestPeerPoolDueEndpointReadmitted(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0)
	p.now = func() int64 { return clk }
	p.fail("tun-probe")
	if got := p.current(); got != "b" {
		t.Fatalf("while a is suspect current should stay on the healthy b, got %q", got)
	}

	p.fail("tun-probe")

	clk += suspectBackoff[len(suspectBackoff)-1] + deadRetest + 1
	got := p.current()
	if got != "a" && got != "b" {
		t.Fatalf("a due endpoint should be re-admitted, got %q", got)
	}

	p.mu.Lock()
	active := p.addrs[p.cur]
	p.mu.Unlock()
	if !p.clearBurn(active) {
		t.Fatal("the node's OK should clear the re-admitted endpoint's burn")
	}
}

func TestPeerPoolSelectPin(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b", "c"}, 0)
	p.now = func() int64 { return clk }
	if p.selectEntry("zzz") {
		t.Fatal("selectEntry must reject an unknown key")
	}
	if !p.selectEntry("c") {
		t.Fatal("selectEntry should find c")
	}
	if !p.isPinned() {
		t.Fatal("pool should report pinned right after selectEntry")
	}
	if got := p.current(); got != "c" {
		t.Fatalf("current() must force the pinned c, got %q", got)
	}

	if a, moved := p.fail("tun-probe"); a != "c" || moved {
		t.Fatalf("fail() while pinned must stay on c: got %q moved=%v, want c false", a, moved)
	}
	p.mu.Lock()
	burnedC := p.health.recs["c"] != nil
	p.mu.Unlock()
	if burnedC {
		t.Fatal("fail() while pinned must not burn the pinned endpoint")
	}
	if a, moved := p.rotateOnce(); a != "c" || moved {
		t.Fatalf("rotateOnce() while pinned must stay on c: got %q moved=%v, want c false", a, moved)
	}
	p.pinLandedOn("c")
	if p.isPinned() {
		t.Fatal("pinLanded on the pinned endpoint must release the pin")
	}

	p.selectEntry("a")
	if !p.pinCannotLand("b") {
		p.mu.Lock()
		still := p.pinKey
		p.mu.Unlock()
		if still != "a" {
			t.Fatal("a failure on a DIFFERENT endpoint released the pin")
		}
	}
	p.pinCannotLand("a")
	if p.isPinned() {
		t.Fatal("the pin survived the first refused attempt on the pinned endpoint — waiting for a " +
			"second only delays the burn that is coming anyway, and forces traffic onto it meanwhile")
	}
}

func TestPeerPoolRetestNow(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0)
	p.now = func() int64 { return clk }
	p.fail("tun-probe")
	if r := p.health.recs["a"]; r == nil || r.nextRetest <= clk {
		t.Fatalf("a should be burned with a future retest, got %+v", r)
	}
	p.retestNow("a")
	if r := p.health.recs["a"]; r == nil || r.nextRetest != clk {
		t.Fatalf("retestNow should pull a's retest to now, got %+v", r)
	}
}

func TestTheOneStatusFileCarriesBothAxes(t *testing.T) {
	b, pp, _ := peerCarrier(t, []string{"a", "b", "c"}, []string{"s1", "s2"})
	pp.fail("tun-probe")
	pp.selectEntry("c")

	st := b.readStatus(t)
	byKind := map[string][]healthStatus{}
	for _, h := range st.Health {
		byKind[h.Kind] = append(byKind[h.Kind], h)
	}
	if len(byKind["dst"]) != 3 || len(byKind["src"]) != 2 {
		t.Fatalf("both pools must report into the ONE file, got dst=%d src=%d — a second file is a "+
			"second answer, and the two can disagree", len(byKind["dst"]), len(byKind["src"]))
	}

	suspect, pinned := map[string]bool{}, ""
	for _, h := range byKind["dst"] {
		if h.State == stateSuspect {
			suspect[h.Key] = true
		}
		if h.Pin {
			pinned = h.Key
		}
	}
	if !suspect["a"] {
		t.Fatalf("a should be reported suspect in health, got %v", suspect)
	}
	if pinned != "c" {
		t.Fatalf("the operator's pick is not flagged in the rows: pinned=%q, want c", pinned)
	}
	if st.Pair.Low != "c" || st.Pair.LowKind != "dst" || st.Pair.HighKind != "src" {
		t.Fatalf("the machine-readable pair is wrong: %+v — the node keys its verdict on this, and "+
			"parsing the display label by eye is what let a stale one through", st.Pair)
	}
}

func TestPeerPoolSingleEndpointNoop(t *testing.T) {
	p := NewPeerPool([]string{"only"}, 0)
	if a, moved := p.fail("tun-probe"); a != "only" || moved {
		t.Fatalf("single-endpoint fail = %q moved=%v, want only false", a, moved)
	}
	if a, moved := p.rotateOnce(); a != "only" || moved {
		t.Fatalf("single-endpoint rotate = %q moved=%v, want only false", a, moved)
	}
}

func TestTCPDialTargetUsesPool(t *testing.T) {
	b := &TCP{isClient: true, addr: "1.1.1.1:9000"}
	if got := b.dialTarget(); got != "1.1.1.1:9000" {
		t.Fatalf("no pool: dialTarget = %q, want the fixed peer", got)
	}
	b.SetPeerPool(NewPeerPool([]string{"2.2.2.2:9000", "3.3.3.3:9000"}, 0))
	if b.pp == nil {
		t.Fatal("direct-tcp client should accept a peer pool")
	}
	if got := b.dialTarget(); got != "2.2.2.2:9000" {
		t.Fatalf("with pool: dialTarget = %q, want the pool's current endpoint", got)
	}

	b.pp.fail("tun-probe")
	if got := b.dialTarget(); got != "3.3.3.3:9000" {
		t.Fatalf("after burn: dialTarget = %q, want the next endpoint", got)
	}

	w := &TCP{isClient: true, ws: true, addr: "1.1.1.1:443"}
	w.SetPeerPool(NewPeerPool([]string{"2.2.2.2:443", "3.3.3.3:443"}, 0))
	if w.pp != nil {
		t.Fatal("ws client must reject a peer pool")
	}
	if got := w.dialTarget(); got != "1.1.1.1:443" {
		t.Fatalf("ws client: dialTarget = %q, want the fixed addr", got)
	}
}

func TestTCPSourceIPUsesPool(t *testing.T) {
	b := &TCP{isClient: true, bindIP: "10.0.0.1"}
	if got := b.sourceIP(); got != "10.0.0.1" {
		t.Fatalf("no source pool: sourceIP = %q, want the fixed bindIP", got)
	}
	b.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, 0))
	if b.sp == nil {
		t.Fatal("direct-tcp client should accept a source pool")
	}
	if got := b.sourceIP(); got != "10.0.0.5" {
		t.Fatalf("with source pool: sourceIP = %q, want the pool's current", got)
	}
	if _, moved := b.rotateSourceTCP(true); !moved {
		t.Fatal("rotateSourceTCP should report moved=true")
	}
	if got := b.sourceIP(); got != "10.0.0.6" {
		t.Fatalf("after rotate: sourceIP = %q, want the advanced source", got)
	}

	w := &TCP{isClient: true, ws: true, bindIP: "10.0.0.1"}
	w.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, 0))
	if w.sp != nil {
		t.Fatal("ws client must reject a source pool")
	}
}

func TestUDPSourceRebindSwapsConn(t *testing.T) {
	c0, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("initial ListenUDP: %v", err)
	}
	b := &UDP{isClient: true}
	b.conn.Store(c0)
	b.SetSourcePool(NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, 0))
	gen0 := b.rebindGen.Load()

	b.rotateSourceUDP(true)
	if b.rebindGen.Load() == gen0 {
		t.Fatal("rebindGen must advance on a source rebind so netToTun keeps the loop alive")
	}
	nc := b.conn.Load()
	if nc == c0 {
		t.Fatal("conn was not swapped")
	}
	if got := nc.LocalAddr().(*net.UDPAddr).IP; !got.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("rebound socket source = %v, want 127.0.0.2", got)
	}
	nc.Close()
}

func TestUDPSourcePoolBindsInitialSource(t *testing.T) {
	c0, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("initial ListenUDP: %v", err)
	}
	b := &UDP{isClient: true}
	b.conn.Store(c0)
	b.SetSourcePool(NewPeerPool([]string{"127.0.0.2", "127.0.0.3"}, 0))
	got := b.conn.Load().LocalAddr().(*net.UDPAddr).IP
	if !got.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("SetSourcePool should bind the initial source to SrcIPs[0]=127.0.0.2, got %v", got)
	}
	b.conn.Load().Close()
}

func TestUDPSourceRebindFailureKeepsSocketAndPool(t *testing.T) {
	c0, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("initial ListenUDP: %v", err)
	}
	b := &UDP{isClient: true}
	b.conn.Store(c0)

	b.SetSourcePool(NewPeerPool([]string{"127.0.0.1", "192.0.2.1"}, 0))
	sockBefore := b.conn.Load()
	gen0 := b.rebindGen.Load()

	b.rotateSourceUDP(false)

	if b.conn.Load() != sockBefore {
		t.Fatal("the socket was swapped even though the rebind failed")
	}
	if b.rebindGen.Load() != gen0 {
		t.Fatal("rebindGen advanced on a failed rebind — netToTun would treat a live socket as swapped")
	}
	if got := b.sp.current(); got != "127.0.0.1" {
		t.Fatalf("pool active = %q after a failed rebind; the socket never left 127.0.0.1", got)
	}
	if b.sp.health.recs["192.0.2.1"] == nil {
		t.Fatal("the unbindable candidate 192.0.2.1 was not burned — rotation will retry it every beat")
	}
	if r := b.sp.health.recs["127.0.0.1"]; r == nil {
		t.Fatal("the failover's own attribution was erased because the NEXT source would not bind — a " +
			"pool whose only alternative is unbindable then never records anything about the source it " +
			"is stuck on, and shows it healthy however long it keeps failing")
	} else if r.state != stateSuspect || r.fails != 0 {
		t.Fatalf("127.0.0.1 sits at %+v — one failover round is one step, no more", *r)
	}

	for i := 0; i < 3; i++ {
		if got := b.sp.current(); got != "127.0.0.1" {
			t.Fatalf("ask %d gave %q — the commitment must hold", i, got)
		}
	}
	b.conn.Load().Close()
}

func TestRotationControllerCouplesSource(t *testing.T) {
	dst := NewPeerPool([]string{"d0", "d1"}, 0)
	src := NewPeerPool([]string{"s0", "s1"}, 0)
	rc := newRotationController(dst, src)
	dstMoves, srcMoves := 0, 0
	rotDst := func(bool) { dstMoves++ }
	rotSrc := func(bool) { srcMoves++ }

	rc.fail(rotDst, rotSrc)
	if dstMoves != 1 || srcMoves != 0 {
		t.Fatalf("after 1 fail: dst=%d src=%d, want 1/0", dstMoves, srcMoves)
	}
	rc.fail(rotDst, rotSrc)
	if dstMoves != 2 || srcMoves != 1 {
		t.Fatalf("after 2 fails: dst=%d src=%d, want 2/1 (source walked)", dstMoves, srcMoves)
	}
	rc.success()
	rc.fail(rotDst, rotSrc)
	if srcMoves != 1 {
		t.Fatalf("success() must reset destRot so the source doesn't advance early, got src=%d", srcMoves)
	}

	rc2 := newRotationController(nil, NewPeerPool([]string{"s0", "s1"}, 0))
	n := 0
	rc2.fail(func(bool) { t.Fatal("no dest pool: rotDst must not be called") }, func(bool) { n++ })
	if n != 1 {
		t.Fatalf("source-only fail should advance the source once, got %d", n)
	}
}

func TestRotationControllerPinReleasesOnTheFirstProvenBlock(t *testing.T) {
	clk := int64(1000)
	dst := NewPeerPool([]string{"d0", "d1"}, 0)
	dst.now = func() int64 { return clk }
	rc := newRotationController(dst, nil)
	if !dst.selectEntry("d1") {
		t.Fatal("selectEntry d1 failed")
	}
	moves := 0
	rotDst := func(bool) { moves++ }
	rotSrc := func(bool) {}

	rc.fail(rotDst, rotSrc)
	if dst.isPinned() {
		t.Fatal("the pin survived the first verdict against it. Holding it for a second only delays the " +
			"burn that is coming anyway, and forces traffic onto the endpoint meanwhile")
	}
	if moves != 1 {
		t.Fatalf("the releasing round must also walk off the blocked endpoint, got moves=%d", moves)
	}

	rc.success()
	if !dst.selectEntry("d1") {
		t.Fatal("re-pin d1 failed")
	}
	if !dst.isPinned() {
		t.Fatal("a fresh pin after a success must hold until something faults it")
	}
	moves = 0
	rc.fail(rotDst, rotSrc)
	if dst.isPinned() || moves != 1 {
		t.Fatalf("the re-pin behaved differently from the first one: pinned=%v moves=%d",
			dst.isPinned(), moves)
	}
}

func TestAPinFlushesTheStatusFileTheMomentItGoes(t *testing.T) {
	b, pp, _ := peerCarrier(t, []string{"a", "b"}, nil)
	pp.selectEntry("b")
	readPin := func() string {
		for _, h := range b.readStatus(t).Health {
			if h.Pin {
				return h.Key
			}
		}
		return ""
	}
	if readPin() != "b" {
		t.Fatalf("status should show pinned b, got %q", readPin())
	}
	pp.pinCannotLand("zzz")
	if readPin() != "b" {
		t.Fatalf("a failure on another endpoint must not touch the pin, got %q", readPin())
	}
	pp.pinCannotLand("b")
	if readPin() != "" {
		t.Fatalf("the status file must clear the pin the moment it is released, got %q", readPin())
	}
}
