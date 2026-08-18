package packet

import (
	"encoding/json"
	"net"
	"os"
	"testing"
)

func TestPeerPoolRotateCycles(t *testing.T) {
	p := NewPeerPool([]string{"a", "b", "c"}, 0, "")
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
	p := NewPeerPool([]string{"a", "b", "c"}, 0, "")

	if a, moved := p.fail(); a != "b" || !moved {
		t.Fatalf("after burning a, got %q moved=%v, want b true", a, moved)
	}

	if a, _ := p.fail(); a != "c" {
		t.Fatalf("after burning b, got %q, want c", a)
	}

	if a, moved := p.rotateOnce(); a != "c" || moved {
		t.Fatalf("only c is live: got %q moved=%v, want c false", a, moved)
	}
}

func TestPeerPoolNeverDeadEndsWhenAllBurned(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, 0, "")
	p.fail()

	a, moved := p.fail()
	if !moved || a != "a" {
		t.Fatalf("after all-burned: got %q moved=%v, want a true (advance off the failed endpoint)", a, moved)
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
	p := NewPeerPool([]string{"a", "b"}, 0, "")
	p.now = func() int64 { return clk }

	p.fail()
	rec := p.health.recs["a"]
	if rec == nil || rec.state != stateSuspect || rec.fails != 0 || rec.nextRetest != clk+suspectBackoff[0] {
		t.Fatalf("first fail should make a suspect at +%ds, got %+v", suspectBackoff[0], rec)
	}

	for i := 1; i < len(suspectBackoff); i++ {
		clk = rec.nextRetest
		p.mu.Lock()
		p.cur = 0
		p.mu.Unlock()
		p.fail()
		if rec.state != stateSuspect || rec.fails != i {
			t.Fatalf("after %d retest fails a should be suspect fails=%d, got %+v", i, i, rec)
		}
	}
	clk = rec.nextRetest
	p.mu.Lock()
	p.cur = 0
	p.mu.Unlock()
	p.fail()
	if rec.state != stateDead || rec.nextRetest != clk+deadRetest {
		t.Fatalf("running off the backoff should mark a dead at +%ds, got %+v", deadRetest, rec)
	}
}

func TestPeerPoolDueEndpointReadmitted(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0, "")
	p.now = func() int64 { return clk }
	p.fail()
	if got := p.current(); got != "b" {
		t.Fatalf("while a is suspect current should stay on the healthy b, got %q", got)
	}

	p.fail()

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
	p := NewPeerPool([]string{"a", "b", "c"}, 0, "")
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

	if a, moved := p.fail(); a != "c" || moved {
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
	for i := 1; i < pinFailRelease; i++ {
		p.pinAttemptFailed("a")
		if !p.isPinned() {
			t.Fatalf("attempt %d of %d released the pin — one failure is not evidence", i, pinFailRelease)
		}
	}
	p.pinAttemptFailed("a")
	if p.isPinned() {
		t.Fatalf("after %d failed attempts on the pinned endpoint the pin must go", pinFailRelease)
	}
}

func TestPeerPoolProbeAllNow(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0, "")
	p.now = func() int64 { return clk }
	p.fail()
	if r := p.health.recs["a"]; r == nil || r.nextRetest <= clk {
		t.Fatalf("a should be burned with a future retest, got %+v", r)
	}
	p.probeAllNow()
	if r := p.health.recs["a"]; r == nil || r.nextRetest != clk {
		t.Fatalf("probeAllNow should pull a's retest to now, got %+v", r)
	}
}

func TestPeerPoolStatusFileFSM(t *testing.T) {
	dir := t.TempDir()
	sp := dir + "/core-x.peerpool"
	p := NewPeerPool([]string{"a", "b", "c"}, 0, sp)
	p.fail()
	p.selectEntry("c")
	data, err := os.ReadFile(sp)
	if err != nil {
		t.Fatalf("status file not written: %v", err)
	}
	var st struct {
		Active string   `json:"active"`
		Addrs  []string `json:"addrs"`
		Pin    string   `json:"pin"`
		Health []struct {
			Key, State string
		} `json:"health"`
	}
	if json.Unmarshal(data, &st) != nil {
		t.Fatalf("status file is not valid JSON: %s", data)
	}
	if st.Active != "c" || st.Pin != "c" {
		t.Fatalf("after pinning c: active=%q pin=%q, want c/c", st.Active, st.Pin)
	}
	if len(st.Addrs) != 3 || len(st.Health) != 3 {
		t.Fatalf("status should list all 3 endpoints, got addrs=%v health=%d", st.Addrs, len(st.Health))
	}

	suspect := map[string]bool{}
	for _, h := range st.Health {
		if h.State == stateSuspect {
			suspect[h.Key] = true
		}
	}
	if !suspect["a"] {
		t.Fatalf("a should be reported suspect in health, got %v", suspect)
	}
}

func TestPeerPoolSingleEndpointNoop(t *testing.T) {
	p := NewPeerPool([]string{"only"}, 0, "")
	if a, moved := p.fail(); a != "only" || moved {
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
	b.SetPeerPool(NewPeerPool([]string{"2.2.2.2:9000", "3.3.3.3:9000"}, 0, ""))
	if b.pp == nil {
		t.Fatal("direct-tcp client should accept a peer pool")
	}
	if got := b.dialTarget(); got != "2.2.2.2:9000" {
		t.Fatalf("with pool: dialTarget = %q, want the pool's current endpoint", got)
	}

	b.pp.fail()
	if got := b.dialTarget(); got != "3.3.3.3:9000" {
		t.Fatalf("after burn: dialTarget = %q, want the next endpoint", got)
	}

	w := &TCP{isClient: true, ws: true, addr: "1.1.1.1:443"}
	w.SetPeerPool(NewPeerPool([]string{"2.2.2.2:443", "3.3.3.3:443"}, 0, ""))
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
	b.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, 0, ""))
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
	w.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, 0, ""))
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
	b.SetSourcePool(NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, 0, ""))
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
	b.SetSourcePool(NewPeerPool([]string{"127.0.0.2", "127.0.0.3"}, 0, ""))
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

	b.SetSourcePool(NewPeerPool([]string{"127.0.0.1", "192.0.2.1"}, 0, ""))
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
	dst := NewPeerPool([]string{"d0", "d1"}, 0, "")
	src := NewPeerPool([]string{"s0", "s1"}, 0, "")
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

	rc2 := newRotationController(nil, NewPeerPool([]string{"s0", "s1"}, 0, ""))
	n := 0
	rc2.fail(func(bool) { t.Fatal("no dest pool: rotDst must not be called") }, func(bool) { n++ })
	if n != 1 {
		t.Fatalf("source-only fail should advance the source once, got %d", n)
	}
}

func TestRotationControllerPinAutoReleasesOnProvenBlock(t *testing.T) {
	clk := int64(1000)
	dst := NewPeerPool([]string{"d0", "d1"}, 0, "")
	dst.now = func() int64 { return clk }
	rc := newRotationController(dst, nil)
	if !dst.selectEntry("d1") {
		t.Fatal("selectEntry d1 failed")
	}
	moves := 0
	rotDst := func(bool) { moves++ }
	rotSrc := func(bool) {}

	for i := 0; i < pinFailRelease-1; i++ {
		rc.fail(rotDst, rotSrc)
		if !dst.isPinned() {
			t.Fatalf("pin must survive proven-dead round %d (< pinFailRelease)", i)
		}
		if moves != 0 {
			t.Fatalf("no failover while the pin is held, got moves=%d", moves)
		}
	}

	rc.success()
	dst.pinLandedOn("d1")
	if dst.isPinned() {
		t.Fatal("a landing on the pinned endpoint must clear it")
	}
	if !dst.selectEntry("d1") {
		t.Fatal("re-pin d1 failed")
	}
	moves = 0
	for i := 0; i < pinFailRelease-1; i++ {
		rc.fail(rotDst, rotSrc)
		if !dst.isPinned() {
			t.Fatalf("the count must restart after success; the re-pin must survive round %d", i)
		}
		if moves != 0 {
			t.Fatalf("no failover while the re-pin is held, got moves=%d", moves)
		}
	}

	rc.fail(rotDst, rotSrc)
	if dst.isPinned() {
		t.Fatal("a pin on a proven-blocked endpoint must auto-release at pinFailRelease")
	}
	if moves != 1 {
		t.Fatalf("the releasing round must also fail over off the blocked endpoint, got moves=%d", moves)
	}
}

func TestPeerPoolExpirePinFlushesStatus(t *testing.T) {
	dir := t.TempDir()
	sp := dir + "/core-x.peerpool"
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0, sp)
	p.now = func() int64 { return clk }
	p.selectEntry("b")
	readPin := func() string {
		data, err := os.ReadFile(sp)
		if err != nil {
			t.Fatalf("status read: %v", err)
		}
		var st struct {
			Pin string `json:"pin"`
		}
		if err := json.Unmarshal(data, &st); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return st.Pin
	}
	if readPin() != "b" {
		t.Fatalf("status should show pinned b, got %q", readPin())
	}
	p.pinAttemptFailed("zzz")
	if readPin() != "b" {
		t.Fatalf("a failure on another endpoint must not touch the pin, got %q", readPin())
	}
	for i := 0; i < pinFailRelease; i++ {
		p.pinAttemptFailed("b")
	}
	if readPin() != "" {
		t.Fatalf("the status file must clear the pin the moment it is released, got %q", readPin())
	}
}
