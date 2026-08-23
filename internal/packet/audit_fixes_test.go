package packet

import (
	"encoding/base64"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func stateOf(rows []healthStatus, kind, key string) string {
	for _, h := range rows {
		if h.Kind == kind && h.Key == key {
			return h.State
		}
	}
	return "<missing>"
}

func eventCodes(b *TCP, t *testing.T) []string {
	t.Helper()
	var out []string
	for _, e := range b.readStatus(t).Events {
		out = append(out, e.Kind+"/"+e.Code)
	}
	return out
}

// A refused dial reaches the edge and stops there: TLS never starts, so the domain is never sent and
// nothing is learned about it. Ending the operator's domain pin over it threw away the expensive pick
// -- the one they chose deliberately -- because a cheap one under it happened to be dead.
func TestARefusedEdgeLeavesTheDomainPinAlone(t *testing.T) {
	b, p := edgeCarrier(t, []string{"ip1:443", "ip2:443"}, snis("front-a", "front-b"))
	if !b.operatorPin(t, "sni", "front-b") {
		t.Fatal("setup: the domain pin was not applied")
	}
	b.pinFailedOn("ip2:443")

	p.mu.Lock()
	sni, ip := p.pinSNI, p.pinIP
	p.mu.Unlock()
	if sni != "front-b" {
		t.Errorf("the edge refused and the DOMAIN pin went with it (pinSNI=%q)", sni)
	}
	if ip != "" {
		t.Errorf("no edge was pinned, yet pinIP=%q", ip)
	}
}

// ...and it still ends an EDGE pin, which is the one thing a refusal does prove.
func TestARefusedEdgeEndsTheEdgePin(t *testing.T) {
	b, p := edgeCarrier(t, []string{"ip1:443", "ip2:443"}, snis("front-a"))
	if !b.operatorPin(t, "ip", "ip2:443") {
		t.Fatal("setup: the edge pin was not applied")
	}
	b.pinFailedOn("ip2:443")
	if p.isPinned() {
		t.Error("the operator's own edge refused the dial and the pin outlived it")
	}
}

// The pin stashes the entry's burn and gives it back when the pin ends. Pinning the SAME entry twice
// used to overwrite that stash with the record the first pin had already cleared -- nothing -- so a
// six-hour dead entry came back healthy and the walk handed it live traffic again.
func TestRePinningTheSameEntryKeepsItsBurn(t *testing.T) {
	t.Run("direct pool", func(t *testing.T) {
		_, pp, _ := peerCarrier(t, []string{"1.1.1.1:443", "2.2.2.2:443"}, nil)
		pp.markSuspect("2.2.2.2:443", "tun-probe")
		pp.selectEntry("2.2.2.2:443")
		pp.selectEntry("2.2.2.2:443")
		pp.releasePin()
		if got := stateOf(pp.healthRows(), "dst", "2.2.2.2:443"); got != stateSuspect {
			t.Errorf("after two pins and a release the burn is %q, want %q", got, stateSuspect)
		}
	})
	t.Run("edge pool", func(t *testing.T) {
		for _, tc := range []struct{ kind, key string }{{"ip", "ip2:443"}, {"sni", "front-b"}} {
			_, p := edgeCarrier(t, []string{"ip1:443", "ip2:443"}, snis("front-a", "front-b"))
			p.markSuspect(tc.kind, tc.key, "tun-probe")
			p.selectEntry(tc.kind, tc.key)
			p.selectEntry(tc.kind, tc.key)
			p.releasePin()
			if got := stateOf(p.healthRows(), tc.kind, tc.key); got != stateSuspect {
				t.Errorf("%s: after two pins and a release the burn is %q, want %q", tc.kind, got, stateSuspect)
			}
		}
	})
}

// Pinning a key the pool does not have must change nothing at all -- not the cursor, not the live
// pin, and not the health of the entry that pin is holding.
func TestPinningAKeyThePoolDoesNotHaveChangesNothing(t *testing.T) {
	_, p := edgeCarrier(t, []string{"ip1:443", "ip2:443"}, snis("front-a", "front-b"))
	p.markSuspect("sni", "front-b", "tun-probe")
	p.selectEntry("sni", "front-b")
	before, _, _ := p.current()

	if p.selectEntry("sni", "nope.example") {
		t.Fatal("selectEntry reported it pinned a domain the pool does not have")
	}
	p.mu.Lock()
	pinned := p.pinSNI
	p.mu.Unlock()
	if pinned != "front-b" {
		t.Errorf("the live pin became %q", pinned)
	}
	if now, _, _ := p.current(); now != before {
		t.Errorf("the cursor moved from %q to %q", before, now)
	}
	p.releasePin()
	if got := stateOf(p.healthRows(), "sni", "front-b"); got != stateSuspect {
		t.Errorf("the stashed burn is %q after the release, want %q", got, stateSuspect)
	}
}

// One connect, one path, one epoch. setActive flushes the status file, so taking that flush before the
// SNI was stored counted the half-built path as a path of its own: two epochs per CDN reconnect, and
// the node's verdict for the first was thrown away as stale.
func TestOneConnectIsOneEpoch(t *testing.T) {
	const psk = "one-epoch-per-connect-psk-abcdefg"
	srvDev, _ := tunPair(t, "1epsrv")
	cliDev, _ := tunPair(t, "1epcli")
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, false, true, psk, "aes-256-gcm", "")
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	pool := newWSPool([]string{addr}, snis("front-a"))
	cli := &TCP{dev: cliDev, cryptoOn: true, cipher: "aes-256-gcm", psk: psk,
		ws: true, wsTLS: false, pool: pool,
		idle: connIdle, ping: pingEvery, isClient: true, addr: "pool", closeCh: make(chan struct{})}
	cli.SetStatusPath(runningStatusPath(t, cli))
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	waitFor(t, 5*time.Second, "carrier up", func() bool { return cli.cur.Load() != nil })
	waitFor(t, 3*time.Second, "the path is published", func() bool {
		_, k, _ := cli.st.tracker.snapshot()
		return k.SNI != ""
	})
	ep, k, _ := cli.st.tracker.snapshot()
	if ep != 1 {
		t.Errorf("one connect moved the path epoch %d times; the path is %+v", ep, k)
	}
}

// Two commands in one tick are two commands. The mailbox was a single slot, so the second erased the
// first while the panel reported both as done -- and a pin and a retest are orders on different
// entries, so neither supersedes the other.
func TestTheOperatorMailboxKeepsEveryCommand(t *testing.T) {
	b, p := edgeCarrier(t, []string{"ip1:443", "ip2:443"}, snis("front-a", "front-b"))
	p.markSuspect("ip", "ip2:443", "tun-probe")

	box := b.st.pinPath()
	f, err := os.OpenFile(box, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"cmd":"retest","kind":"ip","key":"ip2:443"}` + "\n" +
		`{"kind":"sni","key":"front-b"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	b.pollPeerCmd()
	p.mu.Lock()
	pinned := p.pinSNI
	p.mu.Unlock()
	if pinned != "front-b" {
		t.Errorf("the second command was dropped: pinSNI=%q", pinned)
	}
	rec := func() *healthRec {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.ipHealth.rec("ip2:443")
	}()
	if rec != nil && rec.nextRetest > p.now() {
		t.Errorf("the first command was dropped: ip2 still waits until %d", rec.nextRetest)
	}
	if _, err := os.Stat(box); !os.IsNotExist(err) {
		t.Errorf("the mailbox was not consumed: %v", err)
	}
}

// Every walk says where the traffic went, on both pool kinds. The burn names what was condemned; it
// does not name where the tunnel is now. The direct walk was silent and the CDN walk was silent, while
// both timed rotations spoke -- one caller of each rotator carried the announcement and the other
// did not.
func TestEveryWalkSaysWhereItWent(t *testing.T) {
	t.Run("edge pool", func(t *testing.T) {
		b, _ := edgeCarrier(t, []string{"ip1:443", "ip2:443"}, snis("front-a", "front-b"))
		b.pretendConnected("ip1:443", "front-a")
		if !b.tunFailUntilItMoves(t, "ip1:443", "front-a") {
			t.Fatal("setup: the ladder never walked")
		}
		got := strings.Join(eventCodes(b, t), " ")
		if !strings.Contains(got, "down/edge-rotate") {
			t.Errorf("events = %s, want the edge it moved to", got)
		}
	})
	t.Run("direct pool", func(t *testing.T) {
		b, _, _ := peerCarrier(t, []string{"1.1.1.1:443", "2.2.2.2:443"}, nil)
		b.pretendConnected("1.1.1.1:443", "")
		if !b.tunFailUntilItMoves(t, "1.1.1.1:443", "") {
			t.Fatal("setup: the ladder never walked")
		}
		got := strings.Join(eventCodes(b, t), " ")
		if !strings.Contains(got, "down/peer-rotate") {
			t.Errorf("events = %s, want the destination it moved to", got)
		}
	})
	// One entry on an axis is a step to nowhere. Saying "rotated" there is a lie the operator would
	// read as movement, and it would arrive on every single verdict for the life of the outage.
	t.Run("nowhere to go", func(t *testing.T) {
		b, _ := edgeCarrier(t, []string{"ip1:443"}, snis("front-a"))
		b.pretendConnected("ip1:443", "front-a")
		b.tunFailUntilItMoves(t, "ip1:443", "front-a")
		got := strings.Join(eventCodes(b, t), " ")
		if strings.Contains(got, "-rotate") {
			t.Errorf("events = %s: a pool of one announced a rotation", got)
		}
	})
}

// The single-edge ECH key has two writers on two goroutines: the dial loop reads it on every attempt
// and the pin-poll loop rewrites it when the panel pushes a fresh one. Run under -race.
func TestTheECHKeyHasOneOwner(t *testing.T) {
	cliDev, _ := tunPair(t, "echown")
	cli := &TCP{dev: cliDev, cryptoOn: true, cipher: "aes-256-gcm", psk: "ech-one-owner-psk-abcdefghijkl",
		ws: true, wsTLS: true, wsHost: "front-a", wsPath: "/", addr: freeTCPPort(t),
		idle: connIdle, ping: pingEvery, isClient: true, closeCh: make(chan struct{})}
	cli.SetStatusPath(runningStatusPath(t, cli))
	if !cli.rc.polls() {
		t.Fatal("setup: the pin-poll goroutine would not run, so there is no second writer")
	}
	t.Cleanup(func() { cli.Close() })

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the pin-poll goroutine
		defer wg.Done()
		for i := 0; i < 300; i++ {
			key := base64.StdEncoding.EncodeToString([]byte{byte(i), 2, 3, 4, 5, 6, 7, 8})
			writeFileAtomic(cli.st.echCmdPath(), []byte(`{"snis":{"front-a":"`+key+`"}}`), 0o644)
			cli.pollPeerCmd()
		}
	}()
	go func() { // the dial goroutine
		defer wg.Done()
		for i := 0; i < 300; i++ {
			if c, _, _, err := cli.dialCarrier(); err == nil && c != nil {
				c.Close()
			}
		}
	}()
	wg.Wait()
}

// The tracker's live() runs with its lock released -- taking it there would mean holding it across the
// carrier's own -- so two samplers could commit out of order and publish a path older than one already
// published, with a fresh epoch on it. Every event site calls write(), and write() samples.
func TestThePathTrackerNeverGoesBackwards(t *testing.T) {
	var step atomic.Int64
	var tr pathTracker
	tr.setLive(func() (pathKey, bool) {
		n := step.Load()
		time.Sleep(time.Microsecond) // the real live() reads four atomics behind a pointer
		return pathKey{Src: "10.0.0.1", Sport: uint16(n), Dst: "10.0.0.2", Dport: 443}, true
	})

	var wg sync.WaitGroup
	deadline := time.Now().Add(time.Second)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				tr.sample()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for time.Now().Before(deadline) {
			step.Add(1)
			time.Sleep(50 * time.Microsecond)
		}
	}()

	// ONE observer, so the comparison itself cannot reorder: two of them can read in one order and
	// record in the other, which says nothing about the tracker.
	backward, seen, last := 0, 0, uint16(0)
	for time.Now().Before(deadline) {
		_, k, _ := tr.snapshot()
		if k.Sport < last {
			backward++
		}
		last = k.Sport
		seen++
	}
	wg.Wait()

	if seen < 100 || last < 10 {
		t.Fatalf("the probe never got going: %d reads, last sport %d", seen, last)
	}
	if backward > 0 {
		t.Errorf("the path only ever moved forward, and the tracker published an older one %d times "+
			"out of %d reads (now on sport %d)", backward, seen, last)
	}
}

// A local fact, not the ladder's verdict: this address cannot be bound on this host. It was recorded
// silently, so the panel showed a row turning suspect with nothing behind it.
func TestAnUnbindableSourceSaysWhyItBurned(t *testing.T) {
	b, _, sp := peerCarrier(t, []string{"1.1.1.1:443"}, []string{"127.0.0.1:0", "203.0.113.2:0"})
	if _, moved := b.rotateSourceTCP(true); !moved {
		t.Fatal("setup: the source did not rotate")
	}
	b.dialer(time.Second) // the dial is where the bind is actually tried

	if got := stateOf(sp.healthRows(), "src", "203.0.113.2:0"); got != stateSuspect {
		t.Fatalf("the unbindable source is %q, want %q", got, stateSuspect)
	}
	got := strings.Join(eventCodes(b, t), " ")
	if !strings.Contains(got, "burn/unbindable") {
		t.Errorf("events = %s, want a burn naming why: the row turns suspect either way", got)
	}
}
