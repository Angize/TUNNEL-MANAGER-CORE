package packet

import (
	"testing"
	"time"
)

// TestWarmStandbyResumesRotationAfterThePoolHeals drives the REAL warm-standby manager against a live
// in-process ws server, through the sequence that froze rotation for the life of a connection: with one
// edge healthy the standby is built on the ACTIVE's own edge, the tick correctly refuses to promote it,
// and requestStandby() is a hard no-op while one is held. The assertion is that the edge moves on heal.
func TestWarmStandbyResumesRotationAfterThePoolHeals(t *testing.T) {
	const psk = "warm-heal-psk-abcdefghijklmnopq"
	const cipher = "aes-256-gcm"
	srvDev, _ := tunPair(t, "whsrv")
	cliDev, _ := tunPair(t, "whcli")
	ka := time.Second
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, ka, false, true, psk, cipher, "")
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	// One edge IP (the in-process server) with two SNIs, so the two healthy combos differ only on
	// the SNI axis — the smallest pool that can express "the standby is on the active's own edge".
	pool := newWSPool([]string{addr}, snis("front-a", "front-b"), false, "")
	// Burn front-b far into the future, leaving exactly ONE healthy combo.
	pool.mu.Lock()
	pool.sniHealth["front-b"] = &healthRec{state: stateSuspect, nextRetest: pool.now() + 86400}
	pool.mu.Unlock()

	cli := &TCP{dev: cliDev, cryptoOn: true, cipher: cipher, keepalive: ka, psk: psk,
		ws: true, wsTLS: false, pool: pool, warmStandby: true, rotate: 300 * time.Millisecond,
		idle: idleFor(ka), isClient: true, addr: "pool", closeCh: make(chan struct{})}
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	waitFor(t, 5*time.Second, "active up", func() bool { return cli.cur.Load() != nil })
	waitFor(t, 5*time.Second, "warm standby up", func() bool { return cli.standby.Load() != nil })
	if got := poolActive(pool); got != addr+activeSep+"front-a" {
		t.Fatalf("the only healthy combo should be active, got %s", got)
	}
	// Let several rotation ticks pass on the frozen state, so the test really is exercising the
	// same-edge skip and not just racing the first build.
	time.Sleep(1500 * time.Millisecond)
	if got := poolActive(pool); got != addr+activeSep+"front-a" {
		t.Fatalf("rotation moved onto a burned edge: %s", got)
	}

	pool.retestResult("sni", "front-b", true) // the block lifted — front-b is healthy again

	waitFor(t, 10*time.Second, "proactive rotation resumed once the pool healed", func() bool {
		return poolActive(pool) == addr+activeSep+"front-b"
	})
}

// TestHasHealthyEdgeOtherThan pins the query the manager decides on. It must answer on the COMBO,
// not the IP: with a single-IP pool an SNI-only move is still a real rotation, so answering "no
// distinct IP" there would keep rotation frozen exactly where the fix is supposed to release it.
func TestHasHealthyEdgeOtherThan(t *testing.T) {
	burn := func(p *wsPool, kind string, keys ...string) {
		p.mu.Lock()
		for _, k := range keys {
			p.healthMap(kind)[k] = &healthRec{state: stateSuspect, nextRetest: p.now() + 86400}
		}
		p.mu.Unlock()
	}
	t.Run("one ip, one healthy sni -> nothing else", func(t *testing.T) {
		p := newWSPool([]string{"1.1.1.1"}, snis("a", "b"), false, "")
		burn(p, "sni", "b")
		if p.hasHealthyEdgeOtherThan("1.1.1.1" + activeSep + "a") {
			t.Fatal("only one healthy combo exists, yet the pool claims another")
		}
	})
	t.Run("one ip, two healthy snis -> an sni-only move is a real rotation", func(t *testing.T) {
		p := newWSPool([]string{"1.1.1.1"}, snis("a", "b"), false, "")
		if !p.hasHealthyEdgeOtherThan("1.1.1.1" + activeSep + "a") {
			t.Fatal("front-b is healthy on the same ip — that is a rotation the manager must be allowed to make")
		}
	})
	t.Run("second ip healthy", func(t *testing.T) {
		p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, snis("a"), false, "")
		if !p.hasHealthyEdgeOtherThan("1.1.1.1" + activeSep + "a") {
			t.Fatal("a healthy second ip was not seen")
		}
	})
	t.Run("everything burned", func(t *testing.T) {
		p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, snis("a", "b"), false, "")
		burn(p, "ip", "1.1.1.1", "2.2.2.2")
		if p.hasHealthyEdgeOtherThan("1.1.1.1" + activeSep + "a") {
			t.Fatal("no edge is healthy, yet the pool claims one — this would rebuild a standby every interval")
		}
	})
	t.Run("a burned sni cannot rescue a healthy ip", func(t *testing.T) {
		p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, snis("a", "b"), false, "")
		burn(p, "sni", "b")
		burn(p, "ip", "2.2.2.2")
		if p.hasHealthyEdgeOtherThan("1.1.1.1" + activeSep + "a") {
			t.Fatal("both axes must be healthy for a combo to count")
		}
	})
}
