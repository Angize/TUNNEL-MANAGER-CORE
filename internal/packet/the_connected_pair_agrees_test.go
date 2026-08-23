package packet

import (
	"testing"
	"time"
)

// Through the REAL connect, not the harness. pretendConnected builds the pair itself, so every test
// that used it agreed with whatever the test passed -- and said nothing about the line in dialLoop
// that builds it in production. That line kept the old axis order through the swap, and the whole
// suite stayed green: the status published a domain under low_kind "ip", the node keyed its verdict on
// that, and rotateLowTCP burned the domain into the EDGE's health map.
func TestTheConnectedPairAgreesWithTheKindsItIsPublishedUnder(t *testing.T) {
	const psk = "ws-pair-agree-psk-abcdefghijklmn"
	srvDev, _ := tunPair(t, "wpasrv")
	cliDev, _ := tunPair(t, "wpacli")
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, false, true, psk, "aes-256-gcm", "")
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	const domain = "front-a"
	pool := newWSPool([]string{addr}, snis(domain))
	cli := &TCP{dev: cliDev, cryptoOn: true, cipher: "aes-256-gcm", psk: psk,
		ws: true, wsTLS: false, pool: pool,
		idle: connIdle, ping: pingEvery, isClient: true, addr: "pool", closeCh: make(chan struct{})}
	cli.SetStatusPath(runningStatusPath(t, cli))
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	waitFor(t, 5*time.Second, "carrier up", func() bool { return cli.cur.Load() != nil })
	waitFor(t, 2*time.Second, "the pair is published", func() bool {
		low, _ := cli.livePairNow()
		return low != ""
	})

	low, high := cli.livePairNow()
	lowKind, highKind := cli.rc.pair.kinds()
	if lowKind != "ip" || highKind != "sni" {
		t.Fatalf("setup: the edge pool reports kinds %q/%q", lowKind, highKind)
	}
	if low != addr {
		t.Errorf("the low half is %q under low_kind %q, but the edge is %q. The node keys its verdict on "+
			"this pair and the walk burns the low half into the edge's health map", low, lowKind, addr)
	}
	if high != domain {
		t.Errorf("the high half is %q under high_kind %q, want the domain %q", high, highKind, domain)
	}

	// ...and the same pair, as the node actually reads it. The file is refreshed by a one-second
	// sampler, so wait for it rather than racing it.
	waitFor(t, 3*time.Second, "the status file carries the pair", func() bool {
		return cli.readStatus(t).Pair.Low != ""
	})
	st := cli.readStatus(t)
	if st.Pair.Low != addr || st.Pair.High != domain {
		t.Errorf("the status file says low=%q high=%q; the node copies these straight into its verdict",
			st.Pair.Low, st.Pair.High)
	}
}
