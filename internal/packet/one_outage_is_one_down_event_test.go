//go:build linux

package packet

import (
	"testing"
	"time"
)

// A pooled edge carrier wrote its outage TWICE. The cause is consumed by takeLastErr inside the switch
// and published there, and then the tail of the same iteration publishes again with what takeLastErr
// left behind -- the empty string, which classifyErr spells "closed". So every real outage on ws-pool,
// http and grpc landed in the ring as the true cause followed by a meaningless second line, and the
// operator's outage count for those carriers ran at twice the truth. A plain tcp pool never had it:
// the early publish is behind edgePool().
func TestOneOutageIsOneDownEventOnAPooledEdge(t *testing.T) {
	const psk = "one-outage-one-down-event-psk-abcd"
	srvDev, _ := tunPair(t, "1dnsrv")
	cliDev, _ := tunPair(t, "1dncli")
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, false, true, psk, "aes-256-gcm", "")
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	cli := edgeTCP([]string{addr}, snis("front-a"), 0)
	cli.dev, cli.cryptoOn, cli.cipher, cli.psk, cli.wsTLS = cliDev, true, "aes-256-gcm", psk, false
	cli.SetStatusPath(runningStatusPath(t, cli))
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	waitFor(t, 5*time.Second, "carrier up", func() bool { return cli.cur.Load() != nil })
	before := len(cli.readStatus(t).Events)

	cf := cli.cur.Load()
	if cf == nil {
		t.Fatal("the carrier went away before the test could drop it")
	}
	cf.conn.Close()

	waitFor(t, 10*time.Second, "carrier back up", func() bool {
		c := cli.cur.Load()
		return c != nil && c != cf
	})

	var downs []string
	for _, e := range cli.readStatus(t).Events[before:] {
		if e.Kind == "down" {
			downs = append(downs, e.Code)
		}
	}
	t.Logf("down events for ONE dropped connection: %v", downs)

	real := 0
	for _, c := range downs {
		if c != "edge-walk" {
			real++
		}
	}
	if real != 1 {
		t.Errorf("one dropped connection produced %d outage events (%v), want 1 -- the second is what "+
			"takeLastErr leaves behind once the first has already consumed the cause", real, downs)
	}
}
