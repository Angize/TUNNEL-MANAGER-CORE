package packet

import (
	"testing"
	"time"
)

func TestNoClockGivesUpTheSession(t *testing.T) {
	const ka = time.Second
	cli, srv, _ := poollessClient(t, "noclock")

	for cli.sealer() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	was := cli.session.Load()

	srv.Close()

	silent := 3 * time.Second
	start := time.Now()
	for time.Since(start) < silent {
		if cli.session.Load() != was || cli.sealer() == nil {
			t.Fatalf("the session was given up %v after the peer went silent and no verdict asked for it "+
				"-- something is still re-handshaking on a clock",
				time.Since(start).Round(time.Millisecond))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
