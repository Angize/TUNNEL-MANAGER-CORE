package packet

import (
	"net"
	"testing"
	"time"
)

func TestConnectBudgetIsOnlySpentOnTheDead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	b := &TCP{}
	start := time.Now()
	c, err := b.dialer(connectTimeout).Dial("tcp", ln.Addr().String())
	el := time.Since(start)
	if err != nil {
		t.Fatalf("dial to a live listener failed: %v", err)
	}
	c.Close()
	if el > connectTimeout/4 {
		t.Fatalf("a live connect took %v of a %v budget — the budget is not the slack it is meant to be", el, connectTimeout)
	}
}

func TestACannotLandPinEndsInsideTenSeconds(t *testing.T) {

	worstGap := time.Duration(0)
	for i := 0; i < 40; i++ {
		if g := nextReconnectDelay(0); g > worstGap {
			worstGap = g
		}
	}
	attempts := time.Duration(pinFailRelease) * connectTimeout
	gaps := time.Duration(pinFailRelease-1) * worstGap
	total := attempts + gaps

	if total > 10*time.Second {
		t.Fatalf("a pin that cannot land takes up to %v (%d attempts x %v + %d gaps x %v) — over the ten "+
			"seconds an operator is willing to watch. Lower connectTimeout or pinFailRelease.",
			total, pinFailRelease, connectTimeout, pinFailRelease-1, worstGap)
	}

	if connectTimeout < 3*time.Second {
		t.Fatalf("connectTimeout is %v: under 3s the kernel's third SYN (t=3s) never goes out, so two lost "+
			"SYNs kill a healthy edge", connectTimeout)
	}
}
