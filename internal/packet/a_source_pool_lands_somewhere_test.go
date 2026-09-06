//go:build linux

package packet

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func loopbackAliases(t *testing.T) []string {
	t.Helper()
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("no interface addresses: %v", err)
	}
	var out []string
	for _, a := range ifaces {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || !n.IP.IsLoopback() {
			continue
		}
		out = append(out, n.IP.String())
	}
	if len(out) == 0 {
		t.Skip("no loopback IPv4 address to bind")
	}
	return out
}

// A source pool whose first entry is gone from the host. PeerPool.fail burns it AND walks the cursor
// forward, so the pool now reads as if the second entry were live -- but nothing ever bound it. The
// tunnel egressed from whatever the kernel routed it out of while the panel named an address that had
// never been tried, and the next tun-probe verdict burned that one too: both burned, neither used.
func TestASourceThatWillNotBindWalksOnToOneThatDoes(t *testing.T) {
	good := loopbackAliases(t)[0]
	const gone = "192.0.2.77"

	t.Run("udp", func(t *testing.T) {
		dev, _ := tunPair(t, "srcudp")
		b, err := Dial("127.0.0.1:9", dev, false, true, "a-psk-for-the-source-walk", "aes-256-gcm", false, 0, 0)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		t.Cleanup(func() { b.Close() })
		b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))

		sp := NewPeerPool([]string{gone, good}, 0)
		b.SetSourcePool(sp)

		la, ok := b.conn.Load().LocalAddr().(*net.UDPAddr)
		if !ok || la.IP.String() != good {
			t.Fatalf("the socket is bound to %v, want %s. The unbindable entry was burned and the cursor "+
				"moved on, so the pool says %s is live -- the socket has to actually be on it",
				la, good, sp.current())
		}
		if sp.current() != good {
			t.Fatalf("the cursor sits on %s, want %s", sp.current(), good)
		}
		if burnedIn(sp)[good] {
			t.Fatalf("%s bound and was burned anyway", good)
		}
	})

	t.Run("raw", func(t *testing.T) {
		r := &Raw{isClient: true, profile: "udp", closeCh: make(chan struct{})}
		r.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))

		sp := NewPeerPool([]string{gone, good}, 0)
		r.SetSourcePool(sp)

		lip := r.localIP.Load()
		if lip == nil || lip.IP.String() != good {
			t.Fatalf("the forged source is %v, want %s -- raw stores an IP instead of binding a socket, "+
				"but the walk-on rule is the same one", lip, good)
		}
		if sp.current() != good {
			t.Fatalf("the cursor sits on %s, want %s", sp.current(), good)
		}
	})
}

// Every entry is unusable. The pool must not spin: one pass, then give up and leave the kernel to
// choose, rather than looping over a pool that can never land.
func TestASourcePoolWithNothingUsableGivesUpAfterOnePass(t *testing.T) {
	dev, _ := tunPair(t, "srcnone")
	b, err := Dial("127.0.0.1:9", dev, false, true, "a-psk-for-the-empty-walk", "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))

	sp := NewPeerPool([]string{"192.0.2.77", "192.0.2.78"}, 0)
	done := make(chan struct{})
	go func() { b.SetSourcePool(sp); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SetSourcePool did not return: the walk over an all-unusable pool never terminates")
	}

	burned := burnedIn(sp)
	if !burned["192.0.2.77"] || !burned["192.0.2.78"] {
		t.Fatalf("burned = %v, want both entries condemned after the pass", burned)
	}
}
