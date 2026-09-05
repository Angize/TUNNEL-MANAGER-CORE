//go:build linux

package packet

import (
	"log"
	"net"
	"strings"
	"testing"
)

const unusableIP = "192.0.2.77"

const usableLoopbackIP = "127.0.0.1"

func TestRawRefusesASourceThisHostCannotSendFrom(t *testing.T) {

	t.Run("raw rotation undoes the move", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, unusableIP}, 0)
		r := &Raw{isClient: true}
		r.link = &directLink{r: r}
		r.SetSourcePool(sp)
		if got := srcOf(r.localIP.Load()); got != usableLoopbackIP {
			t.Fatalf("seeded source %q, want %s", got, usableLoopbackIP)
		}
		r.rotateSourceRaw(true)
		if got := srcOf(r.localIP.Load()); got != usableLoopbackIP {
			t.Errorf("the carrier now stamps %s, which this host cannot send from — on the udp/tcp raw profiles every packet is dropped from here on", got)
		}
		if cur := sp.current(); cur != usableLoopbackIP {
			t.Errorf("the pool's active source is %s but the packets still leave from %s: the panel names an address the tunnel is not using", cur, usableLoopbackIP)
		}
	})

	t.Run("a raw jump onto an unusable source is refused, not adopted", func(t *testing.T) {
		var sink syncBuf
		old := log.Writer()
		log.SetOutput(&sink)
		defer log.SetOutput(old)

		sp := NewPeerPool([]string{usableLoopbackIP, unusableIP}, 0)
		r := &Raw{isClient: true}
		r.link = &directLink{r: r}
		r.SetSourcePool(sp)
		if !sp.selectEntry(unusableIP) {
			t.Fatal("selectEntry rejected a pool member")
		}
		if got := sp.current(); got != unusableIP {
			t.Fatalf("the jump did not take (pool is on %q) — the rest of this case would be vacuous", got)
		}
		r.adoptSourceRaw()
		if got := srcOf(r.localIP.Load()); got == unusableIP {
			t.Error("the jump was adopted: the tunnel now stamps a source this host cannot send from, and on the udp/tcp raw profiles that is a silent blackout")
		}
		if burned := burnedIn(sp); !burned[unusableIP] {
			t.Error("the unusable source was not condemned, so the walk comes straight back to it")
		}
		if got := sink.String(); !strings.Contains(got, unusableIP) {
			t.Errorf("nothing named the unusable source — the operator sees a dead tunnel and no reason.\nlog was:\n%s", got)
		}
	})

	t.Run("raw seed refuses an unusable first entry", func(t *testing.T) {
		sp := NewPeerPool([]string{unusableIP, usableLoopbackIP}, 0)
		r := &Raw{isClient: true}
		r.link = &directLink{r: r}
		r.SetSourcePool(sp)
		if got := srcOf(r.localIP.Load()); got == unusableIP {
			t.Error("the pool's first entry was seeded unchecked: every packet from the very first one carries a source this host cannot send from")
		}
	})
}

func srcOf(a *net.IPAddr) string {
	if a == nil {
		return ""
	}
	return a.IP.String()
}
