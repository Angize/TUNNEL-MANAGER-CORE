//go:build linux

package packet

import (
	"testing"
)

func TestUDPRefusesASourceThisHostCannotBind(t *testing.T) {
	t.Run("a pin onto an unbindable source is abandoned, not consumed", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, unusableIP}, 0, "")
		b := &UDP{isClient: true}
		b.SetSourcePool(sp)
		if !sp.selectEntry(unusableIP) {
			t.Fatal("selectEntry rejected a pool member")
		}
		if !sp.isPinned() {
			t.Fatal("the pin did not take — the rest of this case would be vacuous")
		}

		b.adoptSourceUDP()

		if sp.isPinned() {
			t.Error("the jump is still in progress: it holds the whole pinTTL forcing a source that will not bind, and the next success releases it as LANDED over a tunnel that never moved")
		}
		if len(burnedIn(sp)) == 0 {
			t.Error("the unbindable source was not burned, so rotation comes straight back to it")
		}
		if cur := sp.current(); cur == unusableIP {
			t.Errorf("the pool still calls %s active — the panel names a source the datagram path never adopted", cur)
		}
	})

	t.Run("an unbindable first entry is burned at seed time", func(t *testing.T) {
		sp := NewPeerPool([]string{unusableIP, usableLoopbackIP}, 0, "")
		b := &UDP{isClient: true}
		b.SetSourcePool(sp)

		if len(burnedIn(sp)) == 0 {
			t.Error("the initial bind failed and nothing marked the entry bad: the socket is on the kernel default while the pool publishes that IP as Active, and with rotate=0 it is never retried")
		}
		if cur := sp.current(); cur == unusableIP {
			t.Errorf("the pool still calls %s active after its bind failed", cur)
		}
	})

	t.Run("a bindable source is neither burned nor un-pinned", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, "127.0.0.2"}, 0, "")
		b := &UDP{isClient: true}
		b.SetSourcePool(sp)
		if burned := burnedIn(sp); len(burned) > 0 {
			t.Fatalf("seeding a bindable source burned %v", burned)
		}
		if !sp.selectEntry("127.0.0.2") {
			t.Fatal("selectEntry rejected a pool member")
		}
		b.adoptSourceUDP()
		if burned := burnedIn(sp); len(burned) > 0 {
			t.Errorf("a pin onto a bindable source burned %v", burned)
		}
	})
}
