//go:build linux

package packet

import (
	"fmt"
	"net"
	"testing"
	"time"
)

const unbindableSrc = "203.0.113.9"

func TestUnusableSourceIsBurnedNotSilentlyIgnored(t *testing.T) {
	sp := NewPeerPool([]string{unbindableSrc, "127.0.0.1"}, 0)
	b := &TCP{sp: sp}
	if got := b.sourceIP(); got != unbindableSrc {
		t.Fatalf("setup: the pool should start on %s, got %s", unbindableSrc, got)
	}

	d := b.dialer(time.Second)
	if d.LocalAddr != nil {
		t.Fatalf("the dialer bound %v, which the kernel cannot honour", d.LocalAddr)
	}
	if got := b.lastSourceUsed(); got != "" {
		t.Fatalf("lastSourceUsed reports %q for a dial that applied no bind — a source pin would be released against it", got)
	}
	if sp.health.recs[unbindableSrc] == nil {
		t.Fatalf("%s was not burned, so every rotation comes straight back to it and the pool still shows it healthy", unbindableSrc)
	}
	if got := sp.current(); got != "127.0.0.1" {
		t.Fatalf("the pool stayed on the unusable source (%s) instead of walking to one that binds", got)
	}

	d = b.dialer(time.Second)
	la, ok := d.LocalAddr.(*net.TCPAddr)
	if !ok || la.IP.String() != "127.0.0.1" {
		t.Fatalf("the dialer bound %v, want 127.0.0.1", d.LocalAddr)
	}
	if got := b.lastSourceUsed(); got != "127.0.0.1" {
		t.Fatalf("lastSourceUsed = %q, want 127.0.0.1", got)
	}
}

func TestUnusableSourceWarnsPerEntry(t *testing.T) {
	b := &TCP{}
	if ip := adoptableSource("tcp", "a", &b.srcWarned); ip != nil {
		t.Fatalf("%q is not an address the kernel can bind", "a")
	}
	if _, seen := b.srcWarned.Load("a"); !seen {
		t.Fatal("the first unusable source was not recorded")
	}
	adoptableSource("tcp", "b", &b.srcWarned)
	if _, seen := b.srcWarned.Load("b"); !seen {
		t.Fatal("a SECOND unusable source was swallowed — that is the sync.Once behaviour")
	}
}

func TestManualJumpToAnUnusableSourceIsAbandonedNotConsumed(t *testing.T) {
	const psk = "srcpin-unbindable-psk-0123456789"
	const cipher = "aes-256-gcm"
	srvDev, _ := tunPair(t, "supsrv")
	cliDev, _ := tunPair(t, "supcli")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	srv, err := ListenTCP([]string{addr}, srvDev, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	cli, err := DialTCP(addr, cliDev, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	sp := NewPeerPool([]string{"127.0.0.1", unbindableSrc}, 0)
	cli.SetSourcePool(sp)
	if !sp.selectEntry(unbindableSrc) {
		t.Fatalf("selectEntry(%s) refused the jump", unbindableSrc)
	}

	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	waitFor(t, 10*time.Second, "the client connected", func() bool { return cli.curConn.Load() != nil })
	if got := cli.lastSourceUsed(); got != "" {
		t.Fatalf("the connection reports source %q, but %s cannot be bound — nothing was bound at all", got, unbindableSrc)
	}

	waitFor(t, 5*time.Second, "the impossible source was condemned", func() bool {
		sp.mu.Lock()
		defer sp.mu.Unlock()
		return sp.health.recs[unbindableSrc] != nil
	})
	if got := sp.current(); got != "127.0.0.1" {
		t.Fatalf("after abandoning the jump the pool is still on %s instead of a source that binds", got)
	}
}
