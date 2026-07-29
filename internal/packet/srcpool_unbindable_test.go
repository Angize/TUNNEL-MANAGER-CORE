//go:build linux

package packet

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// unbindableSrc is in TEST-NET-3 (RFC 5737, reserved for documentation), so it is never configured
// on a host — the same state a source-pool IP reaches when a secondary address is not re-added after
// a provider event.
const unbindableSrc = "203.0.113.9"

// TestUnusableSourceIsBurnedNotSilentlyIgnored drives the real dialer — the function every dial goes
// through to install LocalAddr — over a source pool whose current entry cannot be bound.
//
// Skipping the bind and dialing from the kernel default is deliberate (dialLoop charges a failed dial
// to the DESTINATION, so failing here would burn the destination pool one endpoint at a time while
// the peers are perfectly reachable). What was missing is everything else: the entry stayed HEALTHY
// and ACTIVE, so every rotation came straight back to it, the panel kept showing the tunnel sourced
// from an IP it never leaves from, and source rotation was silently off. The warning was a single
// sync.Once for the whole process, so a pool that rotated onto a SECOND dead IP said nothing at all.
func TestUnusableSourceIsBurnedNotSilentlyIgnored(t *testing.T) {
	sp := NewPeerPool([]string{unbindableSrc, "127.0.0.1"}, true, 0, "")
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
	if sp.health[unbindableSrc] == nil {
		t.Fatalf("%s was not burned, so every rotation comes straight back to it and the pool still shows it healthy", unbindableSrc)
	}
	if got := sp.current(); got != "127.0.0.1" {
		t.Fatalf("the pool stayed on the unusable source (%s) instead of walking to one that binds", got)
	}

	// The next dial must actually bind the working source — the point of burning the other one.
	d = b.dialer(time.Second)
	la, ok := d.LocalAddr.(*net.TCPAddr)
	if !ok || la.IP.String() != "127.0.0.1" {
		t.Fatalf("the dialer bound %v, want 127.0.0.1", d.LocalAddr)
	}
	if got := b.lastSourceUsed(); got != "127.0.0.1" {
		t.Fatalf("lastSourceUsed = %q, want 127.0.0.1", got)
	}
}

// TestUnusableSourceWarnsPerEntry: the warning is per source, not per process. With one sync.Once a
// pool that walked onto a second dead IP was completely silent, so the operator could not tell one
// bad entry from several.
func TestUnusableSourceWarnsPerEntry(t *testing.T) {
	b := &TCP{}
	b.dropUnusableSource("a", "a", false)
	if _, seen := b.srcWarned.Load("a"); !seen {
		t.Fatal("the first unusable source was not recorded")
	}
	b.dropUnusableSource("b", "b", false)
	if _, seen := b.srcWarned.Load("b"); !seen {
		t.Fatal("a SECOND unusable source was swallowed — that is the sync.Once behaviour")
	}
}

// TestSourcePinSurvivesADialThatNeverBound is the end-to-end half: a real direct-tcp client against a
// real in-process server, with the source pool PINNED to an IP that cannot be bound. The dial
// succeeds (from the kernel default, over loopback) and reaches dialLoop's pin-release site.
//
// The pin must NOT be consumed. It is an operator instruction to leave from a specific IP, and this
// connection does not. Before the fix lastSrc held the REQUESTED source, so the comparison matched
// its own input: the panel reported the jump as landed, released the pin, resumed rotation, and the
// tunnel went on leaving from the kernel default. A pin that cannot land now simply lapses on its
// TTL, which is exactly what pinUntil is for.
func TestSourcePinSurvivesADialThatNeverBound(t *testing.T) {
	const psk = "srcpin-unbindable-psk-0123456789"
	const cipher = "aes-256-gcm"
	srvDev, _ := tunPair(t, "supsrv")
	cliDev, _ := tunPair(t, "supcli")
	ka := time.Second

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	srv, err := ListenTCP([]string{addr}, srvDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	cli, err := DialTCP(addr, cliDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	sp := NewPeerPool([]string{"127.0.0.1", unbindableSrc}, true, 0, "")
	cli.SetSourcePool(sp)
	if !sp.selectEntry(unbindableSrc) {
		t.Fatalf("selectEntry(%s) refused the pin", unbindableSrc)
	}

	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	waitFor(t, 10*time.Second, "the client connected", func() bool { return cli.curConn.Load() != nil })
	if got := cli.lastSourceUsed(); got != "" {
		t.Fatalf("the connection reports source %q, but %s cannot be bound — nothing was bound at all", got, unbindableSrc)
	}
	if !sp.isPinned() {
		t.Fatalf("the source pin was consumed by a connection that never left from %s: the panel shows the jump landed and rotation resumes, while the tunnel sources from the kernel default", unbindableSrc)
	}
}
