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
// through to install LocalAddr — over a source pool whose current entry cannot be bound. Skipping the
// bind is deliberate, since dialLoop charges a failed dial to the DESTINATION. What must not be skipped
// is the rest: an entry left HEALTHY and ACTIVE brings every rotation straight back to it, silently.
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
	if sp.health.recs[unbindableSrc] == nil {
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

// TestManualJumpToAnUnusableSourceIsAbandonedNotConsumed is the end-to-end half: a real direct-tcp client
// against a real server, with an operator jump aimed at a source IP that cannot be bound. A jump ends one
// of two ways — the carrier lands on it, or it is proven impossible — and this is the second. The
// observable difference is the burn: an abandoned jump takes the IP out of rotation, a landed one does not.
func TestManualJumpToAnUnusableSourceIsAbandonedNotConsumed(t *testing.T) {
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
	// Abandoned, not consumed-as-landed: the jump is over AND the IP is out of rotation.
	waitFor(t, 5*time.Second, "the impossible jump was abandoned", func() bool { return !sp.isPinned() })
	if sp.health.recs[unbindableSrc] == nil {
		t.Fatalf("%s was reported as a landed jump instead of an abandoned one: it stays active in the pool and the next rotation walks straight back onto it", unbindableSrc)
	}
	if got := sp.current(); got != "127.0.0.1" {
		t.Fatalf("after abandoning the jump the pool is still on %s instead of a source that binds", got)
	}
}

// TestAbandoningAJumpNeverCancelsADifferentOne: the operator can re-aim between the moment the dialer
// reads the source and the moment it discovers the bind is impossible. Cancelling must therefore be
// keyed — an unkeyed release would silently throw away the jump they just made.
func TestAbandoningAJumpNeverCancelsADifferentOne(t *testing.T) {
	sp := NewPeerPool([]string{unbindableSrc, "127.0.0.1"}, true, 0, "")
	if !sp.selectEntry("127.0.0.1") { // the operator has since aimed at a DIFFERENT entry
		t.Fatal("selectEntry refused the jump")
	}
	if sp.pinCannotLand(unbindableSrc) {
		t.Fatal("a stale discovery about another IP cancelled the operator's current jump")
	}
	if !sp.isPinned() {
		t.Fatal("the operator's jump to 127.0.0.1 was thrown away")
	}
	if !sp.pinCannotLand("127.0.0.1") {
		t.Fatal("a jump proven impossible on its OWN key was not abandoned")
	}
	if sp.isPinned() {
		t.Fatal("the jump is still forcing an endpoint that cannot be used")
	}
}
