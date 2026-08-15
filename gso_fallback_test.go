package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// These drive openTUN — the function main() itself calls — not a helper beside it.
// The class they close: a THROUGHPUT knob must never be able to keep the tunnel
// down, and the startup line must never claim gso is on when it is not.

type openCall struct {
	name string
	mtu  int
	addr string
	gso  bool
	n    int // queues asked for
}

// scriptedOpener stands in for tun.Open: it records each call and answers from fn.
func scriptedOpener(t *testing.T, calls *[]openCall, fn func(gso bool) error) tunOpener {
	t.Helper()
	return func(name string, mtu int, addr string, gso bool, n int) ([]*tun.Device, error) {
		*calls = append(*calls, openCall{name, mtu, addr, gso, n})
		if err := fn(gso); err != nil {
			return nil, err
		}
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		t.Cleanup(func() { r.Close(); w.Close() })
		return []*tun.Device{tun.FromFile(r, name)}, nil
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// A kernel or container without IFF_VNET_HDR used to take the whole tunnel down:
// tun.Open failed, main called log.Fatalf and systemd restarted the unit forever.
func TestAKernelWithoutVnetHdrGetsAWorkingTunnelWithoutGSO(t *testing.T) {
	logs := captureLog(t)
	var calls []openCall
	open := scriptedOpener(t, &calls, func(gso bool) error {
		if gso {
			return fmt.Errorf("TUNSETIFF (vnet-hdr): %w: %w", tun.ErrGSOUnsupported, syscall.EINVAL)
		}
		return nil
	})

	devs, gsoOn, err := openTUN(open, "tnl7", 1380, "10.200.0.1/24", true, 1)
	if err != nil {
		t.Fatalf("a missing vnet-hdr must not be fatal, got %v", err)
	}
	if len(devs) == 0 || devs[0] == nil {
		t.Fatal("no device returned")
	}
	if gsoOn {
		t.Fatal("openTUN reported gso ON after falling back — the startup line would lie")
	}
	if len(calls) != 2 {
		t.Fatalf("want an open then one retry, got %d: %+v", len(calls), calls)
	}
	if !calls[0].gso || calls[1].gso {
		t.Fatalf("want gso=true then gso=false, got %v then %v", calls[0].gso, calls[1].gso)
	}
	// The retry must differ in exactly one thing. Reopening with a different name,
	// MTU or address would build a tunnel nobody configured.
	if calls[1].name != calls[0].name || calls[1].mtu != calls[0].mtu || calls[1].addr != calls[0].addr {
		t.Fatalf("the retry changed more than gso: %+v vs %+v", calls[0], calls[1])
	}
	if !strings.Contains(logs.String(), "gso is not available") {
		t.Fatalf("the fallback must be logged, got %q", logs.String())
	}
}

// The retry exists for gso and nothing else: a failure from a later step (the `ip`
// commands, a name already in use) must stay fatal on the first try.
func TestAFailureThatIsNotAboutGSOIsNotRetried(t *testing.T) {
	var calls []openCall
	open := scriptedOpener(t, &calls, func(bool) error {
		return fmt.Errorf("ip addr add: %w", syscall.EEXIST)
	})

	if _, _, err := openTUN(open, "tnl7", 1380, "10.200.0.1/24", true, 1); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("want the original error, got %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("a failure unrelated to gso must not be retried, got %d opens: %+v", len(calls), calls)
	}
}

// ErrGSOUnsupported cannot tell "no vnet-hdr" from "no CAP_NET_ADMIN" — same ioctl,
// and the errno does not separate them. So when the plain open fails too, gso was
// never the problem: report the SECOND error and claim nothing about gso.
func TestWhenThePlainOpenFailsTooTheRealCauseIsReported(t *testing.T) {
	logs := captureLog(t)
	var calls []openCall
	open := scriptedOpener(t, &calls, func(gso bool) error {
		if gso {
			return fmt.Errorf("TUNSETIFF (vnet-hdr): %w: %w", tun.ErrGSOUnsupported, syscall.EPERM)
		}
		return fmt.Errorf("TUNSETIFF: %w", syscall.EPERM)
	})

	_, gsoOn, err := openTUN(open, "tnl7", 1380, "10.200.0.1/24", true, 1)
	if err == nil {
		t.Fatal("want the real cause, got nil")
	}
	if errors.Is(err, tun.ErrGSOUnsupported) {
		t.Fatalf("blamed gso for a failure that survived turning gso off: %v", err)
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("want EPERM, got %v", err)
	}
	if gsoOn {
		t.Fatal("gso reported on after a failed open")
	}
	if len(calls) != 2 {
		t.Fatalf("want one retry, got %d: %+v", len(calls), calls)
	}
	if strings.Contains(logs.String(), "gso is not available") {
		t.Fatalf("claimed gso was unavailable without proving it, got %q", logs.String())
	}
}

// The happy path must be untouched: one open, gso stays on, nothing logged about it.
func TestAKernelWithGSOOpensOnceAndKeepsIt(t *testing.T) {
	logs := captureLog(t)
	var calls []openCall
	open := scriptedOpener(t, &calls, func(bool) error { return nil })

	devs, gsoOn, err := openTUN(open, "tnl7", 1380, "10.200.0.1/24", true, 1)
	if err != nil || len(devs) == 0 || devs[0] == nil {
		t.Fatalf("open failed: %v", err)
	}
	if !gsoOn {
		t.Fatal("gso was available and must stay on")
	}
	if len(calls) != 1 {
		t.Fatalf("want exactly one open, got %d: %+v", len(calls), calls)
	}
	if strings.Contains(logs.String(), "gso is not available") {
		t.Fatalf("logged a fallback that never happened, got %q", logs.String())
	}
}

// gso=false must reach tun.Open as false and be reported as false.
func TestGSOOffIsPassedThroughUntouched(t *testing.T) {
	var calls []openCall
	open := scriptedOpener(t, &calls, func(bool) error { return nil })

	if _, gsoOn, err := openTUN(open, "tnl7", 1380, "10.200.0.1/24", false, 1); err != nil || gsoOn {
		t.Fatalf("gso=false must stay off: gsoOn=%v err=%v", gsoOn, err)
	}
	if len(calls) != 1 || calls[0].gso {
		t.Fatalf("want one open with gso=false, got %+v", calls)
	}
}
