package packet

import "testing"

// `active` is the one line in the status file that says what the carrier is ON. For a pooled edge
// carrier only the dial may write it, because only the dial knows a combo actually carried traffic --
// SetStatusPath deliberately starts it empty for exactly that reason.
//
// A rotation step moves the CURSOR, and a cursor is a plan. Publishing it as `active` tells the
// operator their tunnel is on an edge it has never connected to, and it disagrees with `pair` in the
// same file. Collapsing the edge pool onto PeerPool reintroduced this once: a shared publishActive()
// helper wrote the cursor on every walk, and a probe caught active=e2 while pair still said e1.
func TestARotationStepDoesNotWriteTheActiveLine(t *testing.T) {
	b, _, _ := edgeCarrier(t, []string{"e1", "e2", "e3"}, snis("s1", "s2"))
	b.rc.port.setRoll(func() bool { return true })
	ip, sni, _ := b.edgeCombo()
	b.pretendConnected(ip, sni.host)

	if got := b.readStatus(t).Active; got != "" {
		t.Fatalf("setup: a pooled edge carrier starts with no active line, got %q", got)
	}
	if !b.tunFailUntilItMoves(t, ip, sni.host) {
		t.Fatal("the ladder never walked, so nothing was exercised")
	}
	if got := b.readStatus(t).Active; got != "" {
		t.Fatalf("a walk published %q as the active line while the carrier is still on %s · %s and has "+
			"dialled nothing — the operator reads that line to find their tunnel", got, ip, sni.host)
	}

	b.operatorJump(t, "ip", "e3")
	if got := b.readStatus(t).Active; got != "" {
		t.Fatalf("an operator jump published %q; a jump moves the cursor too, and the dial that "+
			"follows is what proves the edge carries", got)
	}
}

// The other half, so the fix above cannot be "delete every setActive". A DIRECT carrier has no combo
// to wait for -- its destination is the whole story -- so its rotation and its jump both name where
// they went, and always did.
func TestADirectRotationStillNamesWhereItWent(t *testing.T) {
	b, pp, _ := peerCarrier(t, []string{"d1", "d2"}, nil)
	if _, moved := b.rotateDestTCP(true); !moved {
		t.Fatal("setup: a healthy two-entry pool did not rotate")
	}
	want := b.stTag + activeSep + pp.current()
	if got := b.readStatus(t).Active; got != want {
		t.Fatalf("after a direct rotation active is %q, want %q", got, want)
	}

	b.operatorJump(t, axisDst, "d1")
	if got := b.readStatus(t).Active; got != b.stTag+activeSep+"d1" {
		t.Fatalf("after a direct jump active is %q, want it to name d1", got)
	}
}
