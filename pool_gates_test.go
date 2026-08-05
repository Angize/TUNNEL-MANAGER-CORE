package main

import "testing"

// TestASourcePoolAlwaysGetsAMailbox is the pairing invariant behind wantsDestPool/wantsSourcePool.
//
// The node writes BOTH its verdicts -- `ok` and `fail` -- to the DESTINATION pool's command file, and
// pollPins reads that file only when a destination pool exists. So a source pool without a destination
// pool is a rotation nobody can judge: every verdict the node sends is dropped in silence, nothing is
// ever burned, nothing is ever healed, and the timed rotation keeps walking onto a blocked source.
//
// That is what a >=2 gate on the destination produced for a client with one destination and several
// sources -- a shape the panel reaches the moment an operator removes IPs from the far node.
func TestASourcePoolAlwaysGetsAMailbox(t *testing.T) {
	for _, c := range []struct {
		name         string
		cfg          Config
		wantDst, src bool
	}{
		{"one destination, several sources -- the shape that was silently unjudged",
			Config{Role: "client", PeerIPs: []string{"a"}, SrcIPs: []string{"s1", "s2", "s3"}}, true, true},
		{"the ordinary rotating pair",
			Config{Role: "client", PeerIPs: []string{"a", "b"}, SrcIPs: []string{"s1", "s2"}}, true, true},
		{"one of each -- a fixed source that supersedes bind_ip",
			Config{Role: "client", PeerIPs: []string{"a"}, SrcIPs: []string{"s1"}}, true, true},
		{"destinations only",
			Config{Role: "client", PeerIPs: []string{"a", "b"}}, true, false},
		{"no pools configured at all",
			Config{Role: "client"}, false, false},
		{"a server chooses nothing -- both ends rotating would chase each other",
			Config{Role: "server", PeerIPs: []string{"a", "b"}, SrcIPs: []string{"s1", "s2"}}, false, false},
	} {
		dst, src := wantsDestPool(&c.cfg), wantsSourcePool(&c.cfg)
		if dst != c.wantDst || src != c.src {
			t.Errorf("%s: dest=%v source=%v, want dest=%v source=%v", c.name, dst, src, c.wantDst, c.src)
		}
		if src && !dst {
			t.Errorf("%s: a source pool with NO destination pool — the node's verdicts have nowhere to land", c.name)
		}
	}
}
