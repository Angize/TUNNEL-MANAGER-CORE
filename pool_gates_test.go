package main

import "testing"

// TestAPoolIsSomethingToRotate is what wantsDestPool/wantsSourcePool decide.
//
// The two gates differ on purpose. A DESTINATION pool is only worth building to rotate between
// entries, and one entry can neither be burned nor advanced off. A SOURCE pool of one is a fixed
// source that supersedes bind_ip, so the gate there is >=1 and a lone entry is the whole point.
//
// Neither of them gates the JUDGE any more. The node's verdict arrives in the tunnel's own mailbox
// (coreStatus.verdictPath), so a client with no pool at all still hears it and still spends the
// ladder's free rungs on it; a source pool with no destination pool is judged like any other.
func TestAPoolIsSomethingToRotate(t *testing.T) {
	for _, c := range []struct {
		name         string
		cfg          Config
		wantDst, src bool
	}{
		{"one destination is nothing to rotate between",
			Config{Role: "client", PeerIPs: []string{"a"}, SrcIPs: []string{"s1", "s2", "s3"}}, false, true},
		{"the ordinary rotating pair",
			Config{Role: "client", PeerIPs: []string{"a", "b"}, SrcIPs: []string{"s1", "s2"}}, true, true},
		{"one of each -- a fixed source that supersedes bind_ip",
			Config{Role: "client", PeerIPs: []string{"a"}, SrcIPs: []string{"s1"}}, false, true},
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
	}
}
