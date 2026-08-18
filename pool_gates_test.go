package main

import "testing"

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
