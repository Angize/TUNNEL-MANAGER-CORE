//go:build linux

package packet

import (
	"net"
	"testing"
)

func TestIPLinkAddressingMatrix(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s).To4() }
	real := ip("10.0.0.1")
	to := &net.IPAddr{IP: ip("8.8.8.8")}
	decoy := ip("185.51.200.10")
	forgedSrc := ip("192.0.2.7")
	realClient := ip("203.0.113.9")

	hdr := []struct {
		name             string
		l                ipLink
		wantSrc, wantDst net.IP
	}{
		{"direct", &directLink{r: &Raw{}}, real, to.IP},
		{"forge src", &forgedLink{r: &Raw{isClient: true}, spoofSrc: forgedSrc}, forgedSrc, to.IP},
		{"forge dst", &forgedLink{r: &Raw{isClient: true}, spoofDst: decoy}, real, decoy},
		{"forge both", &forgedLink{r: &Raw{isClient: true}, spoofSrc: forgedSrc, spoofDst: decoy}, forgedSrc, decoy},
		{"decoy server (src=decoy, no spoofDst)", &forgedLink{r: &Raw{}, spoofSrc: decoy, decoy: decoy, fixedPeer: realClient}, decoy, to.IP},
		{"src-only server (no forge)", &forgedLink{r: &Raw{}, spoofFd: -1, fixedPeer: realClient}, real, to.IP},
	}
	for _, c := range hdr {
		gotSrc, gotDst := c.l.header(real, to)
		if !gotSrc.Equal(c.wantSrc) || !gotDst.Equal(c.wantDst) {
			t.Errorf("%s: header = (%v,%v), want (%v,%v)", c.name, gotSrc, gotDst, c.wantSrc, c.wantDst)
		}
	}

	src := &net.IPAddr{IP: ip("172.16.9.9")}
	if got := (&directLink{r: &Raw{}}).replyTo(src); !got.IP.Equal(src.IP) {
		t.Errorf("directLink replyTo = %v, want the packet source %v", got.IP, src.IP)
	}
	if got := (&forgedLink{r: &Raw{}, fixedPeer: realClient}).replyTo(src); !got.IP.Equal(realClient) {
		t.Errorf("forgedLink replyTo with fixedPeer = %v, want %v", got.IP, realClient)
	}
	if got := (&forgedLink{r: &Raw{isClient: true}, spoofDst: decoy}).replyTo(src); !got.IP.Equal(src.IP) {
		t.Errorf("forgedLink replyTo without fixedPeer = %v, want the packet source %v", got.IP, src.IP)
	}

	fs := []struct {
		name string
		l    ipLink
		want bool
	}{
		{"direct filters", &directLink{r: &Raw{}}, true},
		{"src-forging client still filters (source not pinned)", &forgedLink{r: &Raw{isClient: true}, spoofSrc: forgedSrc}, true},
		{"dst-forging client does not filter", &forgedLink{r: &Raw{isClient: true}, spoofDst: decoy}, false},
		{"server with fixedPeer does not filter", &forgedLink{r: &Raw{}, fixedPeer: realClient}, false},
		{"decoy server does not filter", &forgedLink{r: &Raw{}, spoofSrc: decoy, decoy: decoy, fixedPeer: realClient}, false},
	}
	for _, c := range fs {
		if got := c.l.filterSrc(); got != c.want {
			t.Errorf("%s: filterSrc = %v, want %v", c.name, got, c.want)
		}
	}

	if (&directLink{r: &Raw{}}).pinsSource() {
		t.Error("directLink must not pin the source")
	}
	if !(&forgedLink{r: &Raw{}, spoofSrc: forgedSrc}).pinsSource() {
		t.Error("a forged source must pin the source (refuse a rotation pool)")
	}
	if (&forgedLink{r: &Raw{}, spoofDst: decoy}).pinsSource() {
		t.Error("a forged destination alone must not pin the source")
	}

	if (&directLink{r: &Raw{}}).fakeFD() != -1 {
		t.Error("directLink fakeFD must be -1")
	}
	if got := (&forgedLink{r: &Raw{}, spoofFd: 7}).fakeFD(); got != 7 {
		t.Errorf("forgedLink fakeFD = %d, want the spoofFd 7", got)
	}
}
