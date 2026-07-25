//go:build linux

package packet

import (
	"net"
	"testing"
)

// TestRawPinnedSrc covers which local address a raw send is pinned to.
//
// Regression guard for a feature that was inert: a raw CLIENT with a source pool rotated the pool,
// logged "rotated source to X" and moved the pool's status file, while every packet still left from
// the kernel-default address. The source only ever reached the wire through the IP_HDRINCL branch,
// which exists solely when spoofing is configured — and rotateSourceRaw deliberately no-ops under
// spoofSrc, so the two conditions were mutually exclusive and the pool could never take effect.
func TestRawPinnedSrc(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s).To4() }

	t.Run("client with a source pool pins the pool's current source", func(t *testing.T) {
		r := &Raw{spoofFd: -1, pktFd: -1, fakeFd: -1,
			sp: NewPeerPool([]string{"10.9.9.1", "10.9.9.2"}, false, 0, "")}
		r.localIP.Store(&net.IPAddr{IP: ip("10.9.9.1")})
		if got := r.pinnedSrc(); !got.Equal(ip("10.9.9.1")) {
			t.Fatalf("want the seeded pool source, got %v", got)
		}
		// ...and it follows a rotation, which is the whole point.
		r.localIP.Store(&net.IPAddr{IP: ip("10.9.9.2")})
		if got := r.pinnedSrc(); !got.Equal(ip("10.9.9.2")) {
			t.Fatalf("want the rotated pool source, got %v", got)
		}
	})

	t.Run("client with no source pool pins nothing", func(t *testing.T) {
		r := &Raw{spoofFd: -1, pktFd: -1, fakeFd: -1}
		r.localIP.Store(&net.IPAddr{IP: ip("10.0.0.5")}) // set by DialRaw from routeLocalIP
		if got := r.pinnedSrc(); got != nil {
			t.Fatalf("a single-source client must keep the kernel's choice, got %v", got)
		}
	})

	t.Run("server pins the IP the client dialed", func(t *testing.T) {
		r := &Raw{spoofFd: -1, pktFd: -1, fakeFd: -1}
		d := ip("94.183.210.134")
		r.replySrc.Store(&d)
		if got := r.pinnedSrc(); !got.Equal(d) {
			t.Fatalf("want the dialed IP, got %v", got)
		}
	})

	t.Run("server's reply source wins over a source pool", func(t *testing.T) {
		r := &Raw{spoofFd: -1, pktFd: -1, fakeFd: -1,
			sp: NewPeerPool([]string{"10.9.9.1", "10.9.9.2"}, false, 0, "")}
		r.localIP.Store(&net.IPAddr{IP: ip("10.9.9.1")})
		d := ip("94.183.210.134")
		r.replySrc.Store(&d)
		if got := r.pinnedSrc(); !got.Equal(d) {
			t.Fatalf("the server must answer from the dialed IP, got %v", got)
		}
	})

	t.Run("nothing known pins nothing", func(t *testing.T) {
		r := &Raw{spoofFd: -1, pktFd: -1, fakeFd: -1}
		if got := r.pinnedSrc(); got != nil {
			t.Fatalf("want nil, got %v", got)
		}
	})
}
