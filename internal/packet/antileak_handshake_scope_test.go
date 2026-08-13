//go:build linux

package packet

import (
	"net"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

const hsScopePSK = "tVYafNLrHaId1AaEM80YebyPzXThOEr2adA27E6mbRc="

// A server's anti-leak rule is scoped to ONE peer, and a server has no peer until a frame OPENS under a
// session — which never happens during a handshake. So from bind until the client's first data frame
// authenticates, the server's own kernel answers everything the client sends: an echo-reply on icmp
// (our ciphertext, mirrored straight back), an ICMP port-unreachable on udp, a RST on tcp. That is the
// whole connect, on every restart, and the handshake is exactly when the tunnel is most fragile.
//
// ParseInit is what makes the fix safe: the sender proved the PSK, and the code already trusts it that
// far — it steers the reply PORT off the same authentication.
func TestTheServerScopesItsAntiLeakRuleForTheHandshake(t *testing.T) {
	for _, profile := range []string{"udp", "tcp", "icmp"} {
		t.Run("raw/"+profile, func(t *testing.T) {
			rec := &scopeRecorder{}
			srv := &Raw{profile: profile, isClient: false, psk: hsScopePSK,
				cipher: "chacha20-poly1305", port: 51820, closeCh: make(chan struct{})}
			srv.link = &capturingLink{r: srv}
			srv.localIP.Store(&net.IPAddr{IP: testDst})
			srv.leak.init(srv.closeCh, rec.installer())
			defer func() { close(srv.closeCh); srv.leak.teardown() }()

			if got := rec.last(); got != "" {
				t.Fatalf("a freshly bound server already scoped a rule to %q", got)
			}
			// The client's init, wrapped exactly as the carrier puts it on the wire, fed to the receive
			// path — not to tryHandshake, which would say nothing about whether the path reaches it.
			srv.handleRaw(clientInit(t, profile), &net.IPAddr{IP: testSrc})

			waitFor(t, 5*time.Second, "the server scoped its anti-leak rule off the authenticated init", func() bool {
				return rec.last() == testSrc.String()
			})
			if cap, _ := srv.link.(*capturingLink); len(cap.sent) != 1 {
				t.Fatalf("the server sent %d handshake replies, want 1 — the init did not reach tryHandshake and this case is vacuous", len(cap.sent))
			}
		})
	}

	t.Run("flux/udp", func(t *testing.T) {
		rec := &scopeRecorder{}
		f := newFlux(nil, time.Second, time.Minute, false, true, hsScopePSK, "chacha20-poly1305",
			"udp", "random", 0, false, 0, 0, false)
		f.sendFd, f.pktFd = -1, -1
		f.leak.init(f.closeCh, rec.installer())
		defer func() { close(f.closeCh); f.leak.teardown() }()

		f.handleCrypto(crypto.InitMsg(hsScopePSK, ephemeral(t)), &net.IPAddr{IP: testSrc})
		waitFor(t, 5*time.Second, "the flux server scoped its anti-leak rule off the authenticated init", func() bool {
			return rec.last() == testSrc.String()
		})
	})

	// The other half: the rule set is single-scoped, so once a peer IS known an init replayed from
	// anywhere else must not drag it off the endpoint carrying the tunnel. learnPeer owns the scope there.
	t.Run("an init from a stranger does not move a scope that is already on the peer", func(t *testing.T) {
		const stranger = "198.51.100.9"
		rec := &scopeRecorder{}
		srv := &Raw{profile: "udp", isClient: false, psk: hsScopePSK,
			cipher: "chacha20-poly1305", port: 51820, closeCh: make(chan struct{})}
		srv.link = &capturingLink{r: srv}
		srv.localIP.Store(&net.IPAddr{IP: testDst})
		srv.leak.init(srv.closeCh, rec.installer())
		defer func() { close(srv.closeCh); srv.leak.teardown() }()

		srv.peer.Store(&net.IPAddr{IP: testSrc})
		srv.leak.scope(testSrc)
		if got := rec.last(); got != testSrc.String() {
			t.Fatalf("pre-scope landed on %q, want %s — the rest of this case would be vacuous", got, testSrc)
		}

		srv.handleRaw(clientInit(t, "udp"), &net.IPAddr{IP: net.ParseIP(stranger).To4()})
		time.Sleep(200 * time.Millisecond) // an async re-scope would have landed well inside this
		if got := rec.last(); got != testSrc.String() {
			t.Errorf("an init from %s dragged the anti-leak rules onto it; they are now OFF %s, the endpoint carrying the tunnel", stranger, testSrc)
		}
	})
}

// clientInit builds the bytes a client puts on the wire for a fresh handshake init of this profile.
func clientInit(t *testing.T, profile string) []byte {
	t.Helper()
	cli := &Raw{profile: profile, isClient: true, psk: hsScopePSK,
		cipher: "chacha20-poly1305", port: 51820}
	cli.link = &capturingLink{r: cli}
	cli.localIP.Store(&net.IPAddr{IP: testSrc})
	return cli.wire(crypto.InitMsg(hsScopePSK, ephemeral(t)), testDst)
}

func ephemeral(t *testing.T) *crypto.Ephemeral {
	t.Helper()
	ci, err := crypto.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	return ci
}
