//go:build linux

package packet

import (
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

const rungPSK = "rehandshake-psk-0123456789abcdef"

func rungSealer(t *testing.T) Sealer {
	t.Helper()
	s, err := crypto.NewSealer(crypto.CipherChaCha, rungPSK, true)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// One carrier's half of the session rung: what the ladder calls, what clientLoop reads afterwards to
// decide whether it still owes the peer a handshake, and the channel that tells it to look now.
type rungRig struct {
	st      *coreStatus
	drop    func() bool
	asking  func() bool
	carries func() bool
	wake    chan struct{}
}

func rawRung(t *testing.T) rungRig {
	t.Helper()
	r := &Raw{isClient: true, profile: "udp", psk: rungPSK, cipher: crypto.CipherChaCha,
		ping: pingEvery, closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
	r.peer.Store(&net.IPAddr{IP: net.IPv4(10, 30, 0, 2)})
	r.session.Store(&sealerBox{s: rungSealer(t)})
	r.link = &capturingLink{r: r}
	r.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	t.Cleanup(func() { close(r.closeCh) })
	return rungRig{st: r.st, drop: r.rehandshake, wake: r.wake,
		asking:  func() bool { return handshakeOutstanding(true, r.sealer(), r.ci.Load()) },
		carries: func() bool { return r.sealer() != nil }}
}

func udpRung(t *testing.T) rungRig {
	t.Helper()
	b := &UDP{isClient: true, cryptoOn: true, psk: rungPSK, cipher: crypto.CipherChaCha,
		ping: pingEvery, closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
	b.peer.Store(&net.UDPAddr{IP: net.IPv4(10, 30, 0, 2), Port: 443})
	b.session.Store(&sealerBox{s: rungSealer(t)})
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	t.Cleanup(func() { close(b.closeCh) })
	return rungRig{st: b.st, drop: b.rehandshake, wake: b.wake,
		asking:  func() bool { return handshakeOutstanding(b.cryptoOn, b.sealer(), b.ci.Load()) },
		carries: func() bool { return b.sealer() != nil }}
}

func fluxRung(t *testing.T) rungRig {
	t.Helper()
	f := &Flux{isClient: true, cryptoOn: true, psk: rungPSK, cipher: crypto.CipherChaCha,
		ping: pingEvery, carrier: "udp", sendFd: -1, pktFd: -1,
		closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
	f.peer.Store(&net.IPAddr{IP: net.IPv4(10, 30, 0, 2)})
	f.session.Store(&sealerBox{s: rungSealer(t)})
	f.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	t.Cleanup(func() { close(f.closeCh) })
	return rungRig{st: f.st, drop: f.rehandshake, wake: f.wake,
		asking:  func() bool { return handshakeOutstanding(f.cryptoOn, f.sealer(), f.ci.Load()) },
		carries: func() bool { return f.sealer() != nil }}
}

var sessionRungCarriers = []struct {
	name string
	rig  func(*testing.T) rungRig
}{{"raw", rawRung}, {"udp", udpRung}, {"flux", fluxRung}}

// A verdict that reaches the session rung must leave a handshake OUTSTANDING -- and leave the session
// alone while it is.
//
// Outstanding is what clientLoop retransmits on. Without it the rung's single Init was the tunnel's
// entire answer to an outage: the loop went straight back to the keepalive branch, and once the far
// end had lost its session (a server-side restart, a reboot, a rebuild) nothing the client ever sent
// again could be opened. The session staying is the other half: it is what carries if the path
// returns before the handshake lands.
//
// Driven through the real ladder -- a verdict file, rc.poll -- not through rehandshake().
func TestTheSessionRungLeavesAHandshakeOutstanding(t *testing.T) {
	for _, c := range sessionRungCarriers {
		t.Run(c.name, func(t *testing.T) {
			rig := c.rig(t)
			rc := newRotationController(nil, nil)
			rc.session.setDrop(rig.drop)
			rc.attachStatus(rig.st)

			liveVerdict(t, rc.verdict, rig.st.pathEpoch(), poolCmd{Cmd: cmdFail})
			rc.poll(func(bool) {}, func(bool) {}, nil, rig.st.pathEpoch)

			if !rig.asking() {
				t.Fatal("the session rung fired and left nothing outstanding — clientLoop goes back " +
					"to the keepalive branch, so this outage gets one Init and then silence")
			}
			if !rig.carries() {
				t.Fatal("the rung threw the live session away — nothing crosses from here until the " +
					"handshake lands, and the old key would have carried the moment the path returned")
			}
			select {
			case <-rig.wake:
			default:
				t.Fatal("the session rung asked without waking clientLoop — the first retransmit " +
					"waits out a whole keepalive interval")
			}
		})
	}
}

// Counts the handshakes on the wire. An Init body is at least crypto.HandshakeCoreSize; a sealed
// keepalive is far shorter, and neither is padded with obfs off.
type countingLink struct {
	mu  sync.Mutex
	big int
}

func (c *countingLink) send(pkt []byte, _ *net.IPAddr) {
	if len(pkt) >= rawHeaderLen("udp")+crypto.HandshakeCoreSize {
		c.mu.Lock()
		c.big++
		c.mu.Unlock()
	}
}

func (c *countingLink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.big
}

func (c *countingLink) recvLoop() error                     { return nil }
func (c *countingLink) replyTo(src *net.IPAddr) *net.IPAddr { return src }
func (c *countingLink) filterSrc() bool                     { return true }
func (c *countingLink) pinsSource() bool                    { return false }
func (c *countingLink) fakeFD() int                         { return -1 }
func (c *countingLink) close()                              {}
func (c *countingLink) header(realSrc net.IP, to *net.IPAddr) (net.IP, net.IP) {
	return realSrc, to.IP
}

func loopRaw(t *testing.T, sportRandom bool) (*Raw, *countingLink) {
	t.Helper()
	link := &countingLink{}
	r := &Raw{isClient: true, profile: "udp", psk: rungPSK, cipher: crypto.CipherChaCha,
		ping: pingEvery, sportRandom: sportRandom,
		closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
	r.peer.Store(&net.IPAddr{IP: net.IPv4(10, 30, 0, 2)})
	r.session.Store(&sealerBox{s: rungSealer(t)})
	r.link = link
	r.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	r.st.trackPath(r.livePath, r.closeCh)
	t.Cleanup(func() { close(r.closeCh) })
	return r, link
}

// ...and the loop then keeps asking, for as long as the outage lasts. This is the behaviour the
// operator sees, and the whole bug in one number: before, the wire carried ONE Init per rung however
// long the outage ran, so a far end that came back a minute later was never spoken to again.
//
// Both rungs, because both had it: the port rung's draw sends an Init from the new port and the
// session rung sends one from wherever it is. The whole running clientLoop is driven here, from a
// verdict file it polls itself -- a test that calls the rung directly says nothing about the loop
// that has to notice.
func TestTheLoopKeepsAskingAfterARung(t *testing.T) {
	for _, c := range []struct {
		name        string
		sportRandom bool
	}{{"port rung", true}, {"session rung", false}} {
		t.Run(c.name, func(t *testing.T) {
			r, link := loopRaw(t, c.sportRandom)
			go r.clientLoop()
			time.Sleep(300 * time.Millisecond)

			liveVerdict(t, r.st.verdictPath(), r.st.pathEpoch(), poolCmd{Cmd: cmdFail})
			time.Sleep(3500 * time.Millisecond)

			if n := link.count(); n < 2 {
				t.Fatalf("the client put %d handshake(s) on the wire in the 3.5s after the rung, want "+
					"at least 2 — one and then silence is exactly the outage that never ends", n)
			}
		})
	}
}
