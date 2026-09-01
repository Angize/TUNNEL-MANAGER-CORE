package dnstun

import (
	"bytes"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type sizingTransport struct {
	*pipeTransport
	max atomic.Int64
}

func (s *sizingTransport) Send(d []byte) error {
	for {
		m := s.max.Load()
		if int64(len(d)) <= m || s.max.CompareAndSwap(m, int64(len(d))) {
			break
		}
	}
	return s.pipeTransport.Send(d)
}

func zoneOfLen(n int) string {
	var sb strings.Builder
	for sb.Len() < n {
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for i := 0; i < 40 && sb.Len() < n; i++ {
			sb.WriteByte('t')
		}
	}
	return sb.String()
}

// The guard in packet/dns.go promises exactly one thing: a zone it accepts leaves an MTU the carrier
// can work with. Nothing tested that promise end to end, and the whole chain that has to hold is
// three-sided -- the codec's per-query capacity, SessionOverhead, and what kcp-go's SetMtu will take.
// kcp-go's floor is IKCP_OVERHEAD, and a version of it that refused anything under 50 would leave
// every zone from 72 characters up quietly moving zero bytes: KCP would keep its 1400-byte default,
// every segment would exceed the codec's capacity, and EncodeName's errTooBig is swallowed with no log
// and no counter. The session handshake rides the raw transport, not KCP, so the carrier would still
// report "session established".
//
// So this drives a real session at every zone length the guard accepts, including the tightest one,
// and checks that the bytes arrive AND that nothing the session emits is too big for the codec that
// has to carry it.
func TestEveryAcceptedZoneLengthCarriesTraffic(t *testing.T) {
	tried := 0
	for n := 20; n <= 120; n += 2 {
		c, err := NewCodec(zoneOfLen(n))
		if err != nil {
			continue
		}
		mtu := c.MaxUpstream() - SessionOverhead
		if mtu < MinUsefulMTU {
			continue
		}
		tried++
		moved, biggest := runZone(t, mtu)
		if moved != zonePayload {
			t.Errorf("zone of %d characters (maxUp %d, mtu %d): moved %d of %d bytes — the guard "+
				"accepted a zone the carrier cannot use", n, c.MaxUpstream(), mtu, moved, zonePayload)
			continue
		}
		if int(biggest) > c.MaxUpstream() {
			t.Errorf("zone of %d characters: the session emitted a %d-byte frame and the codec carries "+
				"%d — EncodeName drops it with no log", n, biggest, c.MaxUpstream())
		}
		t.Logf("zone %3d: maxUp %3d, mtu %2d, biggest frame %3d, %d bytes moved", n, c.MaxUpstream(), mtu, biggest, moved)
	}
	if tried < 20 {
		t.Fatalf("only %d zone lengths were exercised; the sweep is not covering the accepted range", tried)
	}
}

const zonePayload = 4096

func runZone(t *testing.T, mtu int) (int, int64) {
	t.Helper()
	cp, sp := newPipePair(0)
	ct := &sizingTransport{pipeTransport: cp}
	defer ct.Close()
	defer sp.Close()

	cfg := SessionConfig{PSK: "a-psk-for-the-zone", Cipher: "chacha20-poly1305", MTU: mtu}
	srvCh := make(chan net.Conn, 1)
	go func() {
		c, err := ServeSession(sp, cfg)
		if err != nil {
			srvCh <- nil
			return
		}
		srvCh <- c
	}()
	cli, err := DialSession(ct, cfg)
	if err != nil {
		t.Errorf("mtu %d: DialSession: %v", mtu, err)
		return -1, ct.max.Load()
	}
	defer cli.Close()

	payload := bytes.Repeat([]byte{0x5A}, zonePayload)
	go func() { _, _ = cli.Write(payload) }()

	var srv net.Conn
	select {
	case srv = <-srvCh:
	case <-time.After(20 * time.Second):
		t.Errorf("mtu %d: ServeSession never returned", mtu)
		return -2, ct.max.Load()
	}
	if srv == nil {
		t.Errorf("mtu %d: ServeSession failed", mtu)
		return -3, ct.max.Load()
	}
	defer srv.Close()

	done := make(chan int, 1)
	go func() {
		off := 0
		buf := make([]byte, 4096)
		for off < len(payload) {
			n, err := srv.Read(buf)
			off += n
			if err != nil {
				break
			}
		}
		done <- off
	}()
	select {
	case off := <-done:
		return off, ct.max.Load()
	case <-time.After(30 * time.Second):
		return -4, ct.max.Load()
	}
}
