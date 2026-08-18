package packet

import (
	"bytes"
	"log"
	"net"
	"sync"
	"time"
)

const (
	sniSplitMode = "split"

	sniDisorderMode = "disorder"

	sniFakeMode = "fake"
)

const fragGap = 1 * time.Millisecond

const fakeTTL = 64

type fragConn struct {
	net.Conn
	host        string
	ech         bool
	pos         int
	mode        string
	ttl         int
	mu          sync.Mutex
	sent        bool
	warn        sync.Once
	warnFake    sync.Once
	warnNoSplit sync.Once

	dsSend *desyncSend
}

func (f *fragConn) fakeSegTTL() int { return fakeTTL }

func (f *fragConn) degraded(why string) {
	f.warn.Do(func() {
		log.Printf("core/tls: sni_mode %q fell back to a plain split (%s) — the split still helps a stateless DPI, the desync does not apply", f.mode, why)
	})
}

func (f *fragConn) fakeDegraded(why string) {
	f.warnFake.Do(func() {
		log.Printf("core/tls: sni_mode \"fake\" fell back to disorder (%s) — disorder desyncs a DPI that "+
			"reads packets, but NOT one that reassembles the stream, which is the only thing fake buys", why)
	})
}

func (f *fragConn) noSplit(p []byte, at int) {
	f.warnNoSplit.Do(func() {
		switch {
		case f.pos > 0:
			log.Printf("core/tls: sni_split is on but split_pos=%d is outside the %d-byte ClientHello — "+
				"nothing was fragmented", f.pos, len(p))
		case f.host == "":
			log.Printf("core/tls: sni_split is on but this carrier dials with no SNI — nothing was fragmented")
		case f.ech:
			log.Printf("core/tls: sni_split is on but the hostname is not in the ClientHello in cleartext " +
				"(ECH encrypts it) — nothing was fragmented, and nothing needs to be: there is no cleartext " +
				"SNI left for a DPI to read")
		default:
			log.Printf("core/tls: sni_split is on but the hostname %q was not found in the ClientHello, and "+
				"ECH is NOT on — so this is not the harmless ECH case. Nothing was fragmented and the SNI "+
				"the client really sent is on the wire in cleartext; check that ws_host matches the SNI "+
				"this carrier dials with", f.host)
		}
	})
}

func newFragConn(c net.Conn, host string, pos int, mode string, ttl int, ech bool, ds *desyncSend) *fragConn {
	if mode == "" {
		mode = sniSplitMode
	}
	if ds == nil {
		ds = &desyncSend{}
	}
	return &fragConn{Conn: c, host: host, pos: pos, mode: mode, ttl: ttl, ech: ech, dsSend: ds}
}

func (f *fragConn) Write(p []byte) (int, error) {
	f.mu.Lock()
	first := !f.sent
	f.sent = true
	f.mu.Unlock()
	if !first {
		return f.Conn.Write(p)
	}
	at := f.splitAt(p)
	if at <= 0 || at >= len(p) {

		f.noSplit(p, at)
		return f.Conn.Write(p)
	}
	switch f.mode {
	case sniDisorderMode:
		return f.writeDisorder(p, at)
	case sniFakeMode:
		return f.writeFake(p, at)
	}
	return f.writeSplit(p, at)
}

func (f *fragConn) writeSplit(p []byte, at int) (int, error) {
	n1, err := f.Conn.Write(p[:at])
	if err != nil {
		return n1, err
	}
	time.Sleep(fragGap)
	n2, err := f.Conn.Write(p[at:])
	return n1 + n2, err
}

func badTCPChecksum(seg []byte) {
	if len(seg) < 18 {
		return
	}
	seg[16] ^= 0xff
}

var decoyApexes = []string{"b-cdn.net", "fastly.net", "azureedge.net", "cloudflare.com", "cdn.jsdelivr.net"}

func decoySNI(n int) []byte {
	if n <= 0 {
		return nil
	}

	for _, a := range decoyApexes {
		if len(a) == n {
			return []byte(a)
		}
	}

	apex := ""
	for _, a := range decoyApexes {
		if len(a)+2 <= n && len(a) > len(apex) {
			apex = a
		}
	}
	if apex == "" {
		return decoyLabels(n)
	}
	out := make([]byte, 0, n)
	out = append(out, decoyLabels(n-len(apex)-1)...)
	out = append(out, '.')
	return append(out, apex...)
}

func decoyLabels(n int) []byte {
	const fill = "assets"
	const maxLabel = 63
	out := make([]byte, 0, n)
	for len(out) < n {
		seg := n - len(out)
		if seg > maxLabel {
			seg = maxLabel
			if rem := n - len(out) - seg; rem < 2 {
				seg = n - len(out) - 2
			}
		}
		for i := 0; i < seg; i++ {
			out = append(out, fill[len(out)%len(fill)])
		}
		if len(out) < n {
			out = append(out, '.')
		}
	}
	return out
}

func (f *fragConn) splitAt(p []byte) int {
	if f.pos > 0 {
		return f.pos
	}
	if f.host == "" {
		return 0
	}
	i := bytes.Index(p, []byte(f.host))
	if i < 0 {
		return 0
	}
	return i + len(f.host)/2
}
