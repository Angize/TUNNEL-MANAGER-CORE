package packet

import (
	"bytes"
	"log"
	"net"
	"sync"
	"time"
)

// SNI-fragmentation modes.
const (
	// sniSplitMode sends the ClientHello as two IN-ORDER TCP segments split inside the SNI, so no
	// single packet holds the full hostname. Beats a stateless / first-segment DPI, but a DPI that
	// fully reassembles the TCP stream still recovers the SNI.
	sniSplitMode = "split"
	// sniDisorderMode additionally sends the HEAD segment at a low TTL so it expires in transit: an
	// on-path DPI ingests it out of order, but the server never sees that copy and reassembles the real
	// ClientHello from the kernel's retransmit. Costs one retransmit (~RTO) on connect.
	sniDisorderMode = "disorder"
	// sniFakeMode injects a whole FAKE ClientHello (the real one with the SNI overwritten by a benign
	// decoy) at the SAME sequence as the real one, with a corrupt TCP checksum so the server drops it. A
	// reassembling DPI resolves the overlap to the decoy and clears the flow. Killing by checksum is
	// hop-independent, so this is the only mode that beats a DPI which reassembles. Linux + IPv4.
	sniFakeMode = "fake"
)

// fragGap separates the two segments so TCP_NODELAY (set by Go's dialer) reliably emits them as two
// packets instead of coalescing them into one. Paid once, on the first write of a connection.
const fragGap = 1 * time.Millisecond

// fakeTTL is fake mode's DEFAULT decoy TTL: a normal value, because the decoy is killed at the
// server by a bad TCP checksum (hop-independent), not by expiring — so it only needs to be high
// enough to reach the on-path DPI. An operator's split_ttl overrides it (see fakeSegTTL). It lives
// here rather than beside the Linux injector because fakeSegTTL is portable.
const fakeTTL = 64

// fragConn splits the FIRST write on a connection so the client's TLS ClientHello is sent across two
// TCP segments and the cleartext SNI lands on the segment boundary. A cheap complement to ECH (which
// hides the SNI entirely). After the first write the conn is a transparent passthrough; every other
// net.Conn method delegates to the embedded conn.
type fragConn struct {
	net.Conn
	host        string // the SNI we connect with; used to auto-locate the split point (absent under ECH)
	ech         bool   // does this dial present an ECH config? only the fallback messages read it — see noSplit
	pos         int    // explicit split offset into the first write; 0 = auto (middle of the cleartext hostname)
	mode        string // "split" | "disorder" | "fake"
	ttl         int    // disorder: TTL for the head segment; fake: TTL of the injected decoy (0 = each mode's default)
	mu          sync.Mutex
	sent        bool
	warn        sync.Once // one line per conn when the chosen mode had to fall back to a plain split
	warnFake    sync.Once // ...and one for the fake→disorder step, which is a separate loss of protection
	warnNoSplit sync.Once // ...and one for "sni_split is on and nothing was split at all"
	// dsSend belongs to the CARRIER, not to this conn: sni_mode=fake injects once per dial, so a
	// per-conn reporter would report once per reconnect — which on a failing tunnel is a line per
	// retry. Never nil in production (fragWrap passes the carrier's); the zero value is usable, so
	// a hand-built fragConn in a test is safe too.
	dsSend *desyncSend
}

// fakeSegTTL is the TTL stamped on the injected decoy in sni_mode=fake. It is ALWAYS fakeTTL: split_ttl
// does not apply here and is deliberately not read. The two modes want OPPOSITE values out of that one
// stored number — disorder needs it LOW so the head expires before the server, fake needs it HIGH
// because the decoy is killed at the server by its checksum and its job is to reach the DPI first.
func (f *fragConn) fakeSegTTL() int { return fakeTTL }

// degraded reports, exactly once per connection, that the operator's chosen SNI mode could not be
// applied and this conn fell back to a plain in-order split. It has to be said: disorder and fake are
// materially stronger, the panel keeps showing the picked mode, and the usual cause — a container
// without the capability to set a per-segment TTL — is invisible from outside.
func (f *fragConn) degraded(why string) {
	f.warn.Do(func() {
		log.Printf("core/tls: sni_mode %q fell back to a plain split (%s) — the split still helps a stateless DPI, the desync does not apply", f.mode, why)
	})
}

// fakeDegraded is degraded's counterpart for the fake→disorder step, with its own sync.Once: fake is the
// only mode that beats a DPI which REASSEMBLES the stream, so falling back to disorder is a real loss of
// protection even though disorder still runs. A separate Once lets a conn that falls all the way through
// report BOTH steps.
func (f *fragConn) fakeDegraded(why string) {
	f.warnFake.Do(func() {
		log.Printf("core/tls: sni_mode \"fake\" fell back to disorder (%s) — disorder desyncs a DPI that "+
			"reads packets, but NOT one that reassembles the stream, which is the only thing fake buys", why)
	})
}

// noSplit reports, once per connection, that sni_split is configured and nothing was split. at is what
// splitAt returned, so the message names the actual reason. f.ech is what separates the two states that
// look identical from here: under ECH there is no cleartext SNI left and nothing needs splitting, while
// without it the hostname search simply failed and the real SNI is on the wire — a live exposure.
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

// newFragConn wraps c so its first write is split. host is the SNI (for auto split-point location), pos
// an explicit offset (0 = auto), mode the fragmentation mode, ttl the disorder head-segment TTL, ech
// whether this dial presents an ECH config (so the fallback messages state the real cause), ds the
// carrier's decoy-transmit reporter (nil is tolerated).
func newFragConn(c net.Conn, host string, pos int, mode string, ttl int, ech bool, ds *desyncSend) *fragConn {
	if mode == "" {
		mode = sniSplitMode
	}
	if ds == nil {
		ds = &desyncSend{}
	}
	return &fragConn{Conn: c, host: host, pos: pos, mode: mode, ttl: ttl, ech: ech, dsSend: ds}
}

// Write splits only the first call; later writes pass through. The split point is the configured
// offset when > 0, else the middle of the cleartext hostname when it appears in the buffer. If the
// split point is out of range or the hostname isn't in cleartext (e.g. ECH), the buffer is written
// whole — a safe no-op that never corrupts the handshake.
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
		// Nothing is split, on a tunnel whose config says sni_split is on. The usual cause is ECH: with the
		// real name encrypted, splitAt's cleartext search finds nothing and the ClientHello goes out whole —
		// correct, but silent, so an operator running ECH plus sni_split believed both were active.
		f.noSplit(p, at)
		return f.Conn.Write(p)
	}
	switch f.mode {
	case sniDisorderMode:
		return f.writeDisorder(p, at) // linux: low-TTL head; stub: plain split
	case sniFakeMode:
		return f.writeFake(p, at) // linux: overlapping decoy-SNI ClientHello; stub: plain split
	}
	return f.writeSplit(p, at)
}

// writeSplit sends the buffer as two in-order TCP segments, with a small gap so a TCP_NODELAY socket
// does not coalesce them into a single segment.
func (f *fragConn) writeSplit(p []byte, at int) (int, error) {
	n1, err := f.Conn.Write(p[:at])
	if err != nil {
		return n1, err
	}
	time.Sleep(fragGap)
	n2, err := f.Conn.Write(p[at:])
	return n1 + n2, err
}

// badTCPChecksum corrupts the TCP checksum of an IPv4 TCP segment so the SERVER's stack drops it — a
// hop-distance-independent way to make the fake ClientHello die before the server while an on-path DPI
// (which usually does not verify it) still ingests it. Routers work at L3 and never touch the L4
// checksum, unlike a bad IP checksum, which a TTL-decrementing router recomputes and "repairs".
func badTCPChecksum(seg []byte) {
	if len(seg) < 18 {
		return
	}
	seg[16] ^= 0xff // flip the high checksum byte -> guaranteed to differ from the correct checksum
}

// decoyApexes are the domains a decoy ClientHello may claim: real, ubiquitous CDN names a censor
// does not block. Several lengths — and the shortest deliberately at 9 — so that every length from 9
// up can be built by padding a leftmost label instead of by chopping a name in half.
var decoyApexes = []string{"b-cdn.net", "fastly.net", "azureedge.net", "cloudflare.com", "cdn.jsdelivr.net"}

// decoySNI returns exactly n bytes forming a benign, SYNTACTICALLY VALID hostname to overwrite the real
// SNI in the fake ClientHello; n is dictated by the real hostname's length, because the record's SNI
// length field has to stay valid. It pads the LEFTMOST label, the way real CDN hostnames grow, so every
// length lands on a name that could exist — a chopped or doubled constant would be its own anomaly.
func decoySNI(n int) []byte {
	if n <= 0 {
		return nil
	}
	// An exact-length whole apex is the most natural-looking result of all.
	for _, a := range decoyApexes {
		if len(a) == n {
			return []byte(a)
		}
	}
	// Otherwise take the longest apex that still leaves room for "<label>." in front of it.
	apex := ""
	for _, a := range decoyApexes {
		if len(a)+2 <= n && len(a) > len(apex) {
			apex = a
		}
	}
	if apex == "" { // shorter than any apex plus a label: a bare label is still a valid host name
		return decoyLabels(n)
	}
	out := make([]byte, 0, n)
	out = append(out, decoyLabels(n-len(apex)-1)...)
	out = append(out, '.')
	return append(out, apex...)
}

// decoyLabels returns exactly n bytes of dot-separated DNS labels: letters only, no label longer
// than the 63 bytes DNS allows, and never a leading, trailing or doubled dot (each of which would
// make the name malformed — the very thing this is here to avoid).
func decoyLabels(n int) []byte {
	const fill = "assets" // letters only, so it is safe at any offset and reads like a CDN label
	const maxLabel = 63
	out := make([]byte, 0, n)
	for len(out) < n {
		seg := n - len(out)
		if seg > maxLabel {
			seg = maxLabel
			if rem := n - len(out) - seg; rem < 2 { // leave room for "." plus a non-empty next label
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

// splitAt returns the offset in the first write to split at: the configured pos when > 0, else the
// middle of the cleartext hostname if present (0 when there is nothing to split).
func (f *fragConn) splitAt(p []byte) int {
	if f.pos > 0 {
		return f.pos
	}
	if f.host == "" {
		return 0
	}
	i := bytes.Index(p, []byte(f.host))
	if i < 0 {
		return 0 // hostname not in cleartext (ECH, or an unexpected ClientHello layout) -> don't split
	}
	return i + len(f.host)/2
}
