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
	// on-path DPI ingests it (out of order, since the tail arrives first with a higher sequence) but
	// the server never sees that copy. The kernel retransmits the head at the normal TTL, so the
	// server still reassembles the real ClientHello. This desyncs a reassembling DPI's view — the
	// zapret/GoodbyeDPI "disorder" idea — at the cost of one retransmit (~RTO) on connect.
	sniDisorderMode = "disorder"
	// sniFakeMode injects a whole FAKE ClientHello (real one with the SNI overwritten by a benign
	// decoy) as a raw segment at the SAME sequence as the real one, with a corrupt TCP checksum so
	// the server drops it. A reassembling DPI resolves the overlap to the decoy SNI and clears the
	// flow; the server discards the fake (bad checksum) and gets the real ClientHello. Killing by
	// checksum is hop-independent, so unlike disorder it works even when the server is a nearby CDN
	// edge. This is the technique that beats a DPI which reassembles the stream (which plain split and
	// disorder do not). Linux + IPv4; falls back to disorder otherwise.
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

// fakeSegTTL is the TTL stamped on the injected decoy in sni_mode=fake. It is ALWAYS fakeTTL:
// split_ttl does not apply to this mode and is deliberately not read here.
//
// ⚠ It briefly did read it, and that was wrong. The two modes want OPPOSITE values out of that one
// stored number. disorder needs it LOW (default 4) because the head segment has to expire before the
// server. fake needs it HIGH because the decoy is killed at the server by its bad TCP checksum, not
// by expiring, and its whole job is to reach the on-path DPI first — a low TTL kills it before the
// DPI and turns the strongest SNI mode into an expensive no-op. The panel keeps ONE input for both
// modes, so a tunnel that had stored 4 for disorder and then switched to fake silently got a decoy
// that died en route. There is no useful low value here, so there is nothing to honour: the knob
// simply has no meaning in this mode, and the panel no longer offers it.
func (f *fragConn) fakeSegTTL() int { return fakeTTL }

// degraded reports, exactly once per connection, that the operator's chosen SNI mode could not be
// applied and this conn fell back to a plain in-order split. Silence here was the bug: disorder and
// fake are materially stronger than split, the panel keeps showing the mode the operator picked, and
// the usual cause — a container without the capability to set a per-segment TTL — is invisible from
// the outside. Once per conn, not per write, so a busy tunnel cannot flood the journal.
func (f *fragConn) degraded(why string) {
	f.warn.Do(func() {
		log.Printf("core/tls: sni_mode %q fell back to a plain split (%s) — the split still helps a stateless DPI, the desync does not apply", f.mode, why)
	})
}

// fakeDegraded is degraded's counterpart for the fake→disorder step, and it needs its own sync.Once:
// fake is the only mode that beats a DPI which REASSEMBLES the stream, so falling back to disorder
// is a real loss of protection even though disorder still runs. Every one of writeFake's bail-outs
// used to take that step in complete silence — the operator picked the strongest mode, the panel kept
// showing it, and the tunnel quietly ran the weaker one. A separate Once (rather than reusing warn)
// is what lets a conn that falls all the way through report BOTH steps, which is the truth.
func (f *fragConn) fakeDegraded(why string) {
	f.warnFake.Do(func() {
		log.Printf("core/tls: sni_mode \"fake\" fell back to disorder (%s) — disorder desyncs a DPI that "+
			"reads packets, but NOT one that reassembles the stream, which is the only thing fake buys", why)
	})
}

// noSplit reports, once per connection, that sni_split is configured and nothing was split. at is
// what splitAt returned, so the message can name the actual reason instead of a guess.
//
// The last branch used to state ECH as the CAUSE and draw the security conclusion from it — "nothing
// needs to be [fragmented]: there is no cleartext SNI left for a DPI to read" — while nothing had told
// this conn whether ECH was on. It fired on ANY failure of the hostname search, so the case that
// matters most (the configured host simply not matching what the carrier dials with, ECH off, the real
// SNI on the wire) printed a line saying the operator was covered. f.ech carries the fact, so the two
// states can say different things: one is genuinely harmless, the other is a live exposure.
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

// newFragConn wraps c so its first write is split. host is the SNI (for auto split-point location),
// pos an explicit offset (0 = auto), mode the fragmentation mode, ttl the disorder head-segment TTL,
// ech whether this dial presents an ECH config (so the fallback messages can state the real cause
// instead of assuming one), ds the carrier's decoy-transmit reporter (nil is tolerated: a test conn
// reports into its own).
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
		// Nothing is split, on a tunnel whose config says sni_split is on and whose startup log says
		// so too. The usual cause is ECH: with the real name encrypted, splitAt's cleartext search
		// finds nothing and returns 0, and the ClientHello goes out whole. That is the correct
		// behaviour — there is no cleartext SNI left to straddle a segment boundary, and ECH is the
		// stronger defence anyway — but it was completely silent, so an operator running ECH plus
		// sni_split believed both were active when only one was.
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

// badTCPChecksum corrupts the TCP checksum of an IPv4 TCP segment (the checksum field is bytes 16-17
// of the TCP header) so the SERVER's stack drops the segment — a hop-distance-independent way to make
// the fake ClientHello die before the server while an on-path DPI (which usually does not verify the
// TCP checksum) still ingests it. Routers operate at L3 and never touch the L4 checksum, so a bad TCP
// checksum survives all the way to the server — unlike a bad IP checksum, which a TTL-decrementing
// router recomputes and "repairs". This is why fake mode kills its decoy by checksum, not by TTL:
// TTL needs the fake to die between the DPI and the server, a window that may not exist when the
// server is a nearby CDN edge.
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

// decoySNI returns exactly n bytes forming a benign, SYNTACTICALLY VALID hostname, to overwrite the
// real SNI in the fake ClientHello. n is dictated by the real hostname's length, because the SNI
// length field in the record has to stay valid.
//
// It used to be a raw modulo repeat of the 18-byte constant "www.cloudflare.com", so unless the real
// host happened to be exactly 18 characters the decoy was a chopped or doubled string —
// "www.cloudflare." (a trailing dot), "www.cloudflare.comw", "www.cloudflare.comwww.c". None of those
// is a name any client ever sends, so a DPI that reassembled the overlap recorded a structurally
// impossible SNI: an anomaly worth flagging, which is the exact opposite of the point. Padding the
// LEFTMOST label instead is how real CDN hostnames grow ("assets-3f2.cdn.example.com"), so every
// length lands on a name that could exist.
//
// What this does NOT fix: the core is not told which CDN is in front (cdn_profile is a panel concept
// that the node does not forward — backlog B1), so a decoy sent to an ArvanCloud edge can still name
// a different CDN. Choosing the apex to match the edge needs that plumbing first.
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
