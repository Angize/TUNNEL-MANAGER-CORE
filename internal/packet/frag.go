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

// fragConn splits the FIRST write on a connection so the client's TLS ClientHello is sent across two
// TCP segments and the cleartext SNI lands on the segment boundary. A cheap complement to ECH (which
// hides the SNI entirely). After the first write the conn is a transparent passthrough; every other
// net.Conn method delegates to the embedded conn.
type fragConn struct {
	net.Conn
	host string // the SNI we connect with; used to auto-locate the split point (absent under ECH)
	pos  int    // explicit split offset into the first write; 0 = auto (middle of the cleartext hostname)
	mode string // "split" | "disorder"
	ttl  int    // disorder: TTL for the head segment (0 = default); low enough to die before the server
	mu   sync.Mutex
	sent bool
	warn sync.Once // one line per conn when the chosen mode had to fall back to a plain split
}

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

// newFragConn wraps c so its first write is split. host is the SNI (for auto split-point location),
// pos an explicit offset (0 = auto), mode the fragmentation mode, ttl the disorder head-segment TTL.
func newFragConn(c net.Conn, host string, pos int, mode string, ttl int) *fragConn {
	if mode == "" {
		mode = sniSplitMode
	}
	return &fragConn{Conn: c, host: host, pos: pos, mode: mode, ttl: ttl}
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
