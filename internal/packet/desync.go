// Fake-packet desync, the platform-neutral part. The mechanism itself forges IPv4 headers and so
// lives in desync_linux.go; the ceiling below is a property of the CARRIER, not of the platform,
// and the untagged carrier code has to be able to report it.
package packet

import (
	"log"
	"sync/atomic"
	"time"
)

// injectMaxTTL caps the TTL of a kernel-TCP inject decoy (tcp / tcp+cover / ws). Unlike a raw/flux decoy
// — sent to a peer we hold no live kernel connection to — an inject decoy rides a REAL connection's
// 4-tuple, so a segment that actually reached the server would draw an RST and disturb the real flow.
// Clamping guarantees it expires on the path, where the DPI still ingests it.
const injectMaxTTL = 8

// MaxHopBudget is the ceiling for every knob whose whole job is to die in transit: the inject decoy's
// fake_ttl, and the disorder head's split_ttl. ONE number, because it encodes ONE physical claim —
// far enough to pass the on-path DPI, never far enough to reach the peer. A split_ttl above it makes
// the head arrive intact, so sni_mode=disorder degrades to a plain split while every layer keeps
// reporting disorder.
const MaxHopBudget = injectMaxTTL

// desyncReportEvery paces the repeat below. The first failure is reported at once; after that a
// still-failing carrier says so on this cadence, so a condition that persists for hours stays
// visible in the journal without a line per decoy.
const desyncReportEvery = 5 * time.Minute

// desyncSend is the outcome of the decoy TRANSMITS. Decoys are best-effort by design — one lost decoy
// must never fail a tunnel — but discarding the result made "best-effort" mean "unobservable": an
// unresolvable next hop, a missing capability or a downed interface all fail silently while startup has
// already printed that the camouflage is on. Zero value ready to use; note is goroutine-safe.
type desyncSend struct {
	ok   atomic.Int64
	bad  atomic.Int64
	last atomic.Int64 // unix-nanos of the last report; 0 = never reported
}

// note records one decoy transmit. tag is the carrier's log prefix ("tcp" / "raw" / "flux").
func (d *desyncSend) note(tag string, err error) {
	if err == nil {
		d.ok.Add(1)
		return
	}
	bad := d.bad.Add(1)
	now := time.Now().UnixNano()
	last := d.last.Load()
	if last != 0 && now-last < int64(desyncReportEvery) {
		return
	}
	if !d.last.CompareAndSwap(last, now) {
		return // a concurrent note owns this window
	}
	log.Printf("core/%s: fake-desync decoy NOT sent: %v (%d failed, %d delivered) — the camouflage is configured and logged as on, but this decoy never reached the wire",
		tag, err, bad, d.ok.Load())
}
