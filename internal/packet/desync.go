// Fake-packet desync, the platform-neutral part. The mechanism itself forges IPv4 headers and so
// lives in desync_linux.go; the ceiling below is a property of the CARRIER, not of the platform,
// and the untagged carrier code has to be able to report it.
package packet

import (
	"log"
	"sync/atomic"
	"time"
)

// injectMaxTTL caps the TTL of a kernel-TCP inject decoy (tcp / tcp+cover / ws). Unlike a raw/flux
// decoy — sent to a peer we hold no live kernel connection to — an inject decoy rides a REAL
// connection's 4-tuple, so a well-formed segment that actually reached the server would draw an RST
// or a challenge-ACK and could disturb the real flow. Clamping guarantees the decoy expires on the
// path (where the DPI still ingests it) no matter how high the operator set fake_ttl.
const injectMaxTTL = 8

// desyncReportEvery paces the repeat below. The first failure is reported at once; after that a
// still-failing carrier says so on this cadence, so a condition that persists for hours stays
// visible in the journal without a line per decoy.
const desyncReportEvery = 5 * time.Minute

// desyncSend is the outcome of the decoy TRANSMITS, which every carrier used to throw away with
// `_ =`. Decoys are best-effort by design — one lost decoy must never fail a tunnel — but
// "best-effort" was implemented as "unobservable": an L2 next hop that will not resolve, a
// container without the capability, an interface that has gone down, and every decoy fails
// identically and silently while startup has already printed
//
//	tnl-core: fake-desync on (2 decoys, ttl=4, mode=ttl)
//
// So the panel says the camouflage is on, the log says it is on, and the DPI sees nothing — and
// when the tunnel is then blocked there is no way to tell that the camouflage never ran. The
// counters make the difference legible; nothing here changes what is sent.
//
// The zero value is ready to use, and note is safe from several goroutines.
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
