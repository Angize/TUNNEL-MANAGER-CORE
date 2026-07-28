// Fake-packet desync, the platform-neutral part. The mechanism itself forges IPv4 headers and so
// lives in desync_linux.go; the ceiling below is a property of the CARRIER, not of the platform,
// and the untagged carrier code has to be able to report it.
package packet

// injectMaxTTL caps the TTL of a kernel-TCP inject decoy (tcp / tcp+cover / ws). Unlike a raw/flux
// decoy — sent to a peer we hold no live kernel connection to — an inject decoy rides a REAL
// connection's 4-tuple, so a well-formed segment that actually reached the server would draw an RST
// or a challenge-ACK and could disturb the real flow. Clamping guarantees the decoy expires on the
// path (where the DPI still ingests it) no matter how high the operator set fake_ttl.
const injectMaxTTL = 8
