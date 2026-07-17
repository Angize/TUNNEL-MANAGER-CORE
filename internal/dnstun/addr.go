// Package dnstun implements the DNS-tunnel carrier's reliable session layer and
// DNS codec: a kcp-go reliable stream rides over an unreliable, poll-based DNS
// channel, and every KCP datagram is AEAD-sealed so the KCP header never appears
// in cleartext. The pieces here are transport-agnostic and unit-testable without
// a real resolver — the DNS I/O itself lives in the carrier (internal/packet).
package dnstun

import "encoding/hex"

// ClientID is a random per-session identifier the client stamps on every request
// so the server can demultiplex KCP sessions as a stable net.Addr — independent of
// the resolver's UDP source address, which changes per hop and per resolver. It is
// carried INSIDE the AEAD-sealed payload, never in cleartext on the wire.
type ClientID [8]byte

// Network implements net.Addr.
func (c ClientID) Network() string { return "clientid" }

// String implements net.Addr (hex, so it is a valid map key for kcp-go's session table).
func (c ClientID) String() string { return hex.EncodeToString(c[:]) }
