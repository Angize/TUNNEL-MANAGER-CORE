// Server-side compute-DoS cache for handshake inits, shared by the datagram carriers. Each server
// re-sends the response it already computed for a recently-seen init instead of re-running a fresh
// ECDH+HKDF per packet. A tiny fixed-size LRU, not a single pair: caching one init lets an attacker
// alternate two captured ones so every packet misses. Single receive goroutine only, so no locking.
package packet

import "bytes"

// initCacheSize is the LRU depth: enough distinct inits that an attacker cannot
// bust the cache by rotating a handful of captured inits, but small and O(n)-scan
// cheap. Handshake inits are rare, so 8 entries is ample.
const initCacheSize = 8

// initCache maps a cheap hash of an init's bytes to the response computed for it.
// Slots are filled round-robin (oldest overwritten), which is an adequate LRU for
// this size. The full init bytes are kept alongside the hash so a hash collision
// cannot serve the wrong response.
type initCache struct {
	hashes [initCacheSize]uint64 // FNV-1a of the init bytes
	inits  [initCacheSize][]byte // the exact init (nil = empty slot; guards a hash collision)
	resps  [initCacheSize][]byte // the response we sent for that init
	next   int                   // next slot to overwrite (round-robin)
}

// fnv1a is a cheap non-cryptographic hash; collisions are handled by the exact
// bytes.Equal check in get, so hash quality only affects lookup speed, not safety.
func fnv1a(b []byte) uint64 {
	const (
		offset = 1469598103934665603
		prime  = 1099511628211
	)
	h := uint64(offset)
	for _, c := range b {
		h ^= uint64(c)
		h *= prime
	}
	return h
}

// get returns the cached response for init, if present.
func (c *initCache) get(init []byte) ([]byte, bool) {
	h := fnv1a(init)
	for i := 0; i < initCacheSize; i++ {
		if c.inits[i] != nil && c.hashes[i] == h && bytes.Equal(c.inits[i], init) {
			return c.resps[i], true
		}
	}
	return nil, false
}

// put records resp for init, overwriting the oldest slot. init is copied because
// it aliases the receive buffer; resp must be a slice the caller no longer mutates.
func (c *initCache) put(init, resp []byte) {
	i := c.next
	c.hashes[i] = fnv1a(init)
	c.inits[i] = append([]byte(nil), init...)
	c.resps[i] = resp
	c.next = (c.next + 1) % initCacheSize
}
