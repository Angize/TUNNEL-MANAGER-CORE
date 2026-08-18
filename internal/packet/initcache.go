package packet

import "bytes"

const initCacheSize = 8

type initCache struct {
	hashes [initCacheSize]uint64
	inits  [initCacheSize][]byte
	resps  [initCacheSize][]byte
	next   int
}

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

func (c *initCache) get(init []byte) ([]byte, bool) {
	h := fnv1a(init)
	for i := 0; i < initCacheSize; i++ {
		if c.inits[i] != nil && c.hashes[i] == h && bytes.Equal(c.inits[i], init) {
			return c.resps[i], true
		}
	}
	return nil, false
}

func (c *initCache) put(init, resp []byte) {
	i := c.next
	c.hashes[i] = fnv1a(init)
	c.inits[i] = append([]byte(nil), init...)
	c.resps[i] = resp
	c.next = (c.next + 1) % initCacheSize
}
