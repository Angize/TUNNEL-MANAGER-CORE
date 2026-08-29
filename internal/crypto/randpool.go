package crypto

import (
	"crypto/rand"
	"io"
	"sync"
)

const randBlock = 4096

type randPool struct {
	mu   sync.Mutex
	buf  [randBlock]byte
	used int
}

var dataRand = randPool{used: randBlock}

func RandRead(p []byte) error { return dataRand.read(p) }

func (r *randPool) read(p []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(p) > 0 {
		if r.used == randBlock {
			if _, err := io.ReadFull(rand.Reader, r.buf[:]); err != nil {
				r.used = randBlock
				return err
			}
			r.used = 0
		}
		n := copy(p, r.buf[r.used:])
		r.used += n
		p = p[n:]
	}
	return nil
}
