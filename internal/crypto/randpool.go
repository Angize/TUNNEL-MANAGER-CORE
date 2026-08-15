package crypto

// Random bytes for the data path, drawn from crypto/rand in blocks instead of one call per packet.
//
// crypto/rand.Read is a getrandom(2) SYSCALL on any kernel without the vDSO entry point (added in
// 6.11), and the send path reaches for it on EVERY packet: a mask salt in Seal, a padding length in
// the obfs framing. On a linux 6.8 host carrying 214 Mbit a cpu profile put 6% of the whole process in
// that one call.
//
// This buffers crypto/rand; it does not replace it with anything weaker. The bytes handed out ARE
// crypto/rand's bytes, in crypto/rand's order, so nothing about their unpredictability changes -- which
// matters, because a predictable mask salt would let anyone who can see the wire strip the mask.

import (
	"crypto/rand"
	"io"
	"sync"
)

// randBlock is how much is drawn per syscall. At the tunnel's packet rate a 4 KiB block covers a few
// hundred packets, so the syscall stops being per-packet without holding a meaningful amount of unused
// key material around.
const randBlock = 4096

// randPool hands out bytes from a block of crypto/rand output, refilling when it runs out.
//
// A byte is handed out ONCE: `used` only moves forward, and a refill replaces the whole block. Handing
// the same salt to two frames would repeat a ChaCha20 keystream, so this is the property the tests
// exist to pin.
type randPool struct {
	mu   sync.Mutex
	buf  [randBlock]byte
	used int // bytes of buf already given out; == randBlock means empty
}

// dataRand is the pool the per-packet draws share. One process carries one tunnel, so there is no
// cross-tunnel contention on it, and an uncontended mutex is far cheaper than the syscall it replaces.
var dataRand = randPool{used: randBlock}

// RandRead fills p with cryptographically random bytes.
//
// It is a drop-in for io.ReadFull(rand.Reader, p) on the data path. An error means the system's
// entropy source failed; callers must fail the frame rather than send with whatever p holds, exactly
// as they did when they read from rand.Reader directly.
func RandRead(p []byte) error { return dataRand.read(p) }

func (r *randPool) read(p []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(p) > 0 {
		if r.used == randBlock {
			if _, err := io.ReadFull(rand.Reader, r.buf[:]); err != nil {
				// Leave the pool EMPTY. A partially refilled block could otherwise be handed out on a
				// later call mixed with bytes from the failed read.
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
