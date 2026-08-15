package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"testing"
)

// The pool exists to stop a getrandom(2) syscall happening on every packet. What it must never do is
// hand the same bytes out twice: a repeated mask salt repeats a ChaCha20 keystream, and two frames
// masked with the same keystream can be xored together by anyone watching the wire. That is the
// property these pin, at the block boundary and under concurrency, which is where a buffered rng
// actually breaks.

// drawn collects n reads of size sz and fails on any repeat.
func drawn(t *testing.T, n, sz int) map[string]bool {
	t.Helper()
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		b := make([]byte, sz)
		if err := RandRead(b); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if seen[string(b)] {
			t.Fatalf("read %d handed out bytes already given to an earlier caller", i)
		}
		seen[string(b)] = true
	}
	return seen
}

func TestNoTwoReadsGetTheSameBytes(t *testing.T) {
	// well past one block, so the refill path is exercised many times over
	drawn(t, 4*randBlock/maskSaltLen, maskSaltLen)
}

// A read that straddles the end of a block is served from two blocks. The join is where an
// off-by-one hands the last byte of the old block out twice, or skips one.
func TestAReadThatStraddlesARefillIsWholeAndFresh(t *testing.T) {
	var p randPool
	p.used = randBlock

	// take all but three bytes of the first block
	head := make([]byte, randBlock-3)
	if err := p.read(head); err != nil {
		t.Fatal(err)
	}
	last3 := append([]byte(nil), head[len(head)-3:]...)

	// now take eight, which must be the block's final three plus five from a fresh one
	span := make([]byte, 8)
	if err := p.read(span); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(span[:3], last3) {
		t.Fatal("the three bytes at the block boundary were handed out twice")
	}
	if p.used != 5 {
		t.Fatalf("after the straddle the new block has %d bytes taken, want 5", p.used)
	}
}

func TestAReadBiggerThanABlockIsServed(t *testing.T) {
	b := make([]byte, randBlock*2+17)
	if err := RandRead(b); err != nil {
		t.Fatal(err)
	}
	if allSame(b) {
		t.Fatal("a multi-block read came back uniform, so it was never filled")
	}
}

func TestConcurrentReadersNeverShareBytes(t *testing.T) {
	const readers, each = 8, 300
	var mu sync.Mutex
	seen := map[string]bool{}
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				b := make([]byte, maskSaltLen)
				if err := RandRead(b); err != nil {
					t.Errorf("read: %v", err)
					return
				}
				mu.Lock()
				if seen[string(b)] {
					t.Error("two goroutines were handed the same bytes")
				}
				seen[string(b)] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != readers*each {
		t.Fatalf("%d distinct values from %d reads", len(seen), readers*each)
	}
}

// A failed refill must leave NOTHING behind. Handing out a half-filled block would serve whatever the
// buffer happened to hold -- on the first failure that is zeros, and a zero salt is a fixed keystream.
func TestAFailedRefillHandsOutNothing(t *testing.T) {
	var p randPool
	p.used = randBlock
	orig := rand.Reader
	rand.Reader = failAfter{n: 8} // fills 8 bytes, then errors
	defer func() { rand.Reader = orig }()

	b := make([]byte, maskSaltLen)
	if err := p.read(b); err == nil {
		t.Fatal("a failed entropy read was reported as success")
	}
	if p.used != randBlock {
		t.Fatalf("the pool kept %d bytes of a failed refill", randBlock-p.used)
	}
	rand.Reader = orig
	// and the next read, with entropy back, must not serve any of that partial block
	if err := p.read(b); err != nil {
		t.Fatal(err)
	}
	if allSame(b) {
		t.Fatal("the read after a failed refill came back uniform")
	}
}

// The real path, not the helper: Seal draws the salt itself, and it is the salt on the wire that must
// never repeat. maskSaltLen leading bytes of the frame ARE that salt.
func TestNoTwoSealedFramesCarryTheSameSalt(t *testing.T) {
	s, err := NewSealer(CipherAES256, "a-test-psk-for-the-salt-check", true)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 3000; i++ {
		out, err := s.Seal([]byte("payload"), nil)
		if err != nil {
			t.Fatal(err)
		}
		salt := string(out[:maskSaltLen])
		if seen[salt] {
			t.Fatalf("frame %d reused a mask salt: its keystream repeats an earlier frame's", i)
		}
		seen[salt] = true
	}
}

func allSame(b []byte) bool {
	for _, c := range b {
		if c != b[0] {
			return false
		}
	}
	return true
}

// failAfter yields n bytes and then fails, the shape a truncated entropy source has.
type failAfter struct{ n int }

func (f failAfter) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("entropy source failed")
	}
	n := f.n
	if n > len(p) {
		n = len(p)
	}
	for i := range p[:n] {
		p[i] = 0xAA
	}
	return n, io.ErrUnexpectedEOF
}
