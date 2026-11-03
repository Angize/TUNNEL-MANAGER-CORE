//go:build linux

package packet

import (
	"crypto/rand"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const desyncReportEvery = 5 * time.Minute

type desyncSend struct {
	ok       atomic.Int64
	bad      atomic.Int64
	last     atomic.Int64
	failOnce sync.Once
}

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
		return
	}
	log.Printf("core/%s: fake-desync decoy NOT sent: %v (%d failed, %d delivered) — the camouflage is configured and logged as on, but this decoy never reached the wire",
		tag, err, bad, d.ok.Load())
}

type desyncCfg struct {
	on    bool
	ttl   int
	count int
	mode  string
}

func (d desyncCfg) usesBadsum() bool { return d.on && (d.mode == "badsum" || d.mode == "both") }

func (d desyncCfg) usesLowTTL() bool { return d.on && (d.mode == "ttl" || d.mode == "both") }

type fakeSpec struct {
	ttl    int
	badSum bool
}

const badSumTTL = 64

func (d desyncCfg) specs(badAt64 bool) []fakeSpec {
	if !d.on {
		return nil
	}
	out := make([]fakeSpec, 0, d.count)
	for i := 0; i < d.count; i++ {
		bad := d.mode == "badsum" || (d.mode == "both" && i%2 == 1)
		ttl := d.ttl
		if bad && badAt64 {
			ttl = badSumTTL
		}
		out = append(out, fakeSpec{ttl: ttl, badSum: bad})
	}
	return out
}

const fakeSeqGap = 1<<20 + 1<<15

func fakePayload() []byte {
	var lb [1]byte
	_, _ = rand.Read(lb[:])
	n := 48 + int(lb[0])%64
	p := make([]byte, n)
	_, _ = rand.Read(p)
	return p
}
