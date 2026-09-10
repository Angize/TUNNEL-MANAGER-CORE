package packet

import (
	"log"
	"sync/atomic"
	"time"
)

const injectMaxTTL = 8

const MaxHopBudget = injectMaxTTL

const desyncReportEvery = 5 * time.Minute

type desyncSend struct {
	ok   atomic.Int64
	bad  atomic.Int64
	last atomic.Int64
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
