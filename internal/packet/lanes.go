package packet

import "time"

const MaxLanes = 8

const followEvery = 250 * time.Millisecond

func (b *TCP) Follow(lead *TCP, lane int) {
	b.lead, b.lane = lead, lane
}

func (b *TCP) laneHello() []byte {
	if b.lane == 0 {
		return nil
	}
	return []byte{byte(b.lane)}
}

func (b *TCP) noteLane(cf *connFramer, hello []byte) {
	if b.isClient || len(hello) != 1 || hello[0] == 0 || int(hello[0]) >= MaxLanes {
		return
	}
	cf.lane.Store(int32(hello[0]))
	b.laneCur[hello[0]].Store(cf)
}

func (b *TCP) downFrom(cf *connFramer) {
	if l := cf.lane.Load(); l > 0 {
		b.laneCur[l].Store(cf)
		return
	}
	b.cur.Store(cf)
}

func (b *TCP) dropLane(cf *connFramer) {
	if l := cf.lane.Load(); l > 0 {
		b.laneCur[l].CompareAndSwap(cf, nil)
	}
}

func (b *TCP) sendConn(q int) *connFramer {
	if q > 0 {
		if cf := b.laneCur[q].Load(); cf != nil {
			return cf
		}
	}
	return b.cur.Load()
}

func (b *TCP) followLoop() {
	t := time.NewTicker(followEvery)
	defer t.Stop()
	for {
		select {
		case <-b.closeCh:
			return
		case <-t.C:
		}
		dst := followCursor(b.pp, b.lead.pp)
		if src := followCursor(b.sp, b.lead.sp); dst || src {
			b.dropCarrier(dropRotation)
			wakeLoop(b.wake)
		}
	}
}

func followCursor(mine, lead *PeerPool) bool {
	if mine == nil || lead == nil {
		return false
	}
	want := lead.current()
	if want == "" || want == mine.current() {
		return false
	}
	mine.keepCursorOn(want)
	return mine.current() == want
}
