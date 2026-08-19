//go:build linux

package packet

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestARolledSourcePortStartsANewFlow(t *testing.T) {

	r := &Raw{profile: "tcp", proto: protoTCP, isClient: true, port: 443, closeCh: make(chan struct{})}
	r.link = &capturingLink{r: r}
	r.setSportMode(true)
	if !r.sportRandom {
		t.Fatal("the tcp profile did not arm the port rotation")
	}

	before := r.wireTo([]byte("0123456789abcdef0123456789abcdef"), testDst, r.cport())
	seqBefore := binary.BigEndian.Uint32(before[4:8])
	ackBefore := binary.BigEndian.Uint32(before[8:12])
	tsBefore := peerTSVal(before)
	portBefore := r.cport()
	if tsBefore == 0 {
		t.Fatal("the tcp profile is not stamping a timestamp option, so this proves nothing")
	}

	time.Sleep(30 * time.Millisecond)
	mark := time.Now().UnixNano()

	greenSession(t, r)
	if !r.rollSourcePort() {
		t.Fatal("the draw did not move the port")
	}
	if r.tsStart.Load() < mark {
		t.Error("the timestamp clock still counts from when the session opened, so the new tuple's TSval " +
			"is the old one's series read at a different offset")
	}

	after := r.wireTo([]byte("0123456789abcdef0123456789abcdef"), testDst, r.cport())
	seqAfter := binary.BigEndian.Uint32(after[4:8])
	ackAfter := binary.BigEndian.Uint32(after[8:12])
	tsAfter := peerTSVal(after)

	if r.cport() == portBefore {
		t.Fatal("the port did not actually roll")
	}
	if binary.BigEndian.Uint16(after[0:2]) == binary.BigEndian.Uint16(before[0:2]) {
		t.Error("the wire source port did not follow the roll")
	}

	if seqAfter == seqBefore || seqAfter-seqBefore < 1<<20 {
		t.Errorf("the new tuple's sequence continues the old series (%d then %d) — the two tuples "+
			"can be joined on it", seqBefore, seqAfter)
	}
	if ackAfter == ackBefore {
		t.Errorf("the new tuple acknowledges the same peer ISN (%d) as the old one", ackBefore)
	}
	if tsAfter >= tsBefore && tsAfter-tsBefore < 1<<20 {
		t.Errorf("the new tuple's TSval continues the old clock (%d then %d)", tsBefore, tsAfter)
	}
	if r.tcpBytes.Load() != uint32(len(after)-rawHeaderLen("tcp")) {
		t.Errorf("the byte counter carried %d bytes over from the old flow", r.tcpBytes.Load())
	}
}

func TestTheFlowIsStillAFlowBetweenRolls(t *testing.T) {
	r := &Raw{profile: "tcp", proto: protoTCP, isClient: true, port: 443}
	r.link = &capturingLink{r: r}
	r.newTCPFlow()

	payload := []byte("0123456789abcdef")
	first := r.wireTo(payload, testDst, r.cport())
	seq1 := binary.BigEndian.Uint32(first[4:8])
	ts1 := peerTSVal(first)

	time.Sleep(2 * time.Millisecond)
	second := r.wireTo(payload, testDst, r.cport())
	seq2 := binary.BigEndian.Uint32(second[4:8])
	ts2 := peerTSVal(second)

	if want := seq1 + uint32(len(first)-rawHeaderLen("tcp")); seq2 != want {
		t.Errorf("the sequence advanced to %d, want %d — a real flow advances by the bytes it sent", seq2, want)
	}
	if ts2 < ts1 {
		t.Errorf("the timestamp went backwards: %d then %d", ts1, ts2)
	}
	if binary.BigEndian.Uint32(second[8:12]) != binary.BigEndian.Uint32(first[8:12]) {
		t.Error("the acknowledged peer ISN moved inside one flow")
	}
}
