//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

func synFrom(t *testing.T, isn uint32, sport uint16) []byte {
	t.Helper()
	seg := buildTCPSeg(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), sport, rawServerPort,
		isn, 0, tcpSyn, 400, tcpSynOptions(1, 0), nil)
	return ipTCP(t, seg)
}

func lastSeg(t *testing.T, l *capturedLink) []byte {
	t.Helper()
	if len(l.sent) == 0 {
		t.Fatal("the server answered nothing")
	}
	return l.sent[len(l.sent)-1]
}

// The client starts a brand new forged flow every time its path moves: freshTuple calls usePort which
// calls newTCPFlow, and a test already pins that. The server never did. newTCPFlow was reached from
// newRaw and from usePort only, and usePort is a client path, so a server drew its ISN, its timestamp
// base and its byte counter ONCE, at startup, and kept them for the life of the process.
//
// Measured on the netns lab across three source rotations of one client, reading the server's own
// segments: the SYN-ACK carried the identical ISN 206844612 all four times, the data sequence ran
// 206844930 -> 206845020 -> 206845506 -> 206846296 without ever restarting, and the timestamp clock
// went 4184739782 -> 4184739936 -> 4184750790 -> 4184764807 unbroken. Three separate ways to join the
// flow the client had just left to the one it had just opened -- which is the whole thing rotation is
// paid for.
//
// Nothing reads these fields but a watcher: the AEAD decides what is ours. So the server can mint a
// fresh flow for free, and the SYN the client now sends on a new tuple is exactly the signal for it.
func TestTheServerStartsItsOwnFlowForANewClient(t *testing.T) {
	srv, l := rawTCPEnd(t, false)
	peer := &net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}

	srv.tcpFlow(synFrom(t, 1000, rawClientPort), peer)
	first := lastSeg(t, l)
	isn1 := binary.BigEndian.Uint32(first[4:8])
	ts1 := peerTSVal(first)
	srv.tcpBytes.Add(5000)

	srv.tcpFlow(synFrom(t, 7777, 40000), peer)
	second := lastSeg(t, l)
	isn2 := binary.BigEndian.Uint32(second[4:8])
	ts2 := peerTSVal(second)

	if isn2 == isn1 {
		t.Errorf("both flows opened on the same ISN %d — a watcher joins them without arithmetic", isn1)
	}
	if ts2 == ts1 {
		t.Errorf("both flows carry the same timestamp value %d", ts1)
	}
	if got := srv.tcpBytes.Load(); got != 0 {
		t.Errorf("the new flow carried %d bytes of the old one, so its data sequence continues the old "+
			"series however fresh the ISN is", got)
	}
	if got := srv.tcpAck.Load(); got != 7778 {
		t.Errorf("the server acknowledges %d, want the new client's ISN+1 (7778)", got)
	}
	if got := srv.cport(); got != 40000 {
		t.Errorf("the server answers port %d, want the new client's 40000", got)
	}
}

// A retransmitted SYN is the same SYN. Real TCP answers it with the SAME ISN; minting a new one for
// every copy would put two different SYN-ACKs for one SYN on the wire, which is its own tell -- and the
// capture shows the client does retransmit.
func TestARetransmittedSynGetsTheSameAnswer(t *testing.T) {
	srv, l := rawTCPEnd(t, false)
	peer := &net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}

	srv.tcpFlow(synFrom(t, 4242, rawClientPort), peer)
	isn := binary.BigEndian.Uint32(lastSeg(t, l)[4:8])
	srv.tcpBytes.Add(300)

	for i := 0; i < 3; i++ {
		srv.tcpFlow(synFrom(t, 4242, rawClientPort), peer)
		if got := binary.BigEndian.Uint32(lastSeg(t, l)[4:8]); got != isn {
			t.Fatalf("copy %d of one SYN was answered with ISN %d, want %d", i+1, got, isn)
		}
	}
	if got := srv.tcpBytes.Load(); got != 300 {
		t.Errorf("a duplicate SYN reset the live flow's byte counter to %d mid-stream", got)
	}
}

// The client half is unchanged: it must not reset its flow when it receives a SYN, because it never
// does receive one -- only a server does.
func TestAClientIgnoresASyn(t *testing.T) {
	cli, l := rawTCPEnd(t, true)
	isn := cli.tcpISN.Load()
	cli.tcpFlow(synFrom(t, 99, rawClientPort), &net.IPAddr{IP: net.IPv4(10, 0, 0, 2)})
	if cli.tcpISN.Load() != isn {
		t.Error("a client redrew its flow because someone sent it a SYN")
	}
	if len(l.sent) != 0 {
		t.Errorf("a client answered a SYN with %d segment(s)", len(l.sent))
	}
}
