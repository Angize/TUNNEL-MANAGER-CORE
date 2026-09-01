//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

type capturedLink struct{ sent [][]byte }

func (l *capturedLink) send(pkt []byte, to *net.IPAddr) {
	l.sent = append(l.sent, append([]byte(nil), pkt...))
}
func (l *capturedLink) recvLoop() error                     { return nil }
func (l *capturedLink) replyTo(src *net.IPAddr) *net.IPAddr { return src }
func (l *capturedLink) filterSrc() bool                     { return true }
func (l *capturedLink) pinsSource() bool                    { return false }
func (l *capturedLink) fakeFD() int                         { return -1 }
func (l *capturedLink) close()                              {}
func (l *capturedLink) header(realSrc net.IP, to *net.IPAddr) (net.IP, net.IP) {
	return realSrc, to.IP
}

func rawTCPEnd(t *testing.T, isClient bool) (*Raw, *capturedLink) {
	t.Helper()
	r := &Raw{isClient: isClient, profile: "tcp", proto: protoTCP, port: rawServerPort}
	r.cliPort.Store(rawClientPort)
	l := &capturedLink{}
	r.link = l
	r.localIP.Store(&net.IPAddr{IP: net.IPv4(10, 0, 0, byte(1+b2i(!isClient)))})
	r.newTCPFlow()
	return r, l
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func ipTCP(t *testing.T, seg []byte) []byte {
	t.Helper()
	p := buildIP4(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), protoTCP, seg)
	if p == nil {
		t.Fatal("could not wrap the segment in IP")
	}
	return p
}

// The raw "tcp" profile forges a TCP flow, and a forged flow that no TCP endpoint would ever produce
// is worse than none. Measured on the netns lab before this change, over 60 segments of a live tunnel:
// not one SYN -- the flow opened with PSH,ACK out of nowhere -- `win 64240` on every single segment,
// and one frozen ACK number (2262544272) repeated on every client segment while the server sent 94,
// 42, 90 and 126 bytes it never acknowledged. Any DPI that follows TCP state sees a flow it never saw
// open, a receiver whose window never moves, and a peer that acknowledges nothing.
func TestTheForgedTCPFlowOpensWithAHandshake(t *testing.T) {
	cli, cl := rawTCPEnd(t, true)
	srv, sl := rawTCPEnd(t, false)
	peer := &net.IPAddr{IP: net.IPv4(10, 0, 0, 2)}

	cli.knockTCP(peer)
	if len(cl.sent) != 1 {
		t.Fatalf("the client sent %d segments to open the flow, want a SYN", len(cl.sent))
	}
	syn := cl.sent[0]
	if syn[13] != tcpSyn {
		t.Fatalf("the first segment has flags %#x, want SYN %#x", syn[13], tcpSyn)
	}
	cliISN := binary.BigEndian.Uint32(syn[4:8])
	if off := int(syn[12]>>4) * 4; off != 40 {
		t.Fatalf("the SYN carries %d bytes of options, want the 20 a Linux SYN carries", off-20)
	}
	if !hasOpt(syn, tcpOptMSSKind) || !hasOpt(syn, tcpOptSACKOKKind) || !hasOpt(syn, tcpOptWSKind) || !hasOpt(syn, tcpOptTSKind) {
		t.Errorf("the SYN options are not the MSS/SACK/TS/WS set every Linux SYN carries: % x", syn[20:40])
	}

	if !srv.tcpFlow(ipTCP(t, syn), &net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}) {
		t.Fatal("the server handed the SYN on as data instead of answering it")
	}
	if len(sl.sent) != 1 {
		t.Fatalf("the server sent %d segments in answer to a SYN, want a SYN-ACK", len(sl.sent))
	}
	synack := sl.sent[0]
	if synack[13] != tcpSynAck {
		t.Fatalf("the server answered with flags %#x, want SYN|ACK %#x", synack[13], tcpSynAck)
	}
	if got := binary.BigEndian.Uint32(synack[8:12]); got != cliISN+1 {
		t.Fatalf("the SYN-ACK acknowledges %d, want the client's ISN+1 (%d)", got, cliISN+1)
	}
	srvISN := binary.BigEndian.Uint32(synack[4:8])

	if !cli.tcpFlow(ipTCP(t, synack), peer) {
		t.Fatal("the client handed the SYN-ACK on as data")
	}
	if len(cl.sent) != 2 {
		t.Fatalf("the client sent %d segments, want the third leg of the handshake", len(cl.sent))
	}
	ack := cl.sent[1]
	if ack[13] != tcpAckBit {
		t.Fatalf("the third leg has flags %#x, want a bare ACK %#x", ack[13], tcpAckBit)
	}
	if got := binary.BigEndian.Uint32(ack[8:12]); got != srvISN+1 {
		t.Fatalf("the client acknowledges %d, want the server's ISN+1 (%d)", got, srvISN+1)
	}
	if !cli.synAcked.Load() {
		t.Error("the client did not record that the flow is open, so it will keep re-sending the SYN")
	}
}

func hasOpt(seg []byte, kind byte) bool {
	off := int(seg[12]>>4) * 4
	for i := 20; i < off; {
		switch seg[i] {
		case tcpOptEOL:
			return false
		case tcpOptNOPKind:
			i++
			continue
		}
		if seg[i] == kind {
			return true
		}
		if i+1 >= off || int(seg[i+1]) < 2 {
			return false
		}
		i += int(seg[i+1])
	}
	return false
}

// The acknowledgement has to acknowledge. It was a random 32-bit number drawn once per flow and never
// touched again.
func TestTheForgedTCPAckFollowsThePeer(t *testing.T) {
	r, _ := rawTCPEnd(t, true)
	peerISN := uint32(0x11223344)

	seg := buildTCPSeg(net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1), 443, 51820,
		peerISN, 0, tcpSynAck, 400, tcpSynOptions(1, 1), nil)
	r.tcpFlow(ipTCP(t, seg), &net.IPAddr{IP: net.IPv4(10, 0, 0, 2)})
	if got := r.tcpAck.Load(); got != peerISN+1 {
		t.Fatalf("after the SYN-ACK the ack is %d, want %d", got, peerISN+1)
	}

	next := peerISN + 1
	for _, n := range []int{100, 40, 1200} {
		data := buildTCPSeg(net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1), 443, 51820,
			next, 0, tcpPshAck, 400, tcpTSOption(1, 1), make([]byte, n))
		r.tcpFlow(ipTCP(t, data), &net.IPAddr{IP: net.IPv4(10, 0, 0, 2)})
		next += uint32(n)
		if got := r.tcpAck.Load(); got != next {
			t.Fatalf("after %d bytes the ack is %d, want %d", n, got, next)
		}
	}

	stale := buildTCPSeg(net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1), 443, 51820,
		peerISN+1, 0, tcpPshAck, 400, tcpTSOption(1, 1), make([]byte, 10))
	r.tcpFlow(ipTCP(t, stale), &net.IPAddr{IP: net.IPv4(10, 0, 0, 2)})
	if got := r.tcpAck.Load(); got != next {
		t.Fatalf("a reordered segment dragged the ack backwards to %d, want %d", got, next)
	}
}

// A receive window that never moves is the other half of the same tell.
func TestTheForgedTCPWindowMoves(t *testing.T) {
	seen := map[uint16]bool{}
	prev := tcpWindowFor(1000, 500000)
	jump := uint16(0)
	for i := uint32(0); i < 4000; i++ {
		w := tcpWindowFor(1000+i*1400, 500000+i*11)
		seen[w] = true
		if w < rawTCPWinLo || w > rawTCPWinLo+rawTCPWinSpan+16 {
			t.Fatalf("window %d outside the advertised band", w)
		}
		if d := int(w) - int(prev); d > int(jump) {
			jump = uint16(d)
		} else if -d > int(jump) {
			jump = uint16(-d)
		}
		prev = w
	}
	if len(seen) < 100 {
		t.Fatalf("the window took %d distinct values over 4000 segments; it was one value for the life "+
			"of the flow", len(seen))
	}
	if jump > 64 {
		t.Errorf("the window jumped by %d in one segment — a real receive window walks, it does not hop", jump)
	}
}
