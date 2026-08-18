//go:build linux

package packet

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func listener(t *testing.T) (*ipv4.PacketConn, *net.UDPConn, *net.UDPConn) {
	t.Helper()
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rx.Close() })
	tx, err := net.DialUDP("udp4", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Close() })
	return ipv4.NewPacketConn(rx), rx, tx
}

func recvOrTimeout(t *testing.T, b *recvBatcher, pc *ipv4.PacketConn) []ipv4.Message {
	t.Helper()
	type res struct {
		ms  []ipv4.Message
		err error
	}
	ch := make(chan res, 1)
	go func() { ms, err := b.recv(pc); ch <- res{ms, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.ms
	case <-time.After(5 * time.Second):
		t.Fatal("recv blocked with datagrams already queued: it is waiting for the batch to FILL, " +
			"which holds a lone packet back until the next one arrives and can stall a handshake")
		return nil
	}
}

func TestABurstIsTakenWithoutWaitingForTheArrayToFill(t *testing.T) {
	pc, _, tx := listener(t)
	b := newRecvBatcher(maxRecvBatch)

	const sent = 3
	for i := 0; i < sent; i++ {
		if _, err := tx.Write([]byte{byte('a' + i)}); err != nil {
			t.Fatal(err)
		}
	}
	ms := recvOrTimeout(t, b, pc)
	if len(ms) != sent {
		t.Fatalf("took %d of %d queued datagrams", len(ms), sent)
	}
}

func TestAWholeBurstComesBackInOneCall(t *testing.T) {
	pc, _, tx := listener(t)
	b := newRecvBatcher(maxRecvBatch)

	const sent = 40
	for i := 0; i < sent; i++ {
		if _, err := tx.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if ms := recvOrTimeout(t, b, pc); len(ms) != sent {
		t.Fatalf("took %d of %d queued datagrams in one call: the rest wait for another syscall, and the "+
			"tun writer never sees them as one run", len(ms), sent)
	}
}

func TestEverySlotKeepsItsOwnBytes(t *testing.T) {
	pc, _, tx := listener(t)
	b := newRecvBatcher(maxRecvBatch)

	want := []string{"first", "second", "third", "fourth"}
	for _, w := range want {
		if _, err := tx.Write([]byte(w)); err != nil {
			t.Fatal(err)
		}
	}
	ms := recvOrTimeout(t, b, pc)
	if len(ms) != len(want) {
		t.Fatalf("took %d of %d", len(ms), len(want))
	}
	for i := range ms {

		if got := string(ms[i].Buffers[0][:ms[i].N]); got != want[i] {
			t.Fatalf("slot %d carried %q, want %q -- the slots are sharing a buffer", i, got, want[i])
		}
	}
}

func TestWhatDoesNotFitInOneCallIsStillThereForTheNext(t *testing.T) {
	pc, _, tx := listener(t)
	b := newRecvBatcher(maxRecvBatch)

	total := maxRecvBatch + 3
	for i := 0; i < total; i++ {
		if _, err := tx.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	var got []byte
	for len(got) < total {
		for _, m := range recvOrTimeout(t, b, pc) {
			got = append(got, m.Buffers[0][:m.N]...)
		}
	}
	if len(got) != total {
		t.Fatalf("read %d datagrams, sent %d", len(got), total)
	}
	for i := range got {
		if got[i] != byte(i) {
			t.Fatalf("datagram %d carried %d: the burst was reordered or one was lost", i, got[i])
		}
	}
}

func TestEachMessageCarriesItsOwnControlMessage(t *testing.T) {
	pc, rx, tx := listener(t)
	rc, err := rx.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	if cerr := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
	}); cerr != nil || serr != nil {
		t.Fatalf("enabling IP_PKTINFO: %v %v", cerr, serr)
	}
	b := newRecvBatcher(maxRecvBatch)
	for i := 0; i < 2; i++ {
		if _, err := tx.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	for i, m := range recvOrTimeout(t, b, pc) {
		if m.NN == 0 {
			t.Fatalf("message %d came with no control message, so a pooled server would answer from "+
				"the kernel-default source and burn every pool IP but the primary", i)
		}
		if d := pktinfoDst(m.OOB[:m.NN]); d == nil || !d.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("message %d reported destination %v, want 127.0.0.1", i, d)
		}
	}
}

func TestTheReceiveLoopSlicesEachMessageByItsOwnLengths(t *testing.T) {
	src := readSource(t, "raw_linux.go")
	for _, want := range []string{"m.OOB[:m.NN]", "m.Buffers[0][:m.N]"} {
		if !strings.Contains(src, want) {
			t.Fatalf("the receive loop does not slice by %s, so a message is read at the wrong length", want)
		}
	}
}

func TestASlotHoldsAFullDatagram(t *testing.T) {
	b := newRecvBatcher(maxRecvBatch)
	for i, m := range b.ms {
		if got := len(m.Buffers[0]); got != maxDatagram {
			t.Fatalf("slot %d holds %d bytes, want %d", i, got, maxDatagram)
		}
		if len(m.OOB) != pktinfoOOBLen {
			t.Fatalf("slot %d has %d oob bytes, want %d", i, len(m.OOB), pktinfoOOBLen)
		}
	}
}
