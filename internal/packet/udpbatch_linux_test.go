//go:build linux

package packet

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestABatchedReceiveKeepsEveryDatagramDistinct(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	bat := newUDPBatch(srv)
	if bat == nil {
		t.Fatal("no batcher on linux")
	}
	cli, err := net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	const packets = 20
	for i := 0; i < packets; i++ {
		if _, err := cli.Write([]byte(fmt.Sprintf("packet-%03d", i))); err != nil {
			t.Fatal(err)
		}
	}

	srcPort := cli.LocalAddr().(*net.UDPAddr).Port
	_ = srv.SetReadDeadline(time.Now().Add(10 * time.Second))
	var got []string
	for len(got) < packets {
		ds, err := bat.recv()
		if err != nil {
			t.Fatalf("recv after %d of %d datagrams: %v", len(got), packets, err)
		}
		for i, d := range ds {
			if d.addr == nil || d.addr.Port != srcPort {
				t.Fatalf("datagram %q came back with address %v, want port %d", d.pkt, d.addr, srcPort)
			}
			if i > 0 && &d.pkt[0] == &ds[0].pkt[0] {
				t.Fatal("two datagrams in one batch share a buffer: every frame in the burst would be " +
					"handed the same bytes, and the AEAD would open the wrong one")
			}
			got = append(got, string(d.pkt))
		}
	}
	for i, s := range got {
		if want := fmt.Sprintf("packet-%03d", i); s != want {
			t.Fatalf("datagram %d is %q, want %q: the burst was reordered or a buffer was reused", i, s, want)
		}
	}
}

func TestANilSocketGivesNoBatcher(t *testing.T) {
	if newUDPBatch(nil) != nil {
		t.Fatal("a nil socket must give a nil batcher, so the caller keeps its single-datagram read")
	}
}
