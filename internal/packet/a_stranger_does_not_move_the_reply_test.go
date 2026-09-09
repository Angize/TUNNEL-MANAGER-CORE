package packet

import (
	"net"
	"testing"
)

// The udp server adopts the address a frame arrived from as the address it replies to, and it does so
// with NO source allowlist -- which is what lets a client that rotates its source IP be followed for
// free, where the raw server needs peer_src_ips spelled out.
//
// That is only safe because the adoption sits BEHIND the crypto gate: learnPeer runs after the AEAD
// opened the frame and the replay window accepted it. This pins that ordering, so nobody moves the
// adoption in front of the gate and turns "follows a moving client" into "anyone who can send a packet
// redirects the tunnel".
//
// What this proves and what it does not: it drives handleCrypto, which is the gate itself, so it holds
// for every packet that reaches the gate. It does NOT prove the read loop routes to handleCrypto -- the
// crypto-off path calls a different one, and there the magic byte is the only check, which is the
// exposure main.go already refuses to be quiet about at startup.
func TestAStrangerCannotMoveWhereTheUDPServerReplies(t *testing.T) {
	legit := &net.UDPAddr{IP: net.IPv4(10, 9, 0, 1), Port: 4500}
	stranger := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 66), Port: 5555}

	b := &UDP{cryptoOn: true, psk: "a-psk-for-the-stranger-probe-1234", closeCh: make(chan struct{})}
	b.soloPeer.Store(legit)

	for _, pkt := range [][]byte{
		{},
		{magic},
		{magic, typeData, 1, 2, 3, 4, 5, 6, 7, 8},
		make([]byte, 64),
	} {
		b.handleCrypto(pkt, stranger)

		if got := b.soloPeer.Load(); got == nil || !got.IP.Equal(legit.IP) || got.Port != legit.Port {
			t.Fatalf("a %d-byte unauthenticated packet from %v moved the reply address to %v",
				len(pkt), stranger, got)
		}
	}
}
