// The udp carrier's receive side, taken a burst at a time instead of a datagram at a time.
//
// The single reader is deliberate and stays: crypto, the replay guard, the handshake cache and the FEC
// decoder all assume one receive goroutine. What this changes is only how many system calls that one
// goroutine makes -- which is what a cpu profile of a saturated receiver says the cost actually is.
package packet

import "net"

// datagram is one received packet and the address it came from. pkt aliases the batch's own buffer and
// is valid until the next recv, exactly as the single-datagram read's buffer was.
type datagram struct {
	pkt  []byte
	addr *net.UDPAddr
}
