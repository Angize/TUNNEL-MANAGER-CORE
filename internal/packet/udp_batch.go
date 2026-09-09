package packet

import "net"

type datagram struct {
	pkt  []byte
	addr *net.UDPAddr
}
