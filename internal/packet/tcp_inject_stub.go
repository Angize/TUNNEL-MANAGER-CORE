//go:build !linux

package packet

import "net"

func (b *TCP) sendTCPFakes(conn net.Conn) {
	if b.dsWatch != nil {
		b.dsWatch(conn)
	}
}
