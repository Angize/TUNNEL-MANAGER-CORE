//go:build !linux

package packet

import "net"

func (b *TCP) sendTCPFakes(net.Conn) {}
