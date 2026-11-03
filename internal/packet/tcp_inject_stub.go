//go:build !linux

package packet

import "net"

type desyncSend struct{}

func (b *TCP) sendTCPFakes(net.Conn) {}
