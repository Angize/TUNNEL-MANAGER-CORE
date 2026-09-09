package packet

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

var band atomic.Uint64

func init() { SetSportBand(0, 0) }

func SetSportBand(lo, hi int) {
	l, span := sportBand(lo, hi)
	band.Store(uint64(l)<<32 | uint64(span))
}

func loadBand() (lo, span uint32) {
	v := band.Load()
	return uint32(v >> 32), uint32(v)
}

func SportBand() (lo, hi int) {
	l, span := loadBand()
	return int(l), int(l + span - 1)
}

func drawSport() uint16 { return randPort(loadBand()) }

const sportBindTries = 4

func dialFromBand(ctx context.Context, d func() *net.Dialer, addr string) (net.Conn, error) {
	var err error
	for i := 0; i < sportBindTries; i++ {
		var c net.Conn
		if c, err = d().DialContext(ctx, "tcp", addr); err == nil {
			return c, nil
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, err
		}
	}
	return nil, err
}

func (b *TCP) dialBand(timeout time.Duration, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return dialFromBand(ctx, func() *net.Dialer { return b.dialer(timeout) }, addr)
}
