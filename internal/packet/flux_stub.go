//go:build !linux

package packet

import (
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

type Flux struct{}

func (f *Flux) Run() error   { return errRawUnsupported }
func (f *Flux) Close() error { return nil }

func DialFlux(string, *tun.Device, time.Duration, time.Duration, bool, bool, string, string, string, string, int64, bool, int, int) (*Flux, error) {
	return nil, errRawUnsupported
}

func ListenFlux(string, *tun.Device, time.Duration, time.Duration, bool, bool, string, string, string, string, int64, bool, int, int) (*Flux, error) {
	return nil, errRawUnsupported
}
