//go:build !linux

package packet

import (
	"errors"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

type Raw struct{}

var errRawUnsupported = errors.New("raw transport requires Linux (raw IPv4 sockets)")

func (r *Raw) Run() error   { return errRawUnsupported }
func (r *Raw) Close() error { return nil }

func DialRaw(string, *tun.Device, time.Duration, bool, string, string, string, bool, int, int, int, int, int, bool, ...*tun.Device) (*Raw, error) {
	return nil, errRawUnsupported
}

func ListenRaw(string, *tun.Device, time.Duration, bool, string, string, string, bool, int, int, int, int, int, bool, ...*tun.Device) (*Raw, error) {
	return nil, errRawUnsupported
}

func DialSpoof(string, *tun.Device, time.Duration, bool, string, string, string, string, bool, int, int, int) (*Raw, error) {
	return nil, errRawUnsupported
}

func ListenSpoof(string, *tun.Device, time.Duration, bool, string, string, string, string, bool, int, int, int) (*Raw, error) {
	return nil, errRawUnsupported
}

func ProbeSpoof() SpoofProbe {
	return SpoofProbe{Reason: "raw transport requires Linux (raw IPv4 sockets)"}
}
