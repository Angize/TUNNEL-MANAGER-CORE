//go:build !linux

package packet

import (
	"errors"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

type Raw struct{}

var errRawUnsupported = errors.New("raw transport requires Linux (raw IPv4 sockets)")

func (r *Raw) Run() error   { return errRawUnsupported }
func (r *Raw) Close() error { return nil }

func DialRaw(string, *tun.Device, bool, string, string, string, bool, int, int, int, int, int, bool, SportRotation, ...*tun.Device) (*Raw, error) {
	return nil, errRawUnsupported
}

func ListenRaw(string, *tun.Device, bool, string, string, string, bool, int, int, int, int, int, bool, SportRotation, ...*tun.Device) (*Raw, error) {
	return nil, errRawUnsupported
}
