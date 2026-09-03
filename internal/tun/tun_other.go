//go:build !linux

package tun

import (
	"errors"
	"os"
)

var ErrGSOUnsupported = errors.New("the gso-specific part of the tun open failed")

var errNotLinux = errors.New("tun: the core's TUN device is implemented on linux only")

type Device struct {
	Name string
	f    *os.File
}

func OpenN(name string, mtu int, addr string, gso bool, n int) ([]*Device, error) {
	return nil, errNotLinux
}

func FromFile(f *os.File, name string) *Device { return &Device{Name: name, f: f} }

func (d *Device) TryRead(buf []byte) (int, bool, error) { return 0, false, nil }
func (d *Device) Read(buf []byte) (int, error)          { return d.f.Read(buf) }
func (d *Device) Write(pkt []byte) (int, error)         { return d.f.Write(pkt) }

func (d *Device) WriteBatch(pkts [][]byte) error {
	var ferr error
	for _, p := range pkts {
		if _, err := d.Write(p); err != nil && ferr == nil {
			ferr = err
		}
	}
	return ferr
}

func (d *Device) Close() error { return d.f.Close() }
