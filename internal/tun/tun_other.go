//go:build !linux

package tun

import "errors"

var errNotLinux = errors.New("tun: the core's TUN device is implemented on linux only")

type Device struct {
	Name string
}

func OpenN(name string, mtu int, addr string, gso bool, n int) ([]*Device, error) {
	return nil, errNotLinux
}

func (d *Device) TryRead(buf []byte) (int, bool, error) { return 0, false, errNotLinux }
func (d *Device) Read(buf []byte) (int, error)          { return 0, errNotLinux }
func (d *Device) Write(pkt []byte) (int, error)         { return 0, errNotLinux }
func (d *Device) WriteBatch(pkts [][]byte) error        { return errNotLinux }
func (d *Device) Close() error                          { return errNotLinux }
