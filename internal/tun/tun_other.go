//go:build !linux

// Non-linux stand-in for the TUN device, so the tree TYPE-CHECKS for another GOOS. The core only ever
// runs on linux and nothing here is meant to work: Open fails, which is the only place it can fail
// honestly. What it buys is `GOOS=windows go build ./...` and `GOOS=darwin go vet ./...`, the cheapest
// full-tree check there is. Keep the method set in step with tun_linux.go — the cross-build enforces it.
package tun

import (
	"errors"
	"os"
)

// ErrGSOUnsupported mirrors the linux sentinel so main's gso fallback still compiles. Nothing can
// return it here: Open never gets far enough to try a gso-specific ioctl.
var ErrGSOUnsupported = errors.New("the gso-specific part of the tun open failed")

var errNotLinux = errors.New("tun: the core's TUN device is implemented on linux only")

// Device is the off-linux shape of the real device. It carries a file so the FromFile path used by
// the data-plane tests still has something to read and write; everything TUN-specific is absent.
type Device struct {
	Name string
	f    *os.File
}

// Open always fails off linux. It is the single honest failure point: there is no /dev/net/tun to
// open and no ioctl to run, so failing here beats pretending anywhere later.
func Open(name string, mtu int, addr string, gso bool) (*Device, error) { return nil, errNotLinux }

// FromFile wraps an already-open fd as a Device WITHOUT any `ip` configuration, exactly as on
// linux, so a data-plane test driven over a socketpair still compiles for another GOOS.
func FromFile(f *os.File, name string) *Device { return &Device{Name: name, f: f} }

func (d *Device) Read(buf []byte) (int, error)  { return d.f.Read(buf) }
func (d *Device) Write(pkt []byte) (int, error) { return d.f.Write(pkt) }
func (d *Device) Close() error                  { return d.f.Close() }
