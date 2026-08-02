//go:build linux

// This file is linux-only because Device is: it wraps a TUN fd whose whole implementation lives in
// tun_linux.go. Without the tag the package fails to compile for any other GOOS with "undefined:
// Device", so `GOOS=windows go build ./...` — the cheapest way to type-check the tree from a non-linux
// box — could not run at all. Nothing changes on the fleet; the core only ever runs on linux.
package tun

import "os"

// FromFile wraps an already-open file descriptor as a Device WITHOUT running any
// `ip` configuration. It exists so the data-plane (packet.UDP / packet.TCP)
// can be driven end-to-end in tests over a socketpair standing in for the TUN,
// on hosts where /dev/net/tun or iproute2 is unavailable. Not used in production.
func FromFile(f *os.File, name string) *Device {
	return &Device{f: f, fd: -1, Name: name}
}

// FromFileGSO is FromFile with the virtio-net header path ENABLED, so Read/readGSO/Write can be driven
// over a socketpair. Without it the whole GSO device path is unreachable from a test — FromFile
// hard-codes gso=false and Open needs /dev/net/tun plus a kernel with IFF_VNET_HDR — so only the pure
// segment() helper was ever covered. Not used in production.
func FromFileGSO(f *os.File, name string) *Device {
	return &Device{f: f, fd: -1, Name: name, gso: true, rbuf: make([]byte, vnetHdrLen+65535)}
}
