package tun

import "os"

// FromFile wraps an already-open file descriptor as a Device WITHOUT running any
// `ip` configuration. It exists so the data-plane (packet.UDP / packet.TCP)
// can be driven end-to-end in tests over a socketpair standing in for the TUN,
// on hosts where /dev/net/tun or iproute2 is unavailable. Not used in production.
func FromFile(f *os.File, name string) *Device {
	return &Device{f: f, fd: -1, Name: name}
}

// FromFileGSO is FromFile with the virtio-net header path ENABLED, so Read/readGSO/Write —
// everything Open(gso=true) turns on — can be driven over a socketpair. Without it the whole GSO
// device path was unreachable from a test (FromFile hard-coded gso=false and Open needs
// /dev/net/tun plus a kernel with IFF_VNET_HDR), so only the pure segment() helper was ever
// covered and a regression in the read path could only be found on the live fleet. Not used in
// production.
func FromFileGSO(f *os.File, name string) *Device {
	return &Device{f: f, fd: -1, Name: name, gso: true, rbuf: make([]byte, vnetHdrLen+65535)}
}
