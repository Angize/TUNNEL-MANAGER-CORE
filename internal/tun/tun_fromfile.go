//go:build linux

package tun

import "os"

func FromFile(f *os.File, name string) *Device {
	return &Device{f: f, fd: -1, Name: name}
}

func FromFileGSO(f *os.File, name string) *Device {
	return &Device{f: f, fd: -1, Name: name, gso: true, rbuf: make([]byte, vnetHdrLen+65535)}
}
