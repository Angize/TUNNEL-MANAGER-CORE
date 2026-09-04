package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var ErrGSOUnsupported = errors.New("the gso-specific part of the tun open failed")

var setIff = func(f *os.File, ifr *[ifReqSize]byte) syscall.Errno {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIff, uintptr(unsafe.Pointer(ifr)))
	return errno
}

var setOffload = func(f *os.File, flags uintptr) syscall.Errno {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetOffload, flags)
	return errno
}

const (
	iffTun  = 0x0001
	iffNoPI = 0x1000

	iffMultiQueue = 0x0100
	tunSetIff     = 0x400454ca
	ifReqSize     = 40
)

type Device struct {
	f    *os.File
	fd   int
	Name string

	gso  bool
	uso  bool
	rbuf []byte
	q    [][]byte

	nSuper, nSeg atomic.Uint64
	nUnsplit     atomic.Uint64

	nOversize atomic.Uint64

	nOut, nWrites atomic.Uint64

	repAt   time.Time
	repSeen [6]uint64
	repSaid bool
}

const gsoReportEvery = 10 * time.Minute

func (d *Device) reportGSO() {
	now := time.Now()
	cur := [6]uint64{d.nSuper.Load(), d.nSeg.Load(), d.nUnsplit.Load(), d.nOversize.Load(),
		d.nOut.Load(), d.nWrites.Load()}
	if d.repAt.IsZero() {
		d.repAt = now
		if cur == ([6]uint64{}) {
			return
		}
	} else {
		moved := cur != d.repSeen
		switch {
		case moved && !d.repSaid:
		case moved, !d.repSaid:
			if now.Sub(d.repAt) < gsoReportEvery {
				return
			}
		default:
			return
		}
	}
	d.repAt, d.repSeen, d.repSaid = now, cur, true
	log.Printf("tun %s: gso in %d super-packets -> %d segments, %d unsplit%s; out %d packets in %d writes",
		d.Name, cur[0], cur[1], cur[2], oversizeNote(cur[3]), cur[4], cur[5])
}

func OpenN(name string, mtu int, addr string, gso bool, n int) ([]*Device, error) {
	if n < 1 {
		n = 1
	}
	var ds []*Device
	closeAll := func() {
		for _, d := range ds {
			d.Close()
		}
	}
	for i := 0; i < n; i++ {
		hint := name
		if i > 0 {
			hint = ds[0].Name
		}
		d, err := openQueue(hint, gso, n > 1)
		if err != nil {
			closeAll()
			return nil, err
		}
		ds = append(ds, d)
	}
	for _, args := range [][]string{
		{"link", "set", "dev", ds[0].Name, "mtu", strconv.Itoa(mtu)},
		{"addr", "add", addr, "dev", ds[0].Name},
		{"link", "set", "dev", ds[0].Name, "up"},
	} {
		if err := ipCmd(args...); err != nil {
			closeAll()
			return nil, err
		}
	}
	return ds, nil
}

func openQueue(name string, gso, multi bool) (*Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	flags := uint16(iffTun | iffNoPI)
	if multi {
		flags |= iffMultiQueue
	}
	if gso {
		flags |= iffVnetHdr
	}
	var ifr [ifReqSize]byte
	copy(ifr[:15], name)
	binary.LittleEndian.PutUint16(ifr[16:18], flags)
	if errno := setIff(f, &ifr); errno != 0 {
		f.Close()
		if gso {
			return nil, fmt.Errorf("TUNSETIFF (vnet-hdr): %w: %w", ErrGSOUnsupported, errno)
		}
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	real := strings.TrimRight(string(ifr[:16]), "\x00")

	uso := false
	if gso {
		if setOffload(f, uintptr(tunFCSUM|tunFTSO4|tunFTSO6|tunFUSO4|tunFUSO6)) == 0 {
			uso = true
		} else if errno := setOffload(f, uintptr(tunFCSUM|tunFTSO4|tunFTSO6)); errno != 0 {
			f.Close()
			return nil, fmt.Errorf("TUNSETOFFLOAD (gso): %w: %w", ErrGSOUnsupported, errno)
		}
	}

	d := &Device{f: f, fd: int(f.Fd()), Name: real, gso: gso, uso: uso}
	if gso {
		d.rbuf = make([]byte, vnetHdrLen+65535)
	}

	if err := syscall.SetNonblock(d.fd, true); err != nil {
		d.Close()
		return nil, fmt.Errorf("making the tun fd non-blocking: %w", err)
	}
	return d, nil
}

func rawRead(fd int, p []byte) (int, error) {
	for {
		n, err := syscall.Read(fd, p)
		if err == syscall.EINTR {
			continue
		}
		return n, err
	}
}

func rawWrite(fd int, p []byte) (int, error) {
	for {
		n, err := syscall.Write(fd, p)
		if err == syscall.EINTR {
			continue
		}
		return n, err
	}
}

func writeIovec(fd int, iov []unix.Iovec) (int, error) {
	for {
		n, _, errno := syscall.Syscall(unix.SYS_WRITEV, uintptr(fd),
			uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)))
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return int(n), errno
		}
		return int(n), nil
	}
}

func rawWritev(fd int, hdr, pkt []byte) (int, error) {
	var iov [2]unix.Iovec
	iov[0].Base, iov[1].Base = &hdr[0], &pkt[0]
	iov[0].SetLen(len(hdr))
	iov[1].SetLen(len(pkt))
	return writeIovec(fd, iov[:])
}

func (d *Device) rd(p []byte) (int, error) {
	if d.fd < 0 {
		return d.f.Read(p)
	}
	for {
		n, err := rawRead(d.fd, p)
		if err != syscall.EAGAIN {
			return n, err
		}
		if err := d.waitReadable(); err != nil {
			return 0, err
		}
	}
}

func (d *Device) tryRd(p []byte) (int, bool, error) {
	if d.fd < 0 {
		return 0, false, nil
	}
	n, err := rawRead(d.fd, p)
	if err == syscall.EAGAIN {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}

func (d *Device) waitReadable() error {
	fds := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}
	for {
		_, err := unix.Poll(fds, -1)
		if err != unix.EINTR {
			return err
		}
	}
}

func (d *Device) wr(p []byte) (int, error) {
	if d.fd >= 0 {
		return rawWrite(d.fd, p)
	}
	return d.f.Write(p)
}

func (d *Device) wrv(hdr, pkt []byte) (int, error) {
	if d.fd >= 0 {
		return rawWritev(d.fd, hdr, pkt)
	}
	joined := make([]byte, len(hdr)+len(pkt))
	copy(joined, hdr)
	copy(joined[len(hdr):], pkt)
	return d.f.Write(joined)
}

func (d *Device) wrvGSO(vnet, lead []byte, rest [][]byte, off int) (int, error) {
	if d.fd >= 0 {
		var iov [groMaxSegs + 1]unix.Iovec
		iov[0].Base, iov[1].Base = &vnet[0], &lead[0]
		iov[0].SetLen(len(vnet))
		iov[1].SetLen(len(lead))
		for i, p := range rest {
			pay := p[off:]
			iov[i+2].Base = &pay[0]
			iov[i+2].SetLen(len(pay))
		}
		return writeIovec(d.fd, iov[:len(rest)+2])
	}
	joined := make([]byte, 0, len(vnet)+len(lead))
	joined = append(append(joined, vnet...), lead...)
	for _, p := range rest {
		joined = append(joined, p[off:]...)
	}
	return d.f.Write(joined)
}

func (d *Device) Read(buf []byte) (int, error) {
	if !d.gso {
		return d.rd(buf)
	}
	for {
		for len(d.q) == 0 {
			segs, err := d.readGSO()
			if err != nil {
				return 0, err
			}
			d.q = segs
		}
		if n, ok := d.serve(buf); ok {
			return n, nil
		}
	}
}

func (d *Device) TryRead(buf []byte) (int, bool, error) {
	if !d.gso {
		return d.tryRd(buf)
	}
	for {
		for len(d.q) == 0 {
			segs, ok, err := d.tryReadGSO()
			if err != nil || !ok {
				return 0, false, err
			}
			d.q = segs
		}
		if n, ok := d.serve(buf); ok {
			return n, true, nil
		}
	}
}

func (d *Device) serve(buf []byte) (int, bool) {
	seg := d.q[0]
	d.q = d.q[1:]
	if len(seg) > len(buf) {
		d.nOversize.Add(1)
		return 0, false
	}
	return copy(buf, seg), true
}

func (d *Device) readGSO() ([][]byte, error) {
	n, err := d.rd(d.rbuf)
	if err != nil {
		return nil, err
	}
	return d.segsFrom(n), nil
}

func (d *Device) tryReadGSO() ([][]byte, bool, error) {
	n, ok, err := d.tryRd(d.rbuf)
	if err != nil || !ok {
		return nil, false, err
	}
	return d.segsFrom(n), true, nil
}

func (d *Device) segsFrom(n int) [][]byte {
	if n <= vnetHdrLen {
		return nil
	}
	flags := d.rbuf[0]
	gsoType := int(d.rbuf[1])
	gsoSize := int(binary.LittleEndian.Uint16(d.rbuf[4:6]))
	pkt := d.rbuf[vnetHdrLen:n]
	segs, split := [][]byte{pkt}, false
	if gsoType&^gsoECN != gsoNone {
		segs, split = splitGSO(pkt, gsoSize, gsoType)
	}
	if !split {
		if flags&vnetNeedsCsum != 0 {
			finalizeCsum(pkt)
		}
		if gsoType&^gsoECN != gsoNone {
			d.nUnsplit.Add(1)
		}
		d.reportGSO()
		return segs
	}
	d.nSuper.Add(1)
	d.nSeg.Add(uint64(len(segs)))
	d.reportGSO()
	return segs
}

var zeroVnetHdr [vnetHdrLen]byte

func (d *Device) Write(pkt []byte) (int, error) {
	if !d.gso {
		n, err := d.wr(pkt)
		if err == nil {
			d.nOut.Add(1)
			d.nWrites.Add(1)
		}
		return n, err
	}
	if len(pkt) == 0 {
		return 0, nil
	}
	n, err := d.wrv(zeroVnetHdr[:], pkt)
	if n -= vnetHdrLen; n < 0 {
		n = 0
	}
	if err == nil {
		d.nOut.Add(1)
		d.nWrites.Add(1)
	}
	return n, err
}

func oversizeNote(n uint64) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", %d oversize dropped", n)
}

func (d *Device) Close() error {
	if d.gso && (d.nSuper.Load() > 0 || d.nUnsplit.Load() > 0 || d.nOversize.Load() > 0 || d.nOut.Load() > 0) {
		log.Printf("tun %s: gso final: in %d super-packets -> %d segments, %d unsplit%s; out %d packets in %d writes",
			d.Name, d.nSuper.Load(), d.nSeg.Load(), d.nUnsplit.Load(), oversizeNote(d.nOversize.Load()),
			d.nOut.Load(), d.nWrites.Load())
	}
	return d.f.Close()
}

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
