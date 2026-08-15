// Package tun opens and configures a Linux TUN device (raw L3 packets, no PI
// header). Address/MTU/up are applied by shelling out to `ip`, matching the
// node agent's philosophy of driving iproute2 rather than talking netlink
// directly. The device is non-persistent, so closing the fd removes it.
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

// ErrGSOUnsupported wraps a failure of one of the two ioctls Open runs ONLY when gso was asked for:
// TUNSETIFF with IFF_VNET_HDR, and TUNSETOFFLOAD. It means "the gso-specific part of the open failed",
// NOT "this kernel lacks gso" — a missing CAP_NET_ADMIN fails the same ioctl and the errno does not
// distinguish them, so a caller must prove it by opening again WITHOUT gso and seeing that succeed.
var ErrGSOUnsupported = errors.New("the gso-specific part of the tun open failed")

// setIff and setOffload are seams. Production runs the ioctl; the gso-classification test replaces them
// to fail a chosen one, which is the only way to reach the ErrGSOUnsupported branches on a kernel that
// supports gso perfectly well. They take ifr as a POINTER, not a uintptr, because the
// unsafe.Pointer→uintptr conversion must happen inside syscall.Syscall's own argument list.
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
	// iffMultiQueue makes ONE interface out of several open fds. The device keeps its single name, IP
	// and MTU -- `ip addr` still shows one card -- and the queues exist only inside this process, so
	// several goroutines can read and write it without queueing behind one file's lock.
	iffMultiQueue = 0x0100
	tunSetIff     = 0x400454ca
	ifReqSize     = 40
)

// Device is an open TUN interface. When gso is set it was opened with a
// virtio-net header and segmentation offload; Read then serves one L3 packet per
// call out of a queue filled by splitting the kernel's super-packets (see
// offload_linux.go), so callers keep the simple one-packet-per-Read contract.
type Device struct {
	f    *os.File
	fd   int // raw blocking fd for data-path I/O — bypasses Go's netpoller (see rawRead)
	Name string

	gso  bool
	rbuf []byte   // super-packet read buffer (vnet header + up to 64 KiB)
	q    [][]byte // segments not yet handed out; drained before the next read

	nSuper, nSeg atomic.Uint64 // GSO diagnostic: super-packets split and segments produced
	nUnsplit     atomic.Uint64 // GSO super-packets handed back unsegmented (unknown/legacy gso_type, or a header segment() would not parse)
	// nOversize counts packets Read DROPPED because they did not fit the caller's buffer. It is a guard on
	// an exported API, not a diagnostic: no caller in this binary can trip it, since rbuf is
	// vnetHdrLen+65535 and every caller passes exactly maxDatagram. It is therefore reported only when
	// NON-ZERO — a permanent "0 oversize dropped" is noise in a line whose job is "is this knob working?".
	nOversize atomic.Uint64

	// Reporting state, touched ONLY by the single reader goroutine (readGSO), so no lock.
	repAt   time.Time // when the reporting window last restarted
	repSeen [4]uint64 // the values logged then: super, seg, unsplit, oversize
	repSaid bool      // a line has been written at least once
}

// gsoReportEvery bounds how often a running device logs its GSO counters. With the only evidence printed
// at SHUTDOWN, an operator who turned GSO on had no way to tell "the kernel is coalescing" from "the
// knob is inert" without stopping the tunnel. Ten minutes is quiet enough to live in the journal forever
// and often enough to answer the question; a report is skipped entirely when nothing moved.
const gsoReportEvery = 10 * time.Minute

// reportGSO logs the counters at most once per gsoReportEvery, and only when something changed: silence
// on the first read, an IMMEDIATE line the first time a counter moves, at most one per window after
// that, and one "still nothing" line once a full window passes with no movement. Reporting on the first
// read would say "0 -> 0" before the kernel could coalesce anything. readGSO only, so no lock.
func (d *Device) reportGSO() {
	now := time.Now()
	cur := [4]uint64{d.nSuper.Load(), d.nSeg.Load(), d.nUnsplit.Load(), d.nOversize.Load()}
	if d.repAt.IsZero() {
		d.repAt = now
		if cur == ([4]uint64{}) {
			// FIRST read and nothing has happened yet. "gso 0 super-packets -> 0 segments" here is not
			// evidence of anything — it is just too early — and it reads exactly like the answer THE
			// KNOB IS INERT. Printing it milliseconds after startup told the operator the opposite of
			// the truth and, because it stamped the window, put the real answer ten minutes away.
			return
		}
		// Something already moved on the very first read: that IS the answer, so say it now.
	} else {
		moved := cur != d.repSeen
		switch {
		case moved && !d.repSaid:
			// The counters moved for the FIRST time. This is the line the operator is looking for and
			// it must not wait out a window.
		case moved, !d.repSaid:
			// A later movement, or the single "still nothing" line that makes an inert knob visible.
			if now.Sub(d.repAt) < gsoReportEvery {
				return
			}
		default:
			return // nothing moved and we have already spoken: stay quiet
		}
	}
	d.repAt, d.repSeen, d.repSaid = now, cur, true
	log.Printf("tun %s: gso %d super-packets -> %d segments, %d unsplit%s",
		d.Name, cur[0], cur[1], cur[2], oversizeNote(cur[3]))
}

// OpenN creates the TUN interface, assigns addr (CIDR, e.g. "10.200.0.1/24"), sets mtu and brings it
// up. name is a hint; the kernel-assigned name is returned in Device.Name. When gso is true the device
// is opened with a virtio-net header and TCP/UDP segmentation offload for higher bulk throughput.
// n is how many QUEUES the one interface gets, so n goroutines can drive it without queueing behind a
// single file's lock. Every queue is a full Device with its own buffers; only the first configures the
// interface, because there is only ever one interface.
//
// Every queue opened MUST be used: the kernel spreads packets across all of them, so a queue nobody
// reads is a blackhole for whatever lands on it.
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
			hint = ds[0].Name // later queues must name the interface the first one actually got
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

// openQueue opens one fd and attaches it to name, returning it as a Device.
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
	copy(ifr[:15], name) // leave room for NUL terminator
	binary.LittleEndian.PutUint16(ifr[16:18], flags)
	if errno := setIff(f, &ifr); errno != 0 {
		f.Close()
		if gso {
			// IFF_VNET_HDR is the only thing this call does differently when gso is on,
			// so the caller gets the chance to retry without it.
			return nil, fmt.Errorf("TUNSETIFF (vnet-hdr): %w: %w", ErrGSOUnsupported, errno)
		}
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	real := strings.TrimRight(string(ifr[:16]), "\x00")

	if gso {
		off := uintptr(tunFCSUM | tunFTSO4 | tunFTSO6)
		if errno := setOffload(f, off); errno != 0 {
			f.Close()
			return nil, fmt.Errorf("TUNSETOFFLOAD (gso): %w: %w", ErrGSOUnsupported, errno)
		}
	}

	d := &Device{f: f, fd: int(f.Fd()), Name: real, gso: gso}
	if gso {
		d.rbuf = make([]byte, vnetHdrLen+65535)
	}
	// Non-blocking, so a read that finds nothing returns EAGAIN instead of sleeping. That is what lets
	// the send path take a whole burst at once: read the first packet, then keep taking whatever is
	// ALREADY waiting until the queue runs dry. Read keeps its blocking contract by waiting on poll(2)
	// when that happens, so no caller has to change.
	if err := syscall.SetNonblock(d.fd, true); err != nil {
		d.Close()
		return nil, fmt.Errorf("making the tun fd non-blocking: %w", err)
	}
	return d, nil
}

// rawRead/rawWrite do blocking TUN I/O with a plain syscall, DELIBERATELY bypassing os.File and Go's
// netpoller. A dependency's package-init can bring the netpoller up before main() opens the TUN, and the
// TUN fd can then inherit a poisoned pollDesc from a transient fd that failed EPOLL_CTL_ADD — os.File
// then returns "not pollable" and kills the data plane on EVERY transport. Same approach as wireguard-go.
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

// rd/wr are the data-path I/O. The production device (Open) has a real fd and uses the raw,
// netpoller-free path above; the test-only FromFile device sets fd<0 and falls back to os.File
// (its socketpair stand-in is pollable and never hits the poisoned-pollDesc problem).
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

// tryRd is rd without the wait: ok is false the moment the fd has nothing, which is how a drain knows
// where the burst ended. The FromFile stand-in has no non-blocking mode, so it reports nothing waiting
// and simply never batches.
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

// waitReadable sleeps until the fd has something, on poll(2) rather than go's netpoller -- the same
// reason rawRead uses a bare syscall. Only reached because the fd is non-blocking.
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

// Read returns one L3 packet into buf. With GSO enabled it serves segments from
// the queue, refilling it by reading and splitting one kernel super-packet.
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

// TryRead is Read without the wait: it serves a segment already split out, or takes a packet already
// waiting on the fd, and reports ok=false the moment there is neither.
//
// It is what lets a sender collect a burst into ONE syscall without ever holding the first packet back
// for a second that may not come. The send path used to get its batches only from the GSO queue, which
// meant it got them only when the kernel coalesced -- MEASURED on two real hosts, that is close to
// never: one super-packet in a ten-second transfer. Asking the fd directly does not care.
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

// serve hands out the next queued segment. A packet that does not fit is DROPPED, not truncated:
// copy() silently shortens, and the carrier would then ship a header claiming a length the body no
// longer has -- a corrupt packet the far end cannot even diagnose. No caller in THIS binary can reach
// it (rbuf is vnetHdrLen+65535 and every caller passes maxDatagram), but Read is exported.
func (d *Device) serve(buf []byte) (int, bool) {
	seg := d.q[0]
	d.q = d.q[1:]
	if len(seg) > len(buf) {
		d.nOversize.Add(1)
		return 0, false
	}
	return copy(buf, seg), true
}

// readGSO reads one virtio super-packet and returns its L3 segments (one element
// for a non-GSO packet). A runt read returns no segments so Read retries.
func (d *Device) readGSO() ([][]byte, error) {
	n, err := d.rd(d.rbuf)
	if err != nil {
		return nil, err
	}
	return d.segsFrom(n), nil
}

// tryReadGSO is readGSO without the wait, for the drain half of a batch.
func (d *Device) tryReadGSO() ([][]byte, bool, error) {
	n, ok, err := d.tryRd(d.rbuf)
	if err != nil || !ok {
		return nil, false, err
	}
	return d.segsFrom(n), true, nil
}

// segsFrom turns one super-packet read of n bytes into its L3 segments: one element for a plain
// packet, and none for a runt so the caller reads again.
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
		// Either a plain packet or a super-packet splitGSO handed back untouched. BOTH still carry the
		// kernel's DEFERRED (virtio partial) checksum when NEEDS_CSUM is set, so both have to be finalized —
		// finalizing only the plain-packet branch leaves every pass-through with the partial sum in the
		// checksum field, which the far end drops: a silent hole in the stream, with nothing logged.
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

// Write hands one L3 packet to the kernel. With GSO the kernel expects a virtio-net header prefix, and a
// zero header means "one complete packet, checksums done". There is no GRO here — the write side never
// coalesces — so with GSO on this pays one allocation and one copy per packet just to prepend that
// header. That is the cost side of the knob, and why the offload is a read-side win, not a symmetric one.
func (d *Device) Write(pkt []byte) (int, error) {
	if !d.gso {
		return d.wr(pkt)
	}
	out := make([]byte, vnetHdrLen+len(pkt))
	copy(out[vnetHdrLen:], pkt)
	n, err := d.wr(out)
	if n -= vnetHdrLen; n < 0 {
		n = 0
	}
	return n, err
}

// oversizeNote renders the oversize-drop count for the GSO report, and renders NOTHING when it is
// zero — which, for every caller in this binary, is always (see nOversize). A count that cannot move
// is not diagnostics; it is a number the operator has to learn to ignore, sitting in the one line
// that is supposed to tell them whether the knob does anything. If it ever does move, it appears.
func oversizeNote(n uint64) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", %d oversize dropped", n)
}

// Close removes the interface (non-persistent).
func (d *Device) Close() error {
	if d.gso && (d.nSuper.Load() > 0 || d.nUnsplit.Load() > 0 || d.nOversize.Load() > 0) {
		// log, not fmt: this is the closing entry of the same series reportGSO writes while the
		// tunnel runs, so it belongs in the journal beside them and not on a stdout nobody reads.
		log.Printf("tun %s: gso final: %d super-packets -> %d segments, %d unsplit%s",
			d.Name, d.nSuper.Load(), d.nSeg.Load(), d.nUnsplit.Load(), oversizeNote(d.nOversize.Load()))
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
