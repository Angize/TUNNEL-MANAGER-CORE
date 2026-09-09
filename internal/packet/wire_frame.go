package packet

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	magic byte = 0xB1

	typeData byte = 0
	typePing byte = 1
	typePong byte = 2

	maxDatagram = 65535
)

type Sealer interface {
	Seal(pt, aad []byte) ([]byte, error)
	Frame(lead, innerLen int) (buf, head, inner []byte)
	SealInPlace(buf, inner, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) (session uint64, seq uint64, pt []byte, err error)
}

type sealerBox struct{ s Sealer }

type stagedBox struct {
	box *sealerBox
	rp  replayGuard
}

const maxStaged = 8

func wakeLoop(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func runCmdPoll(closeCh <-chan struct{}, tick func()) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-closeCh:
			return
		case <-t.C:
			tick()
		}
	}
}

func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.TrimSpace(s)
}

func parseIP4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func parseIP4s(ips []string) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		if ip := parseIP4(hostOnly(s)); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func adoptableSource(tag, addr string, warned *sync.Map) net.IP {
	ip := parseIP4(hostOnly(addr))
	if ip != nil && canBindSource(ip) {
		return ip
	}
	if _, dup := warned.LoadOrStore(addr, struct{}{}); !dup {
		if ip == nil {
			log.Printf("core/%s: source %q is not a usable IPv4 address — leaving the kernel to pick the source", tag, addr)
		} else {
			log.Printf("core/%s: source IP %s is not configured on this host — leaving the kernel to pick the source", tag, ip)
		}
	}
	return nil
}
