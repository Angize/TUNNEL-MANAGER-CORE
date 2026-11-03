package packet

import (
	"bytes"
	"log"
	"net"
	"sync"
	"time"
)

const (
	sniDisorderMode = "disorder"

	sniFakeMode = "fake"
)

const fragGap = 1 * time.Millisecond

type fragConn struct {
	net.Conn
	host        string
	ech         bool
	pos         int
	mode        string
	ttl         int
	mu          sync.Mutex
	sent        bool
	warn        sync.Once
	warnFake    sync.Once
	warnNoSplit sync.Once
	warnPos     sync.Once

	dsSend *desyncSend
}

func (f *fragConn) noSplit() {
	f.warnNoSplit.Do(func() {
		switch {
		case f.host == "":
			log.Printf("core/tls: sni_split is on but this carrier dials with no SNI — nothing was fragmented")
		case f.ech:
			log.Printf("core/tls: sni_split is on but the hostname is not in the ClientHello in cleartext " +
				"(ECH encrypts it) — nothing was fragmented, and nothing needs to be: there is no cleartext " +
				"SNI left for a DPI to read")
		default:
			log.Printf("core/tls: sni_split is on but the hostname %q was not found in the ClientHello, and "+
				"ECH is NOT on — so this is not the harmless ECH case. Nothing was fragmented and the SNI "+
				"the client really sent is on the wire in cleartext; check that ws_host matches the SNI "+
				"this carrier dials with", f.host)
		}
	})
}

func newFragConn(c net.Conn, host string, pos int, mode string, ttl int, ech bool, ds *desyncSend) *fragConn {
	return &fragConn{Conn: c, host: host, pos: pos, mode: mode, ttl: ttl, ech: ech, dsSend: ds}
}

func (f *fragConn) Write(p []byte) (int, error) {
	f.mu.Lock()
	first := !f.sent
	f.sent = true
	f.mu.Unlock()
	if !first {
		return f.Conn.Write(p)
	}
	at := f.splitAt(p)
	if at <= 0 || at >= len(p) {
		f.noSplit()
		return f.Conn.Write(p)
	}
	switch f.mode {
	case sniDisorderMode:
		return f.writeDisorder(p, at)
	case sniFakeMode:
		return f.writeFake(p, at)
	}
	return f.writeSplit(p, at)
}

func (f *fragConn) writeSplit(p []byte, at int) (int, error) {
	n1, err := f.Conn.Write(p[:at])
	if err != nil {
		return n1, err
	}
	time.Sleep(fragGap)
	n2, err := f.Conn.Write(p[at:])
	return n1 + n2, err
}

func (f *fragConn) splitAt(p []byte) int {
	if f.pos > 0 {
		if f.pos < len(p) {
			return f.pos
		}
		f.warnPos.Do(func() {
			log.Printf("core/tls: split_pos=%d is past the end of this %d-byte ClientHello — "+
				"using the automatic point inside the hostname instead", f.pos, len(p))
		})
	}
	if f.host == "" {
		return 0
	}
	i := bytes.Index(p, []byte(f.host))
	if i < 0 {
		return 0
	}
	return i + len(f.host)/2
}
