package dnstun

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	kcp "github.com/xtaci/kcp-go/v5"
)

type WireTransport interface {
	Send(datagram []byte) error
	Recv() ([]byte, error)
	Close() error
}

const (
	kindHandshake = 0x00
	kindData      = 0x01
	kindPing      = 0x02
	kindPong      = 0x03
)

const keepaliveDeadMult = 3

var (
	defaultKeepalive   = 10 * time.Second
	keepaliveDeadFloor = 20 * time.Second
)

type SessionConfig struct {
	PSK       string
	Cipher    string
	MTU       int
	Keepalive time.Duration
}

var peerKey = ClientID{0xD1, 0x5C, 0xA5, 0x5E, 0x55, 0x10, 0x0A, 0x1D}

const kcpMTUDefault = 220

const SessionOverhead = 1 + 12 + 24 + 16 + 3

const KCPOverhead = 24

const MinUsefulMTU = KCPOverhead + 16

const handshakeRetxInterval = 500 * time.Millisecond

var handshakeTimeout = 15 * time.Second

type sessionConn struct {
	*kcp.UDPSession
	qpc *QueuePacketConn
	t   WireTransport

	sealer atomic.Pointer[crypto.Sealer]

	staged []stagedSession

	lastRx    atomic.Int64
	done      chan struct{}
	closeOnce sync.Once
}

type stagedSession struct {
	eInit  [32]byte
	sealer *crypto.Sealer
	resp   []byte
}

const maxStaged = 8

func (sc *sessionConn) Close() error {
	sc.closeOnce.Do(func() {
		close(sc.done)
		if sc.UDPSession != nil {
			_ = sc.UDPSession.Close()
		}
		_ = sc.qpc.Close()
		_ = sc.t.Close()
	})
	return nil
}

func recvFanout(t WireTransport, inCh chan<- []byte, done <-chan struct{}) {
	for {
		d, err := t.Recv()
		if err != nil {
			close(inCh)
			return
		}
		select {
		case inCh <- d:
		case <-done:
			return
		}
	}
}

func (sc *sessionConn) sendPump() {
	out := sc.qpc.OutgoingQueue(peerKey)
	for {
		select {
		case <-sc.done:
			return
		case dg := <-out:
			sealed, err := sc.sealer.Load().Seal(dg, nil)
			if err != nil {
				continue
			}
			_ = sc.t.Send(append([]byte{kindData}, sealed...))
		}
	}
}

func (sc *sessionConn) recvPump(inCh <-chan []byte, onHandshake func([]byte)) {

	liveProven := false
	for {
		select {
		case <-sc.done:
			return
		case d, ok := <-inCh:
			if !ok {

				_ = sc.qpc.Close()
				return
			}
			if len(d) < 1 {
				continue
			}
			switch d[0] {
			case kindData:
				if _, _, pt, err := sc.sealer.Load().Open(d[1:], nil); err == nil {
					liveProven = true
					sc.lastRx.Store(time.Now().UnixNano())
					sc.qpc.QueueIncoming(pt, peerKey)
					continue
				}
				sc.tryStaged(d[1:], true, &liveProven)
			case kindPing:
				if _, _, _, err := sc.sealer.Load().Open(d[1:], nil); err == nil {

					sc.lastRx.Store(time.Now().UnixNano())
					sc.sendKind(kindPong)
					continue
				}

				sc.tryStaged(d[1:], false, &liveProven)
			case kindPong:
				if _, _, _, err := sc.sealer.Load().Open(d[1:], nil); err == nil {
					sc.lastRx.Store(time.Now().UnixNano())
				}
			case kindHandshake:
				if onHandshake != nil {
					onHandshake(d[1:])
				}
			}
		}
	}
}

func (sc *sessionConn) tryStaged(payload []byte, isData bool, liveProven *bool) {
	for i := range sc.staged {
		_, _, pt, perr := sc.staged[i].sealer.Open(payload, nil)
		if perr != nil {
			continue
		}
		switch {
		case *liveProven:
			_ = sc.qpc.Close()
		case isData:
			sc.sealer.Store(sc.staged[i].sealer)
			sc.staged = nil
			*liveProven = true
			sc.lastRx.Store(time.Now().UnixNano())
			sc.qpc.QueueIncoming(pt, peerKey)
		}
		return
	}
}

func (sc *sessionConn) sendKind(kind byte) {
	s := sc.sealer.Load()
	if s == nil {
		return
	}
	sealed, err := s.Seal(nil, nil)
	if err != nil {
		return
	}
	_ = sc.t.Send(append([]byte{kind}, sealed...))
}

func (sc *sessionConn) keepalive(interval, deadWindow time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-sc.done:
			return
		case <-t.C:
			sc.sendKind(kindPing)
			if last := sc.lastRx.Load(); last != 0 && time.Since(time.Unix(0, last)) > deadWindow {
				_ = sc.Close()
				return
			}
		}
	}
}

func resolveKeepalive(interval time.Duration) (time.Duration, time.Duration) {
	if interval <= 0 {
		interval = defaultKeepalive
	}
	return interval, resolveDeadWindow(interval)
}

func resolveDeadWindow(keepalive time.Duration) time.Duration {
	if keepalive <= 0 {
		keepalive = defaultKeepalive
	}
	dw := time.Duration(keepaliveDeadMult) * keepalive
	if dw < keepaliveDeadFloor {
		dw = keepaliveDeadFloor
	}
	return dw
}

func dialFail(done chan struct{}, t WireTransport, err error) (net.Conn, error) {
	close(done)
	_ = t.Close()
	return nil, err
}

func DialSession(t WireTransport, cfg SessionConfig) (net.Conn, error) {
	done := make(chan struct{})
	inCh := make(chan []byte, 256)
	go recvFanout(t, inCh, done)

	ci, err := crypto.GenerateEphemeralNoPad()
	if err != nil {
		return dialFail(done, t, err)
	}
	initDG := append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci)...)
	_ = t.Send(initDG)

	var sealer *crypto.Sealer
	deadline := time.NewTimer(handshakeTimeout)
	defer deadline.Stop()
	retx := time.NewTicker(handshakeRetxInterval)
	defer retx.Stop()
handshake:
	for {
		select {
		case <-deadline.C:
			return dialFail(done, t, errors.New("dns session: handshake timed out"))
		case <-retx.C:
			_ = t.Send(initDG)
		case d, ok := <-inCh:
			if !ok {
				return dialFail(done, t, errors.New("dns session: transport closed during handshake"))
			}
			if len(d) < 1 || d[0] != kindHandshake {
				continue
			}
			eResp, perr := crypto.ParseResp(cfg.PSK, ci.Pub, d[1:])
			if perr != nil {
				continue
			}
			s, serr := crypto.SessionSealer(cfg.Cipher, cfg.PSK, ci, eResp, ci.Pub, eResp, true)
			if serr != nil {
				return dialFail(done, t, serr)
			}
			sealer = s
			break handshake
		}
	}

	qpc := NewQueuePacketConn(peerKey)
	conn, err := kcp.NewConn2(peerKey, nil, 0, 0, qpc)
	if err != nil {
		close(done)
		_ = qpc.Close()
		_ = t.Close()
		return nil, err
	}
	tuneSession(conn, cfg.MTU)
	sc := &sessionConn{UDPSession: conn, qpc: qpc, t: t, done: done}
	sc.sealer.Store(sealer)
	sc.lastRx.Store(time.Now().UnixNano())
	kaInterval, kaDeadWindow := resolveKeepalive(cfg.Keepalive)
	go sc.sendPump()
	go sc.recvPump(inCh, nil)
	go sc.keepalive(kaInterval, kaDeadWindow)
	return sc, nil
}

func ServeSession(t WireTransport, cfg SessionConfig) (net.Conn, error) {
	done := make(chan struct{})
	inCh := make(chan []byte, 256)
	go recvFanout(t, inCh, done)

	var (
		sealer  *crypto.Sealer
		respDG  []byte
		gotInit [32]byte
	)
	for sealer == nil {
		d, ok := <-inCh
		if !ok {
			return dialFail(done, t, errors.New("dns session: transport closed before handshake"))
		}
		if len(d) < 1 || d[0] != kindHandshake {
			continue
		}
		eInit, perr := crypto.ParseInit(cfg.PSK, d[1:])
		if perr != nil {
			continue
		}
		sr, gerr := crypto.GenerateEphemeralNoPad()
		if gerr != nil {
			return dialFail(done, t, gerr)
		}
		s, serr := crypto.SessionSealer(cfg.Cipher, cfg.PSK, sr, eInit, eInit, sr.Pub, false)
		if serr != nil {
			return dialFail(done, t, serr)
		}
		sealer, gotInit = s, eInit
		respDG = append([]byte{kindHandshake}, crypto.RespMsg(cfg.PSK, eInit, sr)...)
		_ = t.Send(respDG)
	}

	qpc := NewQueuePacketConn(peerKey)
	sc := &sessionConn{qpc: qpc, t: t, done: done}
	sc.sealer.Store(sealer)
	sc.lastRx.Store(time.Now().UnixNano())

	onHS := func(hs []byte) {
		e, err := crypto.ParseInit(cfg.PSK, hs)
		if err != nil {
			return
		}
		if e == gotInit {
			_ = t.Send(respDG)
			return
		}
		for i := range sc.staged {
			if sc.staged[i].eInit == e {
				_ = t.Send(sc.staged[i].resp)
				return
			}
		}

		sr, gerr := crypto.GenerateEphemeralNoPad()
		if gerr != nil {
			return
		}
		s, serr := crypto.SessionSealer(cfg.Cipher, cfg.PSK, sr, e, e, sr.Pub, false)
		if serr != nil {
			return
		}
		resp := append([]byte{kindHandshake}, crypto.RespMsg(cfg.PSK, e, sr)...)
		if len(sc.staged) >= maxStaged {
			sc.staged = sc.staged[1:]
		}
		sc.staged = append(sc.staged, stagedSession{eInit: e, sealer: s, resp: resp})
		_ = t.Send(resp)
	}
	go sc.sendPump()
	go sc.recvPump(inCh, onHS)

	lis, err := kcp.ServeConn(nil, 0, 0, qpc)
	if err != nil {
		sc.Close()
		return nil, err
	}
	conn, err := lis.AcceptKCP()
	if err != nil {
		sc.Close()
		return nil, err
	}
	tuneSession(conn, cfg.MTU)
	sc.UDPSession = conn
	return sc, nil
}

func tuneSession(s *kcp.UDPSession, mtu int) {
	if mtu <= 0 {
		mtu = kcpMTUDefault
	}
	s.SetStreamMode(true)
	s.SetNoDelay(0, 100, 0, 1)
	s.SetWindowSize(64, 64)
	s.SetMtu(mtu)
}
