package packet

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type FrontRoute struct {
	Inner   string
	Backend string
	Cert    string
	Key     string
}

type frontTable struct {
	certByName map[string]*tls.Certificate
	backend    map[string]string
}

type Front struct {
	table atomic.Pointer[frontTable]
	ech   []tls.EncryptedClientHelloKey
	gate  chan struct{}
}

const (
	maxFrontHandshakes = 256
	frontHandshakeWait = 15 * time.Second
	frontBackendWait   = 8 * time.Second
)

func buildTable(routes []FrontRoute) (*frontTable, error) {
	if len(routes) == 0 {
		return nil, errors.New("front: no routes")
	}
	t := &frontTable{certByName: map[string]*tls.Certificate{}, backend: map[string]string{}}
	for _, r := range routes {
		cert, err := tls.X509KeyPair([]byte(r.Cert), []byte(r.Key))
		if err != nil {
			return nil, errors.New("front: bad cert/key for " + r.Inner + ": " + err.Error())
		}
		c := cert
		t.certByName[r.Inner] = &c
		t.backend[r.Inner] = r.Backend
	}
	return t, nil
}

func NewFront(routes []FrontRoute, echKeyHex, echConfB64 string) (*Front, *tls.Config, error) {
	t, err := buildTable(routes)
	if err != nil {
		return nil, nil, err
	}
	f := &Front{gate: make(chan struct{}, maxFrontHandshakes)}
	f.table.Store(t)
	if echKeyHex != "" {
		key, err := hex.DecodeString(echKeyHex)
		if err != nil {
			return nil, nil, err
		}
		conf, err := base64.StdEncoding.DecodeString(echConfB64)
		if err != nil {
			return nil, nil, err
		}
		f.ech = []tls.EncryptedClientHelloKey{{Config: conf, PrivateKey: key}}
	}
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		NextProtos:               []string{"http/1.1"},
		EncryptedClientHelloKeys: f.ech,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := f.table.Load().certByName[chi.ServerName]; c != nil {
				return c, nil
			}
			return nil, errors.New("front: no route for " + chi.ServerName)
		},
	}
	return f, cfg, nil
}

func (f *Front) Reload(routes []FrontRoute) error {
	t, err := buildTable(routes)
	if err != nil {
		return err
	}
	f.table.Store(t)
	return nil
}

func (f *Front) Routes() int {
	return len(f.table.Load().backend)
}

func (f *Front) Run(ln net.Listener) {
	var backoff time.Duration
	for {
		raw, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff < time.Second {
				backoff *= 2
			}
			log.Printf("core/front: accept error: %v (backoff %v)", err, backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		select {
		case f.gate <- struct{}{}:
			go f.conn(raw)
		default:
			raw.Close()
		}
	}
}

func (f *Front) conn(raw net.Conn) {
	defer raw.Close()
	done := false
	release := func() {
		if !done {
			done = true
			<-f.gate
		}
	}
	defer release()
	tc, ok := raw.(*tls.Conn)
	if !ok {
		return
	}
	tc.SetDeadline(time.Now().Add(frontHandshakeWait))
	if err := tc.Handshake(); err != nil {
		return
	}
	st := tc.ConnectionState()
	if len(f.ech) > 0 && !st.ECHAccepted {
		return
	}
	name := st.ServerName
	dst, ok := f.table.Load().backend[name]
	if !ok {
		return
	}
	up, err := net.DialTimeout("tcp", dst, frontBackendWait)
	if err != nil {
		log.Printf("core/front: %s -> %s dial failed: %v", name, dst, err)
		return
	}
	release()
	defer up.Close()
	tc.SetDeadline(time.Time{})
	pipe(tc, up)
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
