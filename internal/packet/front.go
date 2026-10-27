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

type frontRoute struct {
	cert    tls.Certificate
	backend string
}

type Front struct {
	routes atomic.Pointer[map[string]*frontRoute]
	tls    *tls.Config
	gate   chan struct{}
}

const (
	maxFrontHandshakes = 256
	frontBackendWait   = 8 * time.Second
)

func buildRoutes(routes []FrontRoute) (map[string]*frontRoute, error) {
	if len(routes) == 0 {
		return nil, errors.New("front: no routes")
	}
	m := make(map[string]*frontRoute, len(routes))
	for _, r := range routes {
		cert, err := tls.X509KeyPair([]byte(r.Cert), []byte(r.Key))
		if err != nil {
			return nil, errors.New("front: bad cert/key for " + r.Inner + ": " + err.Error())
		}
		m[r.Inner] = &frontRoute{cert: cert, backend: r.Backend}
	}
	return m, nil
}

func NewFront(routes []FrontRoute, echKeyHex, echConfB64 string) (*Front, error) {
	m, err := buildRoutes(routes)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(echKeyHex)
	if err != nil {
		return nil, err
	}
	conf, err := base64.StdEncoding.DecodeString(echConfB64)
	if err != nil {
		return nil, err
	}
	f := &Front{gate: make(chan struct{}, maxFrontHandshakes)}
	f.routes.Store(&m)
	f.tls = &tls.Config{
		MinVersion:               tls.VersionTLS13,
		NextProtos:               []string{"http/1.1"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: conf, PrivateKey: key}},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if r := f.route(chi.ServerName); r != nil {
				return &r.cert, nil
			}
			return nil, errors.New("front: no route for " + chi.ServerName)
		},
	}
	return f, nil
}

func (f *Front) route(name string) *frontRoute {
	return (*f.routes.Load())[name]
}

func (f *Front) Reload(routes []FrontRoute) error {
	m, err := buildRoutes(routes)
	if err != nil {
		return err
	}
	f.routes.Store(&m)
	return nil
}

func (f *Front) Routes() int {
	return len(*f.routes.Load())
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
	tc := tls.Server(raw, f.tls)
	tc.SetDeadline(time.Now().Add(handshakeTimeout))
	err := tc.Handshake()
	<-f.gate
	if err != nil {
		return
	}
	st := tc.ConnectionState()
	r := f.route(st.ServerName)
	if !st.ECHAccepted || r == nil {
		return
	}
	up, err := net.DialTimeout("tcp", r.backend, frontBackendWait)
	if err != nil {
		log.Printf("core/front: %s -> %s dial failed: %v", st.ServerName, r.backend, err)
		return
	}
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
