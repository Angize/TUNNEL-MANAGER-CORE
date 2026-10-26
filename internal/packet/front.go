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
	first      *tls.Certificate
}

type Front struct {
	table atomic.Pointer[frontTable]
	ech   []tls.EncryptedClientHelloKey
}

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
		if t.first == nil {
			t.first = &c
		}
	}
	return t, nil
}

func NewFront(routes []FrontRoute, echKeyHex, echConfB64 string) (*Front, *tls.Config, error) {
	t, err := buildTable(routes)
	if err != nil {
		return nil, nil, err
	}
	f := &Front{}
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
		f.ech = []tls.EncryptedClientHelloKey{{Config: conf, PrivateKey: key, SendAsRetry: true}}
	}
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		NextProtos:               []string{"http/1.1"},
		EncryptedClientHelloKeys: f.ech,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			tb := f.table.Load()
			if c := tb.certByName[chi.ServerName]; c != nil {
				return c, nil
			}
			return tb.first, nil
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
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		go f.conn(raw)
	}
}

func (f *Front) conn(raw net.Conn) {
	defer raw.Close()
	tc, ok := raw.(*tls.Conn)
	if !ok {
		return
	}
	tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	name := tc.ConnectionState().ServerName
	dst, ok := f.table.Load().backend[name]
	if !ok {
		return
	}
	up, err := net.DialTimeout("tcp", dst, 8*time.Second)
	if err != nil {
		log.Printf("core/front: %s -> %s dial failed: %v", name, dst, err)
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
		} else {
			dst.SetDeadline(time.Now())
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
