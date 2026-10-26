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
	"time"
)

type FrontRoute struct {
	Inner   string
	Backend string
	Cert    string
	Key     string
}

func FrontTLS(routes []FrontRoute, echKeyHex, echConfB64 string) (*tls.Config, map[string]string, error) {
	if len(routes) == 0 {
		return nil, nil, errors.New("front: no routes")
	}
	certByName := map[string]*tls.Certificate{}
	backend := map[string]string{}
	var first *tls.Certificate
	for _, r := range routes {
		cert, err := tls.X509KeyPair([]byte(r.Cert), []byte(r.Key))
		if err != nil {
			return nil, nil, errors.New("front: bad cert/key for " + r.Inner + ": " + err.Error())
		}
		c := cert
		certByName[r.Inner] = &c
		backend[r.Inner] = r.Backend
		if first == nil {
			first = &c
		}
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := certByName[chi.ServerName]; c != nil {
				return c, nil
			}
			return first, nil
		},
	}
	if echKeyHex != "" {
		key, err := hex.DecodeString(echKeyHex)
		if err != nil {
			return nil, nil, err
		}
		conf, err := base64.StdEncoding.DecodeString(echConfB64)
		if err != nil {
			return nil, nil, err
		}
		cfg.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{
			Config:      conf,
			PrivateKey:  key,
			SendAsRetry: true,
		}}
	}
	return cfg, backend, nil
}

func RunFront(ln net.Listener, backend map[string]string) {
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		go frontConn(raw, backend)
	}
}

func frontConn(raw net.Conn, backend map[string]string) {
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
	dst, ok := backend[name]
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
