package packet

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"net"
)

func serverListen(addr string, tlsCfg *tls.Config) (net.Listener, error) {
	if tlsCfg == nil {
		return listenTCP(addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(ln, tlsCfg), nil
}

func ServerTLS(certPEM, keyPEM, echKeyHex, echConfB64 string) (*tls.Config, error) {
	if certPEM == "" {
		return nil, nil
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}
	if echKeyHex != "" {
		key, err := hex.DecodeString(echKeyHex)
		if err != nil {
			return nil, err
		}
		conf, err := base64.StdEncoding.DecodeString(echConfB64)
		if err != nil {
			return nil, err
		}
		cfg.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{
			Config:      conf,
			PrivateKey:  key,
			SendAsRetry: true,
		}}
	}
	return cfg, nil
}
