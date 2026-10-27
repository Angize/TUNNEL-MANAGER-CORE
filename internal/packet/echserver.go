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
		k, err := echKey(echKeyHex, echConfB64)
		if err != nil {
			return nil, err
		}
		k.SendAsRetry = true
		cfg.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{k}
	}
	return cfg, nil
}

func echKey(keyHex, confB64 string) (tls.EncryptedClientHelloKey, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	conf, err := base64.StdEncoding.DecodeString(confB64)
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	return tls.EncryptedClientHelloKey{Config: conf, PrivateKey: key}, nil
}
