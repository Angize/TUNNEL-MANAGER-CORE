package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

func dialStream(cfg *Config, dev *tun.Device, cryptoOn, lead bool) (*packet.TCP, string, error) {
	obfsTag := obfsLabel(cfg.Obfs)
	if cfg.Transport == "tcp" {
		b, err := packet.DialTCP(cfg.Peer, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Cover, cfg.CoverSNI)
		return b, fmt.Sprintf("dialing (core/tcp%s%s) %s", obfsTag, coverTag(cfg.Cover), cfg.Peer), err
	}
	carrier := "ws"
	if cfg.cdnIsHTTP() {
		carrier = "http"
	}
	if len(cfg.WSEdgeIPs) > 0 {
		snis := make([]packet.EdgeSNI, len(cfg.WSEdgeSNIs))
		for i, s := range cfg.WSEdgeSNIs {
			snis[i] = packet.EdgeSNI{Host: s.Host, ECH: s.ECH, Path: s.Path}
		}
		rotate := time.Duration(cfg.WSRotateSecs) * time.Second
		if !lead {
			rotate = 0
		}
		b, err := packet.DialEdgePool(dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher,
			cfg.WSEdgeIPs, snis, rotate, cfg.cdnIsHTTP(), cfg.cdnMode(), cfg.WSPortRoll)
		return b, fmt.Sprintf("dialing (core/%s%s wss ech pool: %dIP×%dSNI rotate=%ds port_roll=%t)",
			carrier, obfsTag, len(cfg.WSEdgeIPs), len(cfg.WSEdgeSNIs), cfg.WSRotateSecs, cfg.WSPortRoll), err
	}
	var echList []byte
	if cfg.WSECH != "" {
		echList, _ = base64.StdEncoding.DecodeString(cfg.WSECH)
	}
	if cfg.cdnIsHTTP() {
		b, err := packet.DialHTTPC(cfg.Peer, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSHost, cfg.WSPath, cfg.WSTLS, echList, cfg.cdnMode())
		mode := cfg.cdnMode()
		if mode == "" {
			mode = "post"
		}
		return b, fmt.Sprintf("dialing (core/http:%s%s wss) %s", mode, obfsTag, cfg.Peer), err
	}
	b, err := packet.DialWS(cfg.Peer, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSHost, cfg.WSPath, cfg.WSTLS, echList)
	tlsTag := ""
	if cfg.WSTLS {
		tlsTag = " wss"
	}
	if len(echList) > 0 {
		tlsTag += " ech"
	}
	return b, fmt.Sprintf("dialing (core/ws%s%s) %s", obfsTag, tlsTag, cfg.Peer), err
}

func setupClient(b any, cfg *Config, lead bool) {
	logf := log.Printf
	if !lead {
		logf = func(string, ...any) {}
	}
	if sourceMode(b, cfg) == srcByBind {
		logf("tnl-core: binding outbound source IP to %s", cfg.BindIP)
	}
	if cfg.FakeDesync {
		if s, ok := b.(interface {
			SetDesync(bool, int, int, string)
		}); ok {
			s.SetDesync(true, cfg.FakeTTL, cfg.FakeCount, cfg.FakeMode)
			if usesFakeTTL(cfg) {
				logf("tnl-core: fake-desync on (%d decoys, ttl=%d, mode=%s)", cfg.FakeCount, cfg.FakeTTL, cfg.FakeMode)
			} else {
				logf("tnl-core: fake-desync on (%d decoys, mode=%s) — every decoy on this carrier is a bad-checksum packet sent at TTL 64, so fake_ttl is not read", cfg.FakeCount, cfg.FakeMode)
			}
		}
	}
	if cfg.SNISplit {
		applySNISplit(b, cfg.Transport, cfg.SNIMode, cfg.SplitPos, cfg.SplitTTL, logf)
	}
	rotate := time.Duration(cfg.PeerRotateSecs) * time.Second
	if !lead {
		rotate = 0
	}
	if wantsDestPool(cfg) {
		if s, ok := b.(interface{ SetPeerPool(*packet.PeerPool) }); ok {
			s.SetPeerPool(packet.NewPeerPool(cfg.PeerIPs, rotate))
			logf("tnl-core: destination pool: %d peers rotate=%ds", len(cfg.PeerIPs), cfg.PeerRotateSecs)
		}
	}
	if wantsSourcePool(cfg) {
		if s, ok := b.(interface{ SetSourcePool(*packet.PeerPool) }); ok {
			s.SetSourcePool(packet.NewPeerPool(cfg.SrcIPs, rotate))
			logf("tnl-core: source pool: %d source IPs rotate=%ds", len(cfg.SrcIPs), cfg.PeerRotateSecs)
		}
	}
}

func dialLanes(lead any, cfg *Config, devs []*tun.Device, cryptoOn bool) []*packet.TCP {
	if cfg.Role != "client" || !cfg.laneCarrier() || len(devs) < 2 {
		return nil
	}
	head := lead.(*packet.TCP)
	lanes := make([]*packet.TCP, 0, len(devs)-1)
	for i, d := range devs[1:] {
		b, _, err := dialStream(cfg, d, cryptoOn, false)
		if err != nil {
			log.Fatalf("tnl-core: lane %d: %v", i+1, err)
		}
		setupClient(b, cfg, false)
		b.Follow(head, i+1)
		lanes = append(lanes, b)
	}
	log.Printf("tnl-core: %d parallel lanes, one connection each; lanes 1-%d follow lane 0's path", len(devs), len(devs)-1)
	return lanes
}

func runLanes(lanes []*packet.TCP) {
	for i, l := range lanes {
		go func() {
			if err := l.Run(); err != nil {
				log.Printf("tnl-core: lane %d stopped: %v", i+1, err)
			}
		}()
	}
}

func closeLanes(lead interface{ Close() error }, lanes []*packet.TCP) {
	for _, l := range lanes {
		l.Close()
	}
	lead.Close()
}
