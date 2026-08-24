package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

const version = "0.1.0-core"

type tunOpener func(name string, mtu int, addr string, gso bool, n int) ([]*tun.Device, error)

func openTUN(open tunOpener, name string, mtu int, addr string, gso bool, n int) ([]*tun.Device, bool, error) {
	devs, err := open(name, mtu, addr, gso, n)
	if err == nil {
		return devs, gso, nil
	}
	if !errors.Is(err, tun.ErrGSOUnsupported) {
		return nil, false, err
	}
	plain, plainErr := open(name, mtu, addr, false, n)
	if plainErr != nil {
		return nil, false, plainErr
	}
	log.Printf("tnl-core: tun: gso is not available here (%v) — continuing without it", err)
	return plain, false, nil
}

func main() {
	cfgPath := flag.String("config", "", "path to core JSON config")
	showVer := flag.Bool("version", false, "print version and exit")
	probeSpoof := flag.Bool("probe-spoof", false, "print IP-spoofing capability (JSON) and exit")
	flag.Parse()

	if *showVer {
		os.Stdout.WriteString(version + "\n")
		return
	}
	if *probeSpoof {
		b, _ := json.Marshal(packet.ProbeSpoof())
		os.Stdout.Write(append(b, '\n'))
		return
	}
	if *cfgPath == "" {
		log.Fatal("tnl-core: --config is required")
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("tnl-core: config: %v", err)
	}

	if t := cfg.Tuning; t != nil {
		packet.ApplyTuning(packet.TuningInput{
			SuspectBackoff: t.SuspectBackoff, DeadRetestSecs: t.DeadRetestSecs,
			MinLivenessSecs: t.MinLivenessSecs,
		})
	}

	packet.SetSockBuf(cfg.SockBuf)

	nq := 1
	if !cfg.Fec && queueingCarrier(cfg.Transport) {
		nq = cfg.Workers
	}
	devs, gsoOn, err := openTUN(tun.OpenN, cfg.TunName, cfg.MTU, cfg.TunAddr, cfg.GSO, nq)
	if err != nil {
		log.Fatalf("tnl-core: tun: %v", err)
	}
	dev := devs[0]
	defer func() {
		for _, d := range devs {
			d.Close()
		}
	}()

	cipherName := "off"
	if cfg.Crypto.Enabled {

		s, err := crypto.NewSealer(cfg.Crypto.Cipher, cfg.Crypto.PSK, cfg.Role == "client")
		if err != nil {
			log.Fatalf("tnl-core: crypto: %v", err)
		}
		cipherName = s.Name
	} else {
		if cfg.Obfs {
			log.Fatalf("tnl-core: obfs requires crypto (there is no key to obfuscate with) — enable crypto or disable obfs")
		}

		log.Printf("tnl-core: WARNING crypto is DISABLED — the tunnel is unauthenticated " +
			"and unencrypted; anyone who can send a packet to this listener can hijack or " +
			"inject into it. Enable crypto unless this is a trusted, isolated link.")
	}
	gsoTag := ""
	if gsoOn {
		gsoTag = " gso"
	}
	log.Printf("tnl-core %s: tun=%s addr=%s mtu=%d cipher=%s role=%s%s",
		version, dev.Name, cfg.TunAddr, cfg.MTU, cipherName, cfg.Role, gsoTag)

	type carrier interface {
		Run() error
		Close() error
	}
	var b carrier
	obfsTag := ""
	if cfg.Obfs {
		obfsTag = " obfs"
	}
	fecTag := ""
	if cfg.Fec {
		fecTag = fmt.Sprintf(" fec=%d+%d", cfg.FecData, cfg.FecParity)
	}
	cryptoOn := cfg.Crypto.Enabled
	switch cfg.Transport {
	case "tcp":
		switch cfg.Role {
		case "server":
			la := cfg.ListenIPs
			if len(la) == 0 {
				la = []string{cfg.Listen}
			}
			b, err = packet.ListenTCP(la, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Cover, cfg.CoverSNI)
			if err == nil {
				log.Printf("tnl-core: listening (core/tcp%s%s) on %v", obfsTag, coverTag(cfg.Cover), la)
			}
		case "client":
			b, err = packet.DialTCP(cfg.Peer, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Cover, cfg.CoverSNI)
			if err == nil {
				log.Printf("tnl-core: dialing (core/tcp%s%s) %s", obfsTag, coverTag(cfg.Cover), cfg.Peer)
			}
		}
	case "raw":
		switch cfg.Role {
		case "server":
			b, err = packet.ListenRaw(cfg.Listen, dev, cfg.Obfs, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.RawProfile, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto, cfg.RawPort, cfg.RawSport, cfg.RawSportRandom, devs[1:]...)
			if err == nil {
				log.Printf("tnl-core: listening (core/raw:%s%s%s) on %s", cfg.RawProfile, obfsTag, fecTag, cfg.Listen)
			}
		case "client":
			b, err = packet.DialRaw(cfg.Peer, dev, cfg.Obfs, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.RawProfile, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto, cfg.RawPort, cfg.RawSport, cfg.RawSportRandom, devs[1:]...)
			if err == nil {
				log.Printf("tnl-core: dialing (core/raw:%s%s%s) %s", cfg.RawProfile, obfsTag, fecTag, cfg.Peer)
			}
		}
	case "spoof":
		spoofTag := spoofLogTag(cfg)
		switch cfg.Role {
		case "server":
			b, err = packet.ListenSpoof(cfg.Listen, dev, cfg.Obfs, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.RealPeer, cfg.SpoofDst, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto)
			if err == nil {
				log.Printf("tnl-core: listening (core/spoof:%s%s%s) on %s", spoofTag, obfsTag, fecTag, cfg.Listen)
			}
		case "client":
			b, err = packet.DialSpoof(cfg.Peer, dev, cfg.Obfs, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.SpoofSrc, cfg.SpoofDst, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto)
			if err == nil {
				log.Printf("tnl-core: dialing (core/spoof:%s%s%s) %s", spoofTag, obfsTag, fecTag, cfg.Peer)
			}
		}
	case "flux":
		rotate := time.Duration(cfg.FluxRotateSecs) * time.Second
		switch cfg.Role {
		case "server":
			b, err = packet.ListenFlux(cfg.Listen, dev, rotate, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.FluxCarrier, cfg.FluxShape, cfg.FluxEpochOffset, cfg.Fec, cfg.FecData, cfg.FecParity)
			if err == nil {
				log.Printf("tnl-core: listening (core/flux:%s/%s rotate=%ds%s%s)", cfg.FluxCarrier, cfg.FluxShape, cfg.FluxRotateSecs, obfsTag, fecTag)
			}
		case "client":
			b, err = packet.DialFlux(cfg.Peer, dev, rotate, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.FluxCarrier, cfg.FluxShape, cfg.FluxEpochOffset, cfg.Fec, cfg.FecData, cfg.FecParity)
			if err == nil {
				log.Printf("tnl-core: dialing (core/flux:%s/%s rotate=%ds%s%s) %s", cfg.FluxCarrier, cfg.FluxShape, cfg.FluxRotateSecs, obfsTag, fecTag, cfg.Peer)
			}
		}
	case "ws":
		switch cfg.Role {
		case "server":
			if cfg.cdnIsHTTP() {
				b, err = packet.ListenHTTPC(cfg.Listen, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher)
				if err == nil {
					log.Printf("tnl-core: listening (core/http%s) on %s", obfsTag, cfg.Listen)
				}
				break
			}
			b, err = packet.ListenWS(cfg.Listen, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSPath)
			if err == nil {
				log.Printf("tnl-core: listening (core/ws%s) on %s", obfsTag, cfg.Listen)
			}
		case "client":
			carrier := "ws"
			if cfg.cdnIsHTTP() {
				carrier = "http"
			}
			if len(cfg.WSEdgeIPs) > 0 {
				snis := make([]packet.WSPoolSNI, len(cfg.WSEdgeSNIs))
				for i, s := range cfg.WSEdgeSNIs {
					snis[i] = packet.WSPoolSNI{Host: s.Host, ECH: s.ECH, Path: s.Path}
				}
				b, err = packet.DialWSPoolCfg(dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher,
					cfg.WSEdgeIPs, snis, time.Duration(cfg.WSRotateSecs)*time.Second, cfg.cdnIsHTTP(), cfg.cdnMode())
				if err == nil {
					log.Printf("tnl-core: dialing (core/%s%s wss ech pool: %dIP×%dSNI rotate=%ds)",
						carrier, obfsTag, len(cfg.WSEdgeIPs), len(cfg.WSEdgeSNIs), cfg.WSRotateSecs)
				}
				break
			}
			var echList []byte
			if cfg.WSECH != "" {
				echList, _ = base64.StdEncoding.DecodeString(cfg.WSECH)
			}
			if cfg.cdnIsHTTP() {
				b, err = packet.DialHTTPC(cfg.Peer, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSHost, cfg.WSPath, cfg.WSTLS, echList, cfg.cdnMode())
				if err == nil {
					mode := cfg.cdnMode()
					if mode == "" {
						mode = "post"
					}
					log.Printf("tnl-core: dialing (core/http:%s%s wss) %s", mode, obfsTag, cfg.Peer)
				}
				break
			}
			b, err = packet.DialWS(cfg.Peer, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSHost, cfg.WSPath, cfg.WSTLS, echList)
			if err == nil {
				tlsTag := ""
				if cfg.WSTLS {
					tlsTag = " wss"
				}
				if len(echList) > 0 {
					tlsTag += " ech"
				}
				log.Printf("tnl-core: dialing (core/ws%s%s) %s", obfsTag, tlsTag, cfg.Peer)
			}
		}
	case "dns":
		switch cfg.Role {
		case "server":
			b, err = packet.ListenDNS(dev, cfg.Listen, cfg.DNSZone, cfg.Crypto.PSK, cfg.Crypto.Cipher)
			if err == nil {
				log.Printf("tnl-core: listening (core/dns zone=%s) on %s", cfg.DNSZone, cfg.Listen)
			}
		case "client":
			b, err = packet.DialDNS(dev, cfg.DNSResolvers, cfg.DNSZone, cfg.Crypto.PSK, cfg.Crypto.Cipher)
			if err == nil {
				log.Printf("tnl-core: dialing (core/dns zone=%s via resolvers %s)", cfg.DNSZone, strings.Join(cfg.DNSResolvers, ", "))
			}
		}
	default:
		switch cfg.Role {
		case "server":
			la := cfg.ListenIPs
			if len(la) == 0 {
				la = []string{cfg.Listen}
			}
			b, err = packet.Listen(la, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Fec, cfg.FecData, cfg.FecParity, devs[1:]...)
			if err == nil {
				log.Printf("tnl-core: listening (core/udp%s%s) on %v", obfsTag, fecTag, la)
			}
		case "client":
			b, err = packet.Dial(cfg.Peer, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Fec, cfg.FecData, cfg.FecParity, devs[1:]...)
			if err == nil {
				log.Printf("tnl-core: dialing (core/udp%s%s) %s", obfsTag, fecTag, cfg.Peer)
			}
		}
	}
	if err != nil {
		log.Fatalf("tnl-core: transport: %v", err)
	}
	switch pinSource(b, cfg) {
	case pinByBind:
		log.Printf("tnl-core: binding outbound source IP to %s", cfg.BindIP)
	case pinByPool:
		log.Printf("tnl-core: binding outbound source IP to %s (pinned as a one-entry source pool — %s has no separate bind)", cfg.BindIP, cfg.Transport)
	case pinUnsupported:
		log.Printf("core: WARNING carrier %s ignores bind_ip — it can pin neither a source IP nor a source pool, so this tunnel egresses from whatever source the kernel routes it out of", cfg.Transport)
	}

	if cfg.StatusPath != "" {
		if s, ok := b.(interface{ SetStatusPath(string) }); ok {
			s.SetStatusPath(cfg.StatusPath)
			log.Printf("tnl-core: writing status/events to %s", cfg.StatusPath)
		}
	}

	if cfg.Role == "client" && cfg.FakeDesync {
		if s, ok := b.(interface {
			SetDesync(bool, int, int, string)
		}); ok {
			s.SetDesync(true, cfg.FakeTTL, cfg.FakeCount, cfg.FakeMode)
			log.Printf("tnl-core: fake-desync on (%d decoys, ttl=%d, mode=%s)", cfg.FakeCount, cfg.FakeTTL, cfg.FakeMode)
		}
	}

	if cfg.Role == "client" && cfg.cdnIsHTTP() && (cfg.HTTPUpWorkers|cfg.HTTPUpBatchKB|cfg.HTTPUpRate) != 0 {
		packet.SetHTTPUpstream(cfg.HTTPUpWorkers, cfg.HTTPUpBatchKB, cfg.HTTPUpRate)
		log.Printf("tnl-core: httpc upstream: workers=%d batch=%dKB rate=%d/s (0 = default)",
			cfg.HTTPUpWorkers, cfg.HTTPUpBatchKB, cfg.HTTPUpRate)
	}
	if cfg.Role == "client" && cfg.cdnIsHTTP() && cfg.HTTPStreams != 0 {
		packet.SetHTTPStreams(cfg.HTTPStreams)
		log.Printf("tnl-core: httpc carrier streams=%d", cfg.HTTPStreams)
	}

	if cfg.Role == "client" && cfg.SNISplit {
		applySNISplit(b, cfg.Transport, cfg.SNIMode, cfg.SplitPos, cfg.SplitTTL)
	}

	if wantsDestPool(cfg) {
		if s, ok := b.(interface{ SetPeerPool(*packet.PeerPool) }); ok {
			pp := packet.NewPeerPool(cfg.PeerIPs, time.Duration(cfg.PeerRotateSecs)*time.Second)
			s.SetPeerPool(pp)
			log.Printf("tnl-core: destination pool: %d peers rotate=%ds", len(cfg.PeerIPs), cfg.PeerRotateSecs)
		}
	}

	if wantsSourcePool(cfg) {
		if s, ok := b.(interface{ SetSourcePool(*packet.PeerPool) }); ok {
			sp := packet.NewPeerPool(cfg.SrcIPs, time.Duration(cfg.PeerRotateSecs)*time.Second)
			s.SetSourcePool(sp)
			log.Printf("tnl-core: source pool: %d source IPs rotate=%ds", len(cfg.SrcIPs), cfg.PeerRotateSecs)
		}
	}

	if cfg.Role == "server" && len(cfg.PeerSrcIPs) > 0 {
		if s, ok := b.(interface{ SetPeerSources([]string) }); ok {
			s.SetPeerSources(cfg.PeerSrcIPs)
			log.Printf("tnl-core: pooled server follows client source rotation across %d source IPs", len(cfg.PeerSrcIPs))
		}
	}
	defer b.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Print("tnl-core: shutting down")
		b.Close()
		dev.Close()
		os.Exit(0)
	}()

	if err := b.Run(); err != nil {
		log.Printf("tnl-core: stopped: %v", err)
	}
}

func wantsDestPool(cfg *Config) bool {
	return cfg.Role == "client" && len(cfg.PeerIPs) >= 2
}

func wantsSourcePool(cfg *Config) bool {
	return cfg.Role == "client" && len(cfg.SrcIPs) >= 1
}

func coverTag(cover bool) string {
	if cover {
		return " tls"
	}
	return ""
}

const (
	pinNone        = ""
	pinByBind      = "bind"
	pinByPool      = "pool"
	pinBySrcIPs    = "src_ips"
	pinBySpoof     = "spoof_src"
	pinUnsupported = "unsupported"
)

func pinSource(b any, cfg *Config) string {
	if cfg.Role != "client" || cfg.BindIP == "" {
		return pinNone
	}
	switch s := b.(type) {
	case interface{ SetSourceIP(string) }:
		s.SetSourceIP(cfg.BindIP)
		return pinByBind
	case interface{ SetSourcePool(*packet.PeerPool) }:
		if len(cfg.SrcIPs) > 0 {
			return pinBySrcIPs
		}
		if cfg.SpoofSrc != "" {

			return pinBySpoof
		}

		s.SetSourcePool(packet.NewPeerPool([]string{cfg.BindIP}, 0))
		return pinByPool
	}
	return pinUnsupported
}

func applySNISplit(b any, transport, mode string, pos, ttl int) bool {
	if mode == "" {
		mode = "split"
	}
	s, ok := b.(interface {
		SetSNISplit(bool, int, string, int) bool
	})
	if ok && s.SetSNISplit(true, pos, mode, ttl) {

		if mode == "disorder" {
			log.Printf("tnl-core: SNI fragmentation on (mode=%s split_pos=%d ttl=%d)", mode, pos, ttl)
		} else {
			log.Printf("tnl-core: SNI fragmentation on (mode=%s split_pos=%d; split_ttl does not apply to this mode)", mode, pos)
		}
		return true
	}
	log.Printf("core: WARNING carrier %s ignores sni_split — it sends no TLS ClientHello of its own, so nothing is fragmented", transport)
	return false
}

func spoofLogTag(cfg *Config) string {
	switch {
	case cfg.SpoofSrc != "" && cfg.SpoofDst != "":
		return "src+dst"
	case cfg.SpoofDst != "":
		return "dst"
	case cfg.SpoofSrc != "":
		return "src"
	default:
		return "src"
	}
}
