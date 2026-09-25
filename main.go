package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

var version = "dev"

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

func tuningFrom(t *TuningCfg) packet.TuningInput {
	return packet.TuningInput{
		SuspectBackoff: t.SuspectBackoff,
		DeadRetestSecs: t.DeadRetestSecs,
		LadderRevive:   t.LadderRevive,
	}
}

func main() {
	cfgPath := flag.String("config", "", "path to core JSON config")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		os.Stdout.WriteString(version + "\n")
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
		packet.ApplyTuning(tuningFrom(t))
	}

	packet.SetSockBuf(cfg.SockBuf)
	packet.SetTCPBuf(cfg.TCPBuf)
	packet.SetPortTries(cfg.PortTries)
	packet.SetSportBand(cfg.SportLo, cfg.SportHi)
	if (cfg.SportLo != 0 || cfg.SportHi != 0) && drawsSourcePort(cfg) {
		lo, hi := packet.SportBand()
		log.Printf("tnl-core: source ports are drawn from %d-%d", lo, hi)
	}
	if note := bufNote(cfg.Transport, "sock_buf", "tcp_buf", cfg.SockBuf, sockBufCarrier(cfg.Transport)); note != "" {
		log.Print(note)
	}
	if note := bufNote(cfg.Transport, "tcp_buf", "sock_buf", cfg.TCPBuf, tcpBufCarrier(cfg.Transport)); note != "" {
		log.Print(note)
	}
	if note := workersNote(cfg); note != "" {
		log.Print(note)
	}
	if note := portTriesNote(cfg.Transport, cfg.RawSportRandom, len(cfg.WSEdgeIPs) > 0 && !cfg.WSPortRoll,
		cfg.PortTries); note != "" {
		log.Print(note)
	}

	devs, gsoOn, err := openTUN(tun.OpenN, cfg.TunName, cfg.MTU, cfg.TunAddr, cfg.GSO, cfg.tunQueues())
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
	obfsTag := obfsLabel(cfg.Obfs)
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
			b, err = packet.ListenTCP(la, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Cover, cfg.CoverSNI, devs[1:]...)
			if err == nil {
				log.Printf("tnl-core: listening (core/tcp%s%s) on %v", obfsTag, coverTag(cfg.Cover), la)
			}
		case "client":
			var desc string
			b, desc, err = dialStream(cfg, dev, cryptoOn, true)
			if err == nil {
				log.Printf("tnl-core: %s", desc)
			}
		}
	case "raw":
		switch cfg.Role {
		case "server":
			b, err = packet.ListenRaw(cfg.Listen, dev, cfg.Obfs, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.RawProfile, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto, cfg.RawPort, cfg.RawSport, cfg.RawSportRandom, packet.SportRotation{Every: cfg.RawSportRotate, Dports: cfg.RawDports, Lo: cfg.SportLo, Hi: cfg.SportHi}, devs[1:]...)
			if err == nil {
				log.Printf("tnl-core: listening (core/raw:%s%s%s) on %s", cfg.RawProfile, obfsTag, fecTag, cfg.Listen)
			}
		case "client":
			b, err = packet.DialRaw(cfg.Peer, dev, cfg.Obfs, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.RawProfile, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto, cfg.RawPort, cfg.RawSport, cfg.RawSportRandom, packet.SportRotation{Every: cfg.RawSportRotate, Dports: cfg.RawDports, Lo: cfg.SportLo, Hi: cfg.SportHi}, devs[1:]...)
			if err == nil {
				log.Printf("tnl-core: dialing (core/raw:%s%s%s) %s", cfg.RawProfile, obfsTag, fecTag, cfg.Peer)
			}
		}
	case "ws":
		switch cfg.Role {
		case "server":
			if cfg.cdnIsHTTP() {
				b, err = packet.ListenHTTPC(cfg.Listen, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSPath)
				if err == nil {
					log.Printf("tnl-core: listening (core/http%s) on %s", obfsTag, cfg.Listen)
				}
				break
			}
			b, err = packet.ListenWS(cfg.Listen, dev, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSPath, devs[1:]...)
			if err == nil {
				log.Printf("tnl-core: listening (core/ws%s) on %s", obfsTag, cfg.Listen)
			}
		case "client":
			var desc string
			b, desc, err = dialStream(cfg, dev, cryptoOn, true)
			if err == nil {
				log.Printf("tnl-core: %s", desc)
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
	if cfg.StatusPath != "" {
		if s, ok := b.(interface{ SetStatusPath(string) }); ok {
			s.SetStatusPath(cfg.StatusPath)
			log.Printf("tnl-core: writing status/events to %s", cfg.StatusPath)
		}
	}

	if cfg.Role == "client" {
		setupClient(b, cfg, true)
	}

	if cfg.cdnIsHTTP() && (cfg.HTTPUpWorkers|cfg.HTTPUpBatchKB|cfg.HTTPUpRate) != 0 {
		packet.SetHTTPUpstream(cfg.HTTPUpWorkers, cfg.HTTPUpBatchKB, cfg.HTTPUpRate)
		log.Printf("tnl-core: httpc upstream: workers=%d batch=%dKB rate=%d/s (0 = default)",
			cfg.HTTPUpWorkers, cfg.HTTPUpBatchKB, cfg.HTTPUpRate)
	}
	if cfg.Role == "client" && cfg.cdnIsHTTP() && cfg.HTTPStreams != 0 {
		packet.SetHTTPStreams(cfg.HTTPStreams)
		log.Printf("tnl-core: httpc carrier streams=%d", cfg.HTTPStreams)
	}

	if cfg.Role == "server" && len(cfg.PeerSrcIPs) > 0 {
		if s, ok := b.(interface{ SetPeerSources([]string) }); ok {
			s.SetPeerSources(cfg.PeerSrcIPs)
			log.Printf("tnl-core: pooled server follows client source rotation across %d source IPs", len(cfg.PeerSrcIPs))
		}
	}
	lanes := dialLanes(b, cfg, devs, cryptoOn)
	defer closeLanes(b, lanes)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Print("tnl-core: shutting down")
		closeLanes(b, lanes)
		dev.Close()
		os.Exit(0)
	}()

	runLanes(lanes)
	if err := b.Run(); err != nil {
		log.Printf("tnl-core: stopped: %v", err)
	}
}

func wantsDestPool(cfg *Config) bool {
	return cfg.Role == "client" && len(cfg.PeerIPs) >= 2
}

func wantsSourcePool(cfg *Config) bool {
	return cfg.Role == "client" && len(cfg.SrcIPs) >= 2
}

func obfsLabel(obfs bool) string {
	if obfs {
		return " obfs"
	}
	return ""
}

func coverTag(cover bool) string {
	if cover {
		return " tls"
	}
	return ""
}

const (
	srcNone     = ""
	srcByBind   = "bind"
	srcBySrcIPs = "src_ips"
)

func usesFakeTTL(cfg *Config) bool {
	return !(cfg.Transport == "raw" && cfg.FakeMode == "badsum")
}

func drawsSourcePort(cfg *Config) bool {
	if cfg.Transport == "raw" {
		return packet.RawProfileHasPorts(cfg.RawProfile) && (cfg.RawSportRandom || cfg.RawSportRotate != 0)
	}
	return cfg.Role == "client"
}

func portTriesNote(transport string, sportRandom, edgeNoRoll bool, n int) string {
	if n <= 0 {
		return ""
	}
	if edgeNoRoll {
		return fmt.Sprintf("core: WARNING port_tries=%d is ignored on this ws edge pool because ws_port_roll "+
			"is off: a failed verdict burns the edge at once and no fresh connection is spent first", n)
	}
	if transport != "raw" || sportRandom {
		return ""
	}
	return fmt.Sprintf("core: WARNING port_tries=%d is ignored on raw unless raw_sport_random is on. It "+
		"counts how many source ports one rung may spend, and a raw carrier only draws a source port in "+
		"that mode", n)
}

func workersNote(cfg *Config) string {
	n := cfg.Workers
	if n <= 1 {
		return ""
	}
	if cfg.Fec {
		return fmt.Sprintf("core: WARNING workers=%d is ignored while fec is on. FEC needs one ordered "+
			"stream to rebuild a block from, so the datapath runs a single queue and the extra workers "+
			"are never created", n)
	}
	if !queueingCarrier(cfg.Transport) && !cfg.laneCarrier() {
		return fmt.Sprintf("core: WARNING cdn_carrier %s ignores workers=%d. Parallel lanes are one ws or tcp "+
			"connection each; the http and grpc carriers spread over http_streams instead", cfg.CDNCarrier, n)
	}
	return ""
}

func sockBufCarrier(transport string) bool {
	switch transport {
	case "", "udp", "raw":
		return true
	}
	return false
}

func tcpBufCarrier(transport string) bool { return transport == "tcp" || transport == "ws" }

func bufNote(transport, knob, other string, n int, applies bool) string {
	if n <= 0 || applies {
		return ""
	}
	return fmt.Sprintf("core: WARNING carrier %s ignores %s; its sockets are sized by %s", transport, knob, other)
}

func sourceMode(b any, cfg *Config) string {
	if cfg.Role != "client" || cfg.BindIP == "" {
		return srcNone
	}
	if wantsSourcePool(cfg) {
		return srcBySrcIPs
	}
	b.(interface{ SetSourceIP(string) }).SetSourceIP(cfg.BindIP)
	return srcByBind
}

func applySNISplit(b any, transport, mode string, pos, ttl int, logf func(string, ...any)) {
	if mode == "" {
		mode = "split"
	}
	s, ok := b.(interface {
		SetSNISplit(bool, int, string, int) bool
	})
	if ok && s.SetSNISplit(true, pos, mode, ttl) {
		if mode == "disorder" {
			logf("tnl-core: SNI fragmentation on (mode=%s split_pos=%d ttl=%d)", mode, pos, ttl)
		} else {
			logf("tnl-core: SNI fragmentation on (mode=%s split_pos=%d; split_ttl only applies to disorder)", mode, pos)
		}
		return
	}
	logf("core: WARNING carrier %s ignores sni_split — it sends no TLS ClientHello of its own, so nothing is fragmented", transport)
}
