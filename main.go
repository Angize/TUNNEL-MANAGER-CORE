// Command tnl-core is the custom data-plane core for the tunnel fleet
// manager. It carries raw L3 packets over a TUN device across a selectable
// transport (udp/tcp/raw/flux/ws/http) with optional configurable crypto.
//
// Usage:
//
//	tnl-core --config /run/tnl/core-<id>.json
//
// The node agent owns the config file; the core just runs what it is told.
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

// version is stamped into logs so the panel can tell which core a node runs.
const version = "0.1.0-core"

// tunOpener is tun.Open. It exists so openTUN's fallback can be tested without a
// TUN device, a kernel that lacks IFF_VNET_HDR, or root.
type tunOpener func(name string, mtu int, addr string, gso bool) (*tun.Device, error)

// openTUN opens the TUN and returns the gso setting the device ACTUALLY got.
//
// GSO is a throughput knob and the panel describes it as one ("اگر پشتیبانی نشود
// بی‌اثر است"). It was not: on a kernel or container without IFF_VNET_HDR the
// gso-specific ioctl failed, main called log.Fatalf, systemd restarted the unit and
// the tunnel never came up at all — the whole link dead because a speed knob was on,
// with nothing on the dashboard saying why.
//
// A gso-specific failure is now retried ONCE without gso. The retry is also what
// makes the log honest: ErrGSOUnsupported cannot tell "no vnet-hdr here" from "no
// CAP_NET_ADMIN" (same ioctl, and the errno does not distinguish them), so the
// message is only written when the plain open actually succeeded. If it fails too,
// gso was never the problem and the error reported is the SECOND one — the real cause.
func openTUN(open tunOpener, name string, mtu int, addr string, gso bool) (*tun.Device, bool, error) {
	dev, err := open(name, mtu, addr, gso)
	if err == nil {
		return dev, gso, nil
	}
	if !errors.Is(err, tun.ErrGSOUnsupported) {
		return nil, false, err
	}
	plain, plainErr := open(name, mtu, addr, false)
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

	// Apply any operator-tuned operational timing BEFORE building carriers/pools (they read these
	// package vars at construction). One process = one tunnel, so this is safe process-global state.
	if t := cfg.Tuning; t != nil {
		packet.ApplyTuning(packet.TuningInput{
			SuspectBackoff: t.SuspectBackoff, DeadRetestSecs: t.DeadRetestSecs, PinTTLSecs: t.PinTTLSecs,
			DataFailThreshold: t.DataFailThreshold, DataGoodWindowSecs: t.DataGoodWindowSecs,
			IdleMult: t.IdleMult, IdleMinSecs: t.IdleMinSecs,
			SessionStaleMult: t.SessionStaleMult, SessionStaleMinSecs: t.SessionStaleMinSecs,
			PingLossThreshold: t.PingLossThreshold, MinLivenessSecs: t.MinLivenessSecs,
			ProbeTimeoutSecs: t.ProbeTimeoutSecs,
		})
	}
	// Pin the datagram-carrier socket buffers (udp/raw/flux) BEFORE any socket is opened. cfg.SockBuf is
	// resolved by applyDefaults (4 MiB default; negative = leave the kernel default).
	packet.SetSockBuf(cfg.SockBuf)

	// Open the TUN device BEFORE building the sealer. The sealer's constructor may
	// draw from crypto/rand; on hosts without getrandom(2) that opens /dev/urandom
	// and registers it with the runtime netpoller, which can leave a subsequently
	// opened TUN fd in a half-pollable state (reads fail with "not pollable" and
	// the reader loop dies). Setting up the TUN first avoids that ordering hazard.
	dev, gsoOn, err := openTUN(tun.Open, cfg.TunName, cfg.MTU, cfg.TunAddr, cfg.GSO)
	if err != nil {
		log.Fatalf("tnl-core: tun: %v", err)
	}
	defer dev.Close()

	cipherName := "off"
	if cfg.Crypto.Enabled {
		// Validate the cipher/PSK up front (fail fast); the carriers build the
		// actual per-session sealers after the ephemeral handshake.
		s, err := crypto.NewSealer(cfg.Crypto.Cipher, cfg.Crypto.PSK, cfg.Role == "client")
		if err != nil {
			log.Fatalf("tnl-core: crypto: %v", err)
		}
		cipherName = s.Name
	} else {
		if cfg.Obfs {
			log.Fatalf("tnl-core: obfs requires crypto (there is no key to obfuscate with) — enable crypto or disable obfs")
		}
		// Clear mode has NO authentication: a single spoofed datagram can rebind
		// the peer or inject a packet into the TUN. Make that impossible to miss.
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

	// carrier is satisfied by all four core implementations — UDP (packet.UDP),
	// TCP-family (packet.TCP), raw (packet.Raw) and flux (packet.Flux);
	// cfg.Transport selects which one is built.
	type carrier interface {
		Run() error
		Close() error
	}
	var b carrier
	ka := time.Duration(cfg.Keepalive) * time.Second
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
			la := cfg.ListenIPs // pooled server: bind each selected pool IP; else the single Listen addr
			if len(la) == 0 {
				la = []string{cfg.Listen}
			}
			b, err = packet.ListenTCP(la, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Cover, cfg.CoverSNI)
			if err == nil {
				log.Printf("tnl-core: listening (core/tcp%s%s) on %v", obfsTag, coverTag(cfg.Cover), la)
			}
		case "client":
			b, err = packet.DialTCP(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Cover, cfg.CoverSNI)
			if err == nil {
				log.Printf("tnl-core: dialing (core/tcp%s%s) %s", obfsTag, coverTag(cfg.Cover), cfg.Peer)
			}
		}
	case "raw":
		switch cfg.Role {
		case "server":
			b, err = packet.ListenRaw(cfg.Listen, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.RawProfile, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto)
			if err == nil {
				log.Printf("tnl-core: listening (core/raw:%s%s%s) on %s", cfg.RawProfile, obfsTag, fecTag, cfg.Listen)
			}
		case "client":
			b, err = packet.DialRaw(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.RawProfile, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto)
			if err == nil {
				log.Printf("tnl-core: dialing (core/raw:%s%s%s) %s", cfg.RawProfile, obfsTag, fecTag, cfg.Peer)
			}
		}
	case "spoof":
		spoofTag := spoofLogTag(cfg)
		switch cfg.Role {
		case "server":
			b, err = packet.ListenSpoof(cfg.Listen, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.RealPeer, cfg.SpoofDst, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto)
			if err == nil {
				log.Printf("tnl-core: listening (core/spoof:%s%s%s) on %s", spoofTag, obfsTag, fecTag, cfg.Listen)
			}
		case "client":
			b, err = packet.DialSpoof(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.SpoofSrc, cfg.SpoofDst, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto)
			if err == nil {
				log.Printf("tnl-core: dialing (core/spoof:%s%s%s) %s", spoofTag, obfsTag, fecTag, cfg.Peer)
			}
		}
	case "flux":
		rotate := time.Duration(cfg.FluxRotateSecs) * time.Second
		switch cfg.Role {
		case "server":
			b, err = packet.ListenFlux(cfg.Listen, dev, ka, rotate, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.FluxCarrier, cfg.FluxShape, cfg.FluxEpochOffset, cfg.Fec, cfg.FecData, cfg.FecParity)
			if err == nil {
				log.Printf("tnl-core: listening (core/flux:%s/%s rotate=%ds%s%s)", cfg.FluxCarrier, cfg.FluxShape, cfg.FluxRotateSecs, obfsTag, fecTag)
			}
		case "client":
			b, err = packet.DialFlux(cfg.Peer, dev, ka, rotate, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.FluxCarrier, cfg.FluxShape, cfg.FluxEpochOffset, cfg.Fec, cfg.FecData, cfg.FecParity)
			if err == nil {
				log.Printf("tnl-core: dialing (core/flux:%s/%s rotate=%ds%s%s) %s", cfg.FluxCarrier, cfg.FluxShape, cfg.FluxRotateSecs, obfsTag, fecTag, cfg.Peer)
			}
		}
	case "ws":
		switch cfg.Role {
		case "server":
			if cfg.cdnIsHTTP() {
				b, err = packet.ListenHTTPC(cfg.Listen, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher)
				if err == nil {
					log.Printf("tnl-core: listening (core/http%s) on %s", obfsTag, cfg.Listen)
				}
				break
			}
			b, err = packet.ListenWS(cfg.Listen, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSPath)
			if err == nil {
				log.Printf("tnl-core: listening (core/ws%s) on %s", obfsTag, cfg.Listen)
			}
		case "client":
			carrier := "ws"
			if cfg.cdnIsHTTP() {
				carrier = "http"
			}
			if len(cfg.WSEdgeIPs) > 0 { // rotating edge pool overrides the single edge (ws or httpc)
				snis := make([]packet.WSPoolSNI, len(cfg.WSEdgeSNIs))
				for i, s := range cfg.WSEdgeSNIs {
					snis[i] = packet.WSPoolSNI{Host: s.Host, ECH: s.ECH, Path: s.Path}
				}
				b, err = packet.DialWSPoolCfg(dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher,
					cfg.WSEdgeIPs, snis, time.Duration(cfg.WSRotateSecs)*time.Second, cfg.WSAutoBurn, cfg.WSStatusPath, cfg.cdnIsHTTP(), cfg.cdnMode(), cfg.WSWarmStandby)
				if err == nil {
					warmTag := ""
					if cfg.WSWarmStandby {
						warmTag = " warm-standby"
					}
					log.Printf("tnl-core: dialing (core/%s%s wss ech pool: %dIP×%dSNI rotate=%ds auto_burn=%v%s)",
						carrier, obfsTag, len(cfg.WSEdgeIPs), len(cfg.WSEdgeSNIs), cfg.WSRotateSecs, cfg.WSAutoBurn, warmTag)
				}
				break
			}
			var echList []byte
			if cfg.WSECH != "" { // validated as base64 in Config.Validate
				echList, _ = base64.StdEncoding.DecodeString(cfg.WSECH)
			}
			if cfg.cdnIsHTTP() { // single-edge HTTP carrier
				b, err = packet.DialHTTPC(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSHost, cfg.WSPath, cfg.WSTLS, echList, cfg.cdnMode())
				if err == nil {
					mode := cfg.cdnMode()
					if mode == "" {
						mode = "post"
					}
					log.Printf("tnl-core: dialing (core/http:%s%s wss) %s", mode, obfsTag, cfg.Peer)
				}
				break
			}
			b, err = packet.DialWS(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSHost, cfg.WSPath, cfg.WSTLS, echList)
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
			b, err = packet.DialDNS(dev, cfg.DNSResolvers, cfg.DNSZone, cfg.Crypto.PSK, cfg.Crypto.Cipher, ka)
			if err == nil {
				log.Printf("tnl-core: dialing (core/dns zone=%s via resolvers %s)", cfg.DNSZone, strings.Join(cfg.DNSResolvers, ", "))
			}
		}
	default: // "udp"
		switch cfg.Role {
		case "server":
			la := cfg.ListenIPs // pooled server: bind each selected pool IP; else the single Listen addr
			if len(la) == 0 {
				la = []string{cfg.Listen}
			}
			b, err = packet.Listen(la, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Fec, cfg.FecData, cfg.FecParity)
			if err == nil {
				log.Printf("tnl-core: listening (core/udp%s%s) on %v", obfsTag, fecTag, la)
			}
		case "client":
			b, err = packet.Dial(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Fec, cfg.FecData, cfg.FecParity)
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
	// Per-tunnel self-heal deadline: when set, tighten the carrier's dead-detection window so this
	// tunnel re-establishes/fails over faster than the default (~3×keepalive / 60s idle backstop).
	// Every carrier implements it; a 0 value leaves the default formula in place.
	//
	// Applied on BOTH roles, not just the client. The panel writes dead_after_secs onto both ends of a
	// tunnel and config.go validates it on both, but this was gated on "client" — so on tcp/ws, where
	// the window IS the connection's read deadline and the server has one of its own, the server kept
	// its default (~60s) while the client honoured the operator's 20s. Half the tunnel self-healed at
	// the configured speed and the other half did not. On the connectionless carriers (udp/raw/flux)
	// the server holds no such window at all — there is no connection to reap — so this is inert
	// there by shape, not by oversight.
	applyDeadAfter(b, cfg.Transport, cfg.Keepalive, cfg.DeadAfterSecs)
	// Wire the status file: a liveness heartbeat (hb) plus this carrier's resolved dead window (dw),
	// and an event ring carrying the client's precise self-heal reasons into the node/panel system
	// log. EVERY client carrier implements it now — dns was the last one that did not, which left the
	// panel deciding its dot from traffic flow alone. Only the client writes it.
	if cfg.Role == "client" && cfg.StatusPath != "" {
		if s, ok := b.(interface{ SetStatusPath(string) }); ok {
			s.SetStatusPath(cfg.StatusPath)
			log.Printf("tnl-core: writing status/events to %s", cfg.StatusPath)
		}
	}
	// Fake-packet desync (client, raw/flux): emit decoy packets before each handshake to
	// mis-sync a stateful DPI. Only the raw/flux carriers implement it (they build the IPv4
	// header themselves); the kernel-socket carriers ignore this.
	if cfg.Role == "client" && cfg.FakeDesync {
		if s, ok := b.(interface {
			SetDesync(bool, int, int, string)
		}); ok {
			s.SetDesync(true, cfg.FakeTTL, cfg.FakeCount, cfg.FakeMode)
			log.Printf("tnl-core: fake-desync on (%d decoys, ttl=%d, mode=%s)", cfg.FakeCount, cfg.FakeTTL, cfg.FakeMode)
		}
	}
	// POST-ladder upstream shape (client, httpc): per-CDN, see SetHTTPUpstream. Before any dial.
	if cfg.Role == "client" && cfg.cdnIsHTTP() && (cfg.HTTPUpWorkers|cfg.HTTPUpBatchKB|cfg.HTTPUpRate) != 0 {
		packet.SetHTTPUpstream(cfg.HTTPUpWorkers, cfg.HTTPUpBatchKB, cfg.HTTPUpRate)
		log.Printf("tnl-core: httpc upstream: workers=%d batch=%dKB rate=%d/s (0 = default)",
			cfg.HTTPUpWorkers, cfg.HTTPUpBatchKB, cfg.HTTPUpRate)
	}
	// SNI fragmentation (client, ws/http): split the wss ClientHello so the cleartext SNI crosses a
	// TCP segment boundary. Only the ws/HTTP carrier implements it; others ignore this.
	if cfg.Role == "client" && cfg.SNISplit {
		applySNISplit(b, cfg.Transport, cfg.SNIMode, cfg.SplitPos, cfg.SplitTTL)
	}
	// Destination rotation pool (client, direct transports udp/tcp/raw/flux): cycle the peer IPs and
	// burn a blocked one so a single filtered server IP doesn't kill the tunnel — the direct-transport
	// analogue of the ws edge pool. Only the direct carriers implement SetPeerPool; ws (its own edge
	// pool) and the server ignore it. Needs >=2 endpoints to actually rotate (config allows fewer only
	// as the degenerate single-peer case, which never moves).
	if cfg.Role == "client" && len(cfg.PeerIPs) >= 2 {
		if s, ok := b.(interface{ SetPeerPool(*packet.PeerPool) }); ok {
			pp := packet.NewPeerPool(cfg.PeerIPs, cfg.PeerAutoBurn, time.Duration(cfg.PeerRotateSecs)*time.Second, cfg.PeerStatusPath)
			s.SetPeerPool(pp)
			log.Printf("tnl-core: destination pool: %d peers rotate=%ds auto_burn=%v", len(cfg.PeerIPs), cfg.PeerRotateSecs, cfg.PeerAutoBurn)
		}
	}
	// Source rotation pool (client, direct transports): cycle the client's OWN source IPs alongside the
	// destination pool (same rotate/auto-burn settings). raw/flux swap the crafted-header source, udp
	// rebinds its socket, tcp re-dials with a new LocalAddr. Only the direct carriers implement it. The
	// source pool doesn't own a status file (the destination pool writes the panel-facing status).
	// >=1 (not >=2): a LONE src_ip is a fixed source that supersedes bind_ip (per the field doc) — it
	// wires a 1-entry pool that seeds the source and never rotates. Without this a single src_ip was
	// silently ignored and the kernel picked the default egress IP. A >=2 pool rotates as before.
	if cfg.Role == "client" && len(cfg.SrcIPs) >= 1 {
		if s, ok := b.(interface{ SetSourcePool(*packet.PeerPool) }); ok {
			sp := packet.NewPeerPool(cfg.SrcIPs, cfg.PeerAutoBurn, time.Duration(cfg.PeerRotateSecs)*time.Second, cfg.SrcStatusPath)
			s.SetSourcePool(sp)
			log.Printf("tnl-core: source pool: %d source IPs rotate=%ds auto_burn=%v", len(cfg.SrcIPs), cfg.PeerRotateSecs, cfg.PeerAutoBurn)
		}
	}
	// Pooled server (raw/flux): the client rotates its SOURCE IP, but these carriers see every host on the
	// wire and pre-filter incoming frames by the learned peer source. Give the server the client's known
	// source pool so a rotated source still reaches crypto (which authenticates it) and learnPeer re-binds
	// — otherwise a source rotation strands the server on the stale source until a rebuild. udp/tcp bind a
	// socket per source and re-learn naturally, so they don't implement this.
	if cfg.Role == "server" && len(cfg.PeerSrcIPs) > 0 {
		if s, ok := b.(interface{ SetPeerSources([]string) }); ok {
			s.SetPeerSources(cfg.PeerSrcIPs)
			log.Printf("tnl-core: pooled server follows client source rotation across %d source IPs", len(cfg.PeerSrcIPs))
		}
	}
	defer b.Close()

	// Clean shutdown removes the TUN (via defers) on SIGINT/SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Print("tnl-core: shutting down")
		b.Close()
		dev.Close()
		os.Exit(0)
	}()

	// Live "rotate now" for a ws edge pool, driven by the node via `systemctl kill`:
	// SIGUSR1 rotates the edge IP, SIGUSR2 rotates the SNI — one dimension, no rebuild,
	// the TUN stays up while the carrier re-dials on the new edge.
	if r, ok := b.(interface {
		RotateIP()
		RotateSNI()
		ProbeAllNow()
	}); ok {
		rsig := make(chan os.Signal, 3)
		signal.Notify(rsig, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP)
		go func() {
			for s := range rsig {
				switch s {
				case syscall.SIGUSR1:
					log.Print("tnl-core: rotate-now (edge IP)")
					r.RotateIP()
				case syscall.SIGUSR2:
					log.Print("tnl-core: rotate-now (SNI)")
					r.RotateSNI()
				case syscall.SIGHUP:
					log.Print("tnl-core: probe-now (retest all suspect/dead edges)")
					r.ProbeAllNow()
				}
			}
		}()
	} else if r, ok := b.(interface{ ProbeAllNow() }); ok {
		// Direct-transport peer/source pool (udp/tcp/raw/flux): SIGHUP retests every suspect/dead
		// endpoint immediately (the "probe now" control). These carriers have no ws edge dimensions to
		// rotate, so only SIGHUP is wired; the else-if avoids double-registering it for the ws path.
		rsig := make(chan os.Signal, 1)
		signal.Notify(rsig, syscall.SIGHUP)
		go func() {
			for range rsig {
				log.Print("tnl-core: probe-now (retest all suspect/dead peer/source endpoints)")
				r.ProbeAllNow()
			}
		}()
	}

	if err := b.Run(); err != nil {
		log.Printf("tnl-core: stopped: %v", err)
	}
}

func coverTag(cover bool) string {
	if cover {
		return " tls"
	}
	return ""
}

// How pinSource wired (or did not wire) the client's outbound source. Returned rather than logged in
// place so main prints one honest line and the decision itself is testable without a real carrier.
const (
	pinNone        = ""            // nothing to do: server role, or no bind_ip
	pinByBind      = "bind"        // the carrier pins a source itself (SetSourceIP: tcp/ws/http)
	pinByPool      = "pool"        // pinned as a one-entry source pool (udp/raw/flux)
	pinBySrcIPs    = "src_ips"     // an explicit source pool supersedes bind_ip
	pinBySpoof     = "spoof_src"   // a forged source already owns the source field
	pinUnsupported = "unsupported" // the carrier can pin neither, so the kernel chooses
)

// pinSource pins the client's outbound source IP to this node's own registered IP when bind_ip is
// set, so on a multi-IP host the peer/CDN sees THAT address instead of whatever the route's default
// source happens to be. The node stamps bind_ip from local_ip on every client core tunnel, so this
// runs on effectively all of them.
//
// SetSourceIP is a TCP-family method (tcp/ws/http re-dial with a LocalAddr). udp/raw/flux have no
// such method — they pin a source through the source POOL, whose gate is deliberately len>=1 so a
// LONE entry is a fixed source that never rotates. bind_ip therefore becomes a one-entry pool there
// rather than nothing: the same request, expressed the way those carriers already implement it.
//
// Doing nothing was the bug, and it was silent in both directions: the type assertion had no else,
// and the "binding outbound source IP" line lived inside its successful branch. So on udp/raw/flux
// the kernel picked the route's default source and NOTHING said the operator's chosen node address
// was unused — on a host whose other addresses are burned, that is the entire point of the knob.
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
			return pinBySrcIPs // wired further down, and it supersedes bind_ip per the field doc
		}
		if cfg.SpoofSrc != "" {
			// A forged source already owns the source field. SetSourcePool refuses a pool here and
			// says so, naming a pool the operator never configured; bind_ip is simply moot.
			return pinBySpoof
		}
		// No auto-burn and no rotate: a fixed source must stay fixed, and burning the only entry
		// would leave the pool with nothing to fall back to. No status path either — the panel's
		// source box belongs to a pool the operator chose, not to this.
		s.SetSourcePool(packet.NewPeerPool([]string{cfg.BindIP}, false, 0, ""))
		return pinByPool
	}
	return pinUnsupported
}

// effectiveDeadAfter resolves the dead window a carrier will REALLY enforce for the operator's
// dead_after_secs, plus a short note naming the floor that applied — so the startup log cannot promise
// a number the carrier then overrides.
//
// Every carrier floors the override, but not by the same rule: udp/tcp/raw/flux clamp up to 2×keepalive,
// while dns applies its own ABSOLUTE floor (dnstun's dead floor) because that carrier is high-loss and
// its window must survive several dropped pings. Logging 2×keepalive for dns was wrong in BOTH
// directions — with keepalive=15/dead_after=10 it printed 30s against a real 20s, and with
// keepalive=5/dead_after=10 it printed 10s against the same real 20s. An operator asking why a dns
// tunnel self-heals when it does was reading a number nothing enforced.
func effectiveDeadAfter(transport string, keepaliveSecs, deadAfterSecs int) (int, string) {
	floor, note := 2*keepaliveSecs, "≥2×keepalive"
	if transport == "dns" {
		floor = packet.DNSDeadFloorSecs()
		note = fmt.Sprintf("≥%ds, the dns carrier floor", floor)
	}
	if deadAfterSecs < floor {
		return floor, note
	}
	return deadAfterSecs, note
}

// applyDeadAfter wires the per-tunnel self-heal deadline into the carrier and logs the EFFECTIVE
// value. It deliberately takes NO role: dead_after_secs is written onto both ends of a tunnel by the
// panel and validated on both by config.go, and on tcp/ws the window IS the connection's read
// deadline, which the server has one of too. Gating this on role=="client" left the server reaping a
// dead connection on its own ~60s default while the client honoured the operator's 20s — half the
// tunnel self-healing at the configured speed and half not. On the connectionless carriers the
// server holds no such window at all (there is no connection to reap), so this is inert there by the
// shape of the carrier rather than by a gate.
//
// Split out of main so the decision is reachable from a test without opening a TUN.
func applyDeadAfter(b any, transport string, keepaliveSecs, deadAfterSecs int) bool {
	if deadAfterSecs <= 0 {
		return false // leave each carrier's default formula in place
	}
	s, ok := b.(interface{ SetDeadAfter(int) })
	if !ok {
		// Say so. The comment here used to claim every carrier implements this, and *packet.DNS did
		// not — so the assertion failed, the success log never printed, and a fleet-wide operator
		// setting was silently inert on exactly one transport.
		log.Printf("core: WARNING carrier %s ignores dead_after_secs — it implements no SetDeadAfter", transport)
		return false
	}
	s.SetDeadAfter(deadAfterSecs)
	effDead, floorNote := effectiveDeadAfter(transport, keepaliveSecs, deadAfterSecs)
	log.Printf("tnl-core: self-heal deadline set to %ds (%s)", effDead, floorNote)
	return true
}

// applySNISplit wires SNI fragmentation into the carrier and logs what really happened.
//
// The old code printed "SNI fragmentation on" for any carrier that merely HAD the method. *TCP has
// it for transport=tcp as well as ws, and on tcp it discards the setting — no ClientHello of ours
// goes to an edge there — so a tcp tunnel logged positive confirmation of a defence that was not
// running. Report what the carrier actually accepted instead.
//
// Split out of main so the decision is reachable from a test without opening a TUN.
func applySNISplit(b any, transport, mode string, pos, ttl int) bool {
	if mode == "" {
		mode = "split"
	}
	s, ok := b.(interface {
		SetSNISplit(bool, int, string, int) bool
	})
	if ok && s.SetSNISplit(true, pos, mode, ttl) {
		log.Printf("tnl-core: SNI fragmentation on (mode=%s split_pos=%d ttl=%d)", mode, pos, ttl)
		return true
	}
	log.Printf("core: WARNING carrier %s ignores sni_split — it sends no TLS ClientHello of its own, so nothing is fragmented", transport)
	return false
}

// spoofLogTag names which outer field(s) a spoof carrier forges, for the startup log.
func spoofLogTag(cfg *Config) string {
	switch {
	case cfg.SpoofSrc != "" && cfg.SpoofDst != "":
		return "src+dst"
	case cfg.SpoofDst != "":
		return "dst" // decoy destination (server side carries only this + real_peer)
	case cfg.SpoofSrc != "":
		return "src"
	default:
		return "src" // server for a src-only client carries neither field, only real_peer
	}
}
