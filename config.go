package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
)

type CryptoCfg struct {
	Enabled bool   `json:"enabled"`
	PSK     string `json:"psk"`
	Cipher  string `json:"cipher"`
}

type WSSNI struct {
	Host string `json:"host"`
	ECH  string `json:"ech"`
	Path string `json:"path"`
}

func (c *Config) cdnIsHTTP() bool { return c.CDNCarrier == "http" || c.CDNCarrier == "grpc" }

func queueingCarrier(t string) bool { return t == "raw" || t == "udp" }

const maxWorkers = 4

func (c *Config) cdnMode() string {
	if c.CDNCarrier == "grpc" {
		return "grpc"
	}
	return "post"
}

type Config struct {
	Role    string `json:"role"`
	Mode    string `json:"mode"`
	Profile string `json:"profile"`

	Transport string `json:"transport"`

	RawProfile string `json:"raw_profile"`

	RawProto int `json:"raw_proto"`

	RawPort int `json:"raw_port"`

	RawSport int `json:"raw_sport"`

	RawSportRandom bool `json:"raw_sport_random"`

	SpoofSrc string `json:"spoof_src_ip"`
	RealPeer string `json:"real_peer_ip"`

	SpoofDst string `json:"spoof_dst_ip"`

	DNSZone      string   `json:"dns_zone"`
	DNSResolvers []string `json:"dns_resolvers"`

	Listen string `json:"listen"`

	ListenIPs []string `json:"listen_ips"`
	Peer      string   `json:"peer"`

	PeerIPs        []string `json:"peer_ips"`
	PeerRotateSecs int      `json:"peer_rotate_secs"`

	SrcIPs []string `json:"src_ips"`

	PeerSrcIPs []string `json:"peer_src_ips"`

	BindIP string `json:"bind_ip"`

	TunName string `json:"tun_name"`
	TunAddr string `json:"tun_addr"`
	MTU     int    `json:"mtu"`

	SockBuf int `json:"sock_buf"`

	PortTries int `json:"port_tries"`

	Workers int       `json:"workers"`
	Crypto  CryptoCfg `json:"crypto"`

	Obfs bool `json:"obfs"`

	Cover    bool   `json:"cover"`
	CoverSNI string `json:"cover_sni"`

	WSHost string `json:"ws_host"`
	WSPath string `json:"ws_path"`
	WSTLS  bool   `json:"ws_tls"`

	SNISplit bool `json:"sni_split"`
	SplitPos int  `json:"split_pos"`

	SNIMode  string `json:"sni_mode"`
	SplitTTL int    `json:"split_ttl"`

	CDNCarrier string `json:"cdn_carrier"`

	HTTPUpWorkers int `json:"http_up_workers"`
	HTTPUpBatchKB int `json:"http_up_batch_kb"`
	HTTPUpRate    int `json:"http_up_rate"`
	HTTPStreams   int `json:"http_streams"`

	WSECH string `json:"ws_ech"`

	WSEdgeIPs    []string `json:"ws_edge_ips"`
	WSEdgeSNIs   []WSSNI  `json:"ws_edge_snis"`
	WSRotateSecs int      `json:"ws_rotate_secs"`

	StatusPath string `json:"status_path"`

	FluxCarrier string `json:"flux_carrier"`

	FluxShape string `json:"flux_shape"`

	FluxEpochOffset int64 `json:"flux_epoch_offset"`

	FluxRotateSecs int `json:"flux_rotate_secs"`

	Fec bool `json:"fec"`

	FecData   int `json:"fec_data"`
	FecParity int `json:"fec_parity"`

	FakeDesync bool   `json:"fake_desync"`
	FakeTTL    int    `json:"fake_ttl"`
	FakeCount  int    `json:"fake_count"`
	FakeMode   string `json:"fake_mode"`

	GSO bool `json:"gso"`

	Tuning *TuningCfg `json:"tuning"`
}

type TuningCfg struct {
	SuspectBackoff  []int64 `json:"suspect_backoff"`
	DeadRetestSecs  int64   `json:"dead_retest_secs"`
	MinLivenessSecs int64   `json:"min_liveness_secs"`
	LadderRevive    []int64 `json:"ladder_revive"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.applyDefaults()
	return &c, nil
}

const minRotateSecs = 10

func (c *Config) applyDefaults() {
	if c.MTU <= 0 {
		c.MTU = 1400
	}
	if c.Workers < 1 {
		c.Workers = 1
	}
	if c.Workers > maxWorkers {
		c.Workers = maxWorkers
	}
	if c.SockBuf == 0 {
		c.SockBuf = 4 << 20
	}
	if c.SockBuf > 0 && c.SockBuf < 64<<10 {
		c.SockBuf = 64 << 10
	}
	if c.SockBuf > 64<<20 {
		c.SockBuf = 64 << 20
	}
	if c.Crypto.Cipher == "" {
		c.Crypto.Cipher = "aes-256-gcm"
	}
	if c.Transport == "" {
		c.Transport = "udp"
	}

	if len(c.PeerIPs) > 0 {
		c.Peer = c.PeerIPs[0]
	}
	if c.Transport == "raw" && c.RawProfile == "" {
		c.RawProfile = "bare"
	}
	if c.Transport == "flux" {
		if c.FluxRotateSecs == 0 {
			c.FluxRotateSecs = 600
		}
		if c.FluxCarrier == "" {
			c.FluxCarrier = "udp"
		}
		if c.FluxShape == "" {
			c.FluxShape = "random"
		}
	}
	if c.Fec {
		if c.FecData == 0 {
			c.FecData = 10
		}
		if c.FecParity == 0 {
			c.FecParity = 3
		}
	}
	if c.Transport == "ws" && c.WSPath == "" {
		c.WSPath = "/"
	}
	if c.FakeDesync {
		if c.FakeTTL <= 0 {
			c.FakeTTL = 4
		}
		if c.FakeCount <= 0 {
			c.FakeCount = 2
		}
		if c.FakeMode == "" {
			c.FakeMode = "ttl"
		}
	}
}

func validatePoolEndpoint(field, e string, needPort bool) error {
	if needPort {
		host, port, err := net.SplitHostPort(e)
		if err != nil {
			return errors.New(field + " entry " + strconv.Quote(e) + " must be \"ip:port\"")
		}
		if net.ParseIP(host) == nil {
			return errors.New(field + " entry " + strconv.Quote(e) + " has a non-IP host (the pool dials IPs directly, no DNS)")
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return errors.New(field + " entry " + strconv.Quote(e) + " has an invalid port")
		}
		return nil
	}
	host := e
	if h, _, err := net.SplitHostPort(e); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
		return errors.New(field + " entry " + strconv.Quote(e) + " must be an IPv4 address")
	}
	return nil
}

func rawProtoBorrowed(proto int) error {
	owner, taken := packet.RawProfileOwning(proto)
	if !taken || owner == "bare" {
		return nil
	}
	return errors.New("raw_proto " + strconv.Itoa(proto) + " is the \"" + owner +
		"\" profile's protocol number, and a headerless carrier sends that number with no header at all —" +
		" a middlebox parses the ciphertext as a " + owner + " header and drops the flow." +
		" Use raw_profile \"" + owner + "\" instead")
}

func (c *Config) validate() error {
	if c.Mode != "packet" {
		return errors.New("mode must be \"packet\" in this build")
	}
	if c.Profile != "core" {
		return errors.New("profile must be \"core\" in this build")
	}
	switch c.Role {
	case "server":
		if c.Listen == "" {
			return errors.New("server role requires \"listen\"")
		}

		if len(c.ListenIPs) > 0 && c.Transport != "" && c.Transport != "udp" && c.Transport != "tcp" {
			return errors.New("listen_ips is read only by the udp and tcp servers; transport \"" + c.Transport + "\" binds \"listen\" alone")
		}
		for _, la := range c.ListenIPs {
			if err := validatePoolEndpoint("listen_ips", la, true); err != nil {
				return err
			}
		}
	case "client":
		if c.Transport != "dns" && c.Peer == "" && len(c.PeerIPs) == 0 {
			return errors.New("client role requires \"peer\" (or a peer_ips rotation pool)")
		}
	default:
		return errors.New("role must be \"server\" or \"client\"")
	}
	if c.BindIP != "" && net.ParseIP(c.BindIP) == nil {
		return errors.New("bind_ip must be a valid IP address")
	}
	switch c.Transport {
	case "", "udp", "tcp":
	case "raw":
		if c.RawProfile != "" && !packet.RawProfileValid(c.RawProfile) {
			return errors.New("raw_profile must be one of " + strings.Join(packet.RawProfileNames(), "|"))
		}

		if c.RawProto != 0 {
			if c.RawProfile != "" && c.RawProfile != "bare" {
				return errors.New("raw_proto overrides the outer protocol number for the \"bare\" profile only (raw_profile \"" + c.RawProfile + "\" is tied to its forged header)")
			}
			if c.RawProto < 1 || c.RawProto > 255 {
				return errors.New("raw_proto must be in 1..255 (0 = the profile's native protocol number)")
			}
			if err := rawProtoBorrowed(c.RawProto); err != nil {
				return err
			}
		}

		if c.RawPort != 0 {
			if !packet.RawProfileHasPorts(c.RawProfile) {
				return errors.New("raw_port sets the forged server port of the \"udp\" and \"tcp\" profiles only" +
					" (raw_profile \"" + c.RawProfile + "\" forges no ports)")
			}
			if c.RawPort < 1 || c.RawPort > 65535 {
				return errors.New("raw_port must be in 1..65535 (0 = the profile default 443)")
			}
		}

		if c.RawSportRandom && !packet.RawProfileHasPorts(c.RawProfile) {
			return errors.New("raw_sport_random rolls the forged SOURCE port of the \"udp\" and \"tcp\"" +
				" profiles only (raw_profile \"" + c.RawProfile + "\" forges no ports)")
		}
		if c.RawSport != 0 {
			if !packet.RawProfileHasPorts(c.RawProfile) {
				return errors.New("raw_sport sets the forged client source port of the \"udp\" and \"tcp\"" +
					" profiles only (raw_profile \"" + c.RawProfile + "\" forges no ports)")
			}
			if c.RawSport < 1 || c.RawSport > 65535 {
				return errors.New("raw_sport must be in 1..65535 (0 = the profile default 51820)")
			}

			if c.RawSportRandom {
				return errors.New("raw_sport fixes the forged client source port and raw_sport_random rolls it" +
					" -- set one or the other, not both")
			}
		}
		if !c.Crypto.Enabled {
			return errors.New("raw transport requires crypto enabled (the AEAD both encrypts and authenticates each raw packet)")
		}
	case "spoof":
		if !c.Crypto.Enabled {
			return errors.New("spoof transport requires crypto enabled (the AEAD authenticates every forged-header frame)")
		}
		if c.RawProto != 0 {
			if c.RawProto < 1 || c.RawProto > 255 {
				return errors.New("raw_proto must be in 1..255 (0 = the bare default 253)")
			}
			if err := rawProtoBorrowed(c.RawProto); err != nil {
				return err
			}
		}

		if c.RawPort != 0 {
			return errors.New("raw_port sets a forged L4 port, and the spoof carrier writes no L4 header at all")
		}
		if c.RawSportRandom {
			return errors.New("raw_sport_random rolls a forged L4 source port, and the spoof carrier writes no L4 header at all")
		}
		if c.RawSport != 0 {
			return errors.New("raw_sport sets a forged L4 source port, and the spoof carrier writes no L4 header at all")
		}
		if c.SpoofSrc != "" && net.ParseIP(c.SpoofSrc).To4() == nil {
			return errors.New("spoof_src_ip must be an IPv4 address")
		}
		if c.SpoofDst != "" && net.ParseIP(c.SpoofDst).To4() == nil {
			return errors.New("spoof_dst_ip must be an IPv4 address")
		}
		if c.RealPeer != "" && net.ParseIP(c.RealPeer).To4() == nil {
			return errors.New("real_peer_ip must be an IPv4 address")
		}
		switch c.Role {
		case "client":
			if c.SpoofSrc == "" && c.SpoofDst == "" {
				return errors.New("spoof transport requires at least one of spoof_src_ip / spoof_dst_ip on the client")
			}
		case "server":
			if c.RealPeer == "" {
				return errors.New("spoof server requires real_peer_ip (the client's real IP to reply to)")
			}
		}
	case "flux":
		if !c.Crypto.Enabled {
			return errors.New("flux transport requires crypto enabled (the shape is derived from the PSK and the AEAD authenticates every frame)")
		}
		if c.FluxRotateSecs < 0 {
			return errors.New("flux_rotate_secs must be >= 0 (0 defaults to 600)")
		}
		switch c.FluxCarrier {
		case "", "udp", "stun":
		default:
			return errors.New("flux_carrier must be \"udp\" or \"stun\"")
		}
		switch c.FluxShape {
		case "", "random", "quic", "video", "webrtc":
		default:
			return errors.New("flux_shape must be \"random\", \"quic\", \"video\", or \"webrtc\"")
		}
	case "dns":
		if !c.Crypto.Enabled {
			return errors.New("dns transport requires crypto enabled (the session handshake and every datagram are AEAD-authenticated)")
		}
		if c.DNSZone == "" {
			return errors.New("dns transport requires dns_zone (the delegated zone whose authoritative NS is the server)")
		}
		if c.Role == "client" && len(c.DNSResolvers) == 0 {
			return errors.New("dns client requires at least one dns_resolvers entry (a recursive resolver to query)")
		}
	case "ws":
		if c.WSTLS && c.Role == "client" && c.WSHost == "" && len(c.WSEdgeIPs) == 0 {
			return errors.New("ws_tls requires ws_host (the TLS SNI / fronting domain)")
		}

		if c.WSECH != "" {
			if !c.WSTLS || c.Role != "client" {
				return errors.New("ws_ech requires ws_tls on a client")
			}
			if _, err := base64.StdEncoding.DecodeString(c.WSECH); err != nil {
				return errors.New("ws_ech is not valid base64")
			}
		}

		if c.HTTPStreams != 0 {
			if c.Role != "client" || (c.CDNCarrier != "http" && c.CDNCarrier != "grpc") {
				return errors.New("http_streams applies to an http- or grpc-carrier CLIENT only")
			}
			if c.HTTPStreams < 0 || c.HTTPStreams > 16 {
				return errors.New("http_streams must be between 1 and 16 (0 = default)")
			}
		}
		if c.HTTPUpWorkers != 0 || c.HTTPUpBatchKB != 0 || c.HTTPUpRate != 0 {
			if c.Role != "client" || c.CDNCarrier != "http" {
				return errors.New("http_up_workers/http_up_batch_kb/http_up_rate apply to an http-carrier CLIENT only")
			}
			if c.HTTPUpWorkers < 0 || c.HTTPUpWorkers > 16 {
				return errors.New("http_up_workers must be between 1 and 16 (0 = default)")
			}

			if c.HTTPUpBatchKB < 0 || c.HTTPUpBatchKB > 512 {
				return errors.New("http_up_batch_kb must be between 0 and 512 (0 = default; a value below 8 is raised to 8)")
			}
			if c.HTTPUpRate < 0 || c.HTTPUpRate > 1000 {
				return errors.New("http_up_rate must be between 1 and 1000 POSTs/sec (0 = unpaced)")
			}
		}
		if c.SNISplit {
			if !c.WSTLS || c.Role != "client" {
				return errors.New("sni_split requires ws_tls on a client")
			}
			if c.SplitPos < 0 || c.SplitPos > 1400 {
				return errors.New("split_pos must be between 0 and 1400")
			}
			switch c.SNIMode {
			case "", "split", "disorder", "fake":
			default:
				return errors.New("sni_mode must be \"split\", \"disorder\", or \"fake\"")
			}

			if c.SplitTTL < 0 || c.SplitTTL > packet.MaxHopBudget {
				return fmt.Errorf("split_ttl must be between 0 and %d (0 = default); above that the "+
					"disorder head reaches the server and the mode is a no-op", packet.MaxHopBudget)
			}
		}

		switch c.CDNCarrier {
		case "", "ws", "http", "grpc":
		default:
			return errors.New("cdn_carrier must be \"ws\", \"http\" or \"grpc\"")
		}
		if c.CDNCarrier == "grpc" && c.Role == "client" && !c.WSTLS && len(c.WSEdgeIPs) == 0 {
			return errors.New("cdn_carrier \"" + c.CDNCarrier + "\" requires ws_tls (needs HTTP/2 to the edge)")
		}

		if c.WSRotateSecs < 0 {
			return errors.New("ws_rotate_secs must be >= 0 (0 = rotate only on a failed edge)")
		}

		if len(c.WSEdgeIPs) > 0 || len(c.WSEdgeSNIs) > 0 {
			if c.Role != "client" || !c.WSTLS {
				return errors.New("ws edge pool requires ws_tls on a client")
			}
			if len(c.WSEdgeIPs) == 0 || len(c.WSEdgeSNIs) == 0 {
				return errors.New("ws edge pool needs at least one edge IP and one SNI")
			}

			for _, e := range c.WSEdgeIPs {
				if err := validatePoolEndpoint("ws_edge_ips", e, true); err != nil {
					return err
				}
			}
			for _, s := range c.WSEdgeSNIs {
				if s.Host == "" {
					return errors.New("ws edge pool: an SNI entry has no host")
				}
				if s.ECH != "" {
					if _, err := base64.StdEncoding.DecodeString(s.ECH); err != nil {
						return errors.New("ws edge pool: an SNI has invalid base64 ech")
					}
				}
			}
		}
	default:
		return errors.New("transport must be \"udp\", \"tcp\", \"raw\", \"flux\", \"spoof\", \"ws\", or \"dns\"")
	}

	if len(c.PeerIPs) > 0 {
		if c.Role != "client" {
			return errors.New("peer_ips is a client rotation pool (a server listens, it does not dial)")
		}
		switch c.Transport {
		case "", "udp", "tcp", "raw", "flux":
		default:
			return errors.New("peer_ips is only for the direct transports (udp, tcp, raw, flux) — ws has its own edge pool")
		}

		needPort := c.Transport != "raw" && c.Transport != "flux"
		for _, e := range c.PeerIPs {
			if err := validatePoolEndpoint("peer_ips", e, needPort); err != nil {
				return err
			}
		}
	}

	if len(c.SrcIPs) > 0 {
		if c.Role != "client" {
			return errors.New("src_ips is a client source rotation pool (a server does not dial)")
		}
		switch c.Transport {
		case "", "udp", "tcp", "raw", "flux":
		default:
			return errors.New("src_ips is only for the direct transports (udp, tcp, raw, flux) — ws has its own edge pool")
		}
		for _, e := range c.SrcIPs {
			if err := validatePoolEndpoint("src_ips", e, false); err != nil {
				return err
			}
		}
	}
	if len(c.PeerSrcIPs) > 0 {
		if c.Role != "server" {
			return errors.New("peer_src_ips is a server-side view of the client's source pool")
		}
		switch c.Transport {
		case "raw", "flux":
		default:
			return errors.New("peer_src_ips is only for the raw/flux transports (udp/tcp re-learn the source on their own)")
		}
		for _, e := range c.PeerSrcIPs {
			if err := validatePoolEndpoint("peer_src_ips", e, false); err != nil {
				return err
			}
		}
	}

	for _, r := range []struct {
		name string
		secs int
	}{{"peer_rotate_secs", c.PeerRotateSecs}, {"ws_rotate_secs", c.WSRotateSecs}} {
		if r.secs > 0 && r.secs < minRotateSecs {
			return fmt.Errorf("%s (%ds) must be at least %ds: the endpoint it selects never gets to "+
				"answer before the next rotation moves on, so nothing is ever judged", r.name, r.secs, minRotateSecs)
		}
	}
	if c.PeerRotateSecs < 0 {
		return errors.New("peer_rotate_secs must be >= 0 (0 = rotate only on a dead peer)")
	}
	if c.TunAddr == "" {
		return errors.New("tun_addr is required")
	}
	if c.Crypto.Enabled && c.Crypto.PSK == "" {
		return errors.New("crypto enabled but psk is empty")
	}
	if c.Obfs && !c.Crypto.Enabled {
		return errors.New("obfs requires crypto enabled")
	}

	if c.Obfs && c.Transport == "dns" {
		return errors.New("obfs is not supported on the dns transport (the DNS carrier has no obfs framing)")
	}
	if c.Fec {
		switch c.Transport {
		case "", "udp", "raw", "flux", "spoof":
		default:
			return fmt.Errorf("fec is not supported on the %s carrier — only on the datagram carriers (udp, raw, flux, spoof)", c.Transport)
		}
		if c.FecData < 0 || c.FecParity < 0 {
			return errors.New("fec_data / fec_parity must be >= 0 (0 defaults to 10 / 3)")
		}

		ed, ep := c.FecData, c.FecParity
		if ed == 0 {
			ed = 10
		}
		if ep == 0 {
			ep = 3
		}
		if ed < 1 || ep < 1 || ed+ep > 255 {
			return errors.New("effective fec_data (default 10) + fec_parity (default 3) must satisfy fec_data>=1, fec_parity>=1, fec_data+fec_parity<=255")
		}

		if ed > packet.MaxFecData {
			return fmt.Errorf("fec_data must be at most %d: above that a parity-recovered frame lands outside the receiver's replay window and is discarded, so FEC would cost its full bandwidth and repair nothing", packet.MaxFecData)
		}
	}
	if c.FakeDesync {
		switch c.Transport {
		case "raw", "flux", "spoof", "tcp", "ws":
		default:
			return errors.New("fake_desync is supported on the raw, flux, spoof, tcp and ws carriers (not plain udp)")
		}

		if c.cdnIsHTTP() {
			return errors.New("fake_desync does not work on the HTTP carrier (its conn has no real TCP 4-tuple to mirror) — use the plain ws mode, or turn desync off")
		}
		if c.FakeTTL < 0 || c.FakeTTL > 255 {
			return errors.New("fake_ttl must be between 0 and 255 (0 defaults to 4)")
		}
		if c.FakeCount < 0 || c.FakeCount > 64 {
			return errors.New("fake_count must be between 0 and 64 (0 defaults to 2)")
		}
		switch c.FakeMode {
		case "", "ttl", "badsum", "both":
		default:
			return errors.New("fake_mode must be \"ttl\", \"badsum\", or \"both\"")
		}

		if c.FakeMode == "both" && c.FakeCount == 1 {
			return errors.New("fake_mode \"both\" needs fake_count >= 2 (one decoy cannot be both a low-TTL and a bad-checksum packet)")
		}
	}
	if c.Cover && c.Transport != "tcp" {
		return errors.New("cover (TLS) requires transport \"tcp\"")
	}

	if c.Cover && !c.Crypto.Enabled {
		return errors.New("cover (TLS) requires crypto enabled (the REALITY auth token is keyed on the PSK)")
	}
	if c.Cover && c.CoverSNI == "" {
		return errors.New("cover (TLS) requires cover_sni (the SNI to present)")
	}
	return nil
}
