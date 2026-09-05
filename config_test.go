package main

import (
	"strings"
	"testing"
)

func TestHTTPUpBatchMessageMatchesTheCheck(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
			Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true, WSHost: "cdn.example.com",
			CDNCarrier: "http",
			Crypto:     CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}

	for _, v := range []int{1, 4, 7, 8, 128, 512} {
		c := base()
		c.HTTPUpBatchKB = v
		if err := c.validate(); err != nil {
			t.Errorf("http_up_batch_kb=%d rejected: %v", v, err)
		}
	}

	c := base()
	c.HTTPUpBatchKB = 513
	err := c.validate()
	if err == nil {
		t.Fatal("http_up_batch_kb=513 accepted")
	}
	if !strings.Contains(err.Error(), "http_up_batch_kb") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
	if strings.Contains(err.Error(), "between 8") {
		t.Errorf("the message names 8 as the floor while 1..7 validate cleanly: %q", err.Error())
	}
}

func validRaw() *Config {
	return &Config{
		Role:      "client",
		Mode:      "packet",
		Profile:   "core",
		Transport: "raw",
		Peer:      "203.0.113.9",
		TunAddr:   "10.200.0.2/24",
		Crypto:    CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
	}
}

func TestRawTransportValidAndDefaults(t *testing.T) {
	c := validRaw()
	if err := c.validate(); err != nil {
		t.Fatalf("valid raw config rejected: %v", err)
	}
	c.applyDefaults()
	if c.RawProfile != "bare" {
		t.Errorf("raw_profile default = %q, want bare", c.RawProfile)
	}
}

func TestRawTransportProfiles(t *testing.T) {
	for _, p := range []string{"bare", "ipip", "gre", "icmp", "udp", "tcp"} {
		c := validRaw()
		c.RawProfile = p
		if err := c.validate(); err != nil {
			t.Errorf("raw_profile %q rejected: %v", p, err)
		}
	}
	c := validRaw()
	c.RawProfile = "wireguard"
	if err := c.validate(); err == nil {
		t.Error("bogus raw_profile accepted")
	}
}

func TestRawTransportRequiresCrypto(t *testing.T) {
	c := validRaw()
	c.Crypto = CryptoCfg{Enabled: false}
	if err := c.validate(); err == nil {
		t.Error("raw transport without crypto was accepted")
	}
}

func TestFakeDesyncBothNeedsTwo(t *testing.T) {
	c := validRaw()
	c.FakeDesync = true
	c.FakeMode = "both"
	c.FakeCount = 1
	if err := c.validate(); err == nil {
		t.Error("fake_mode=both with fake_count=1 was accepted (the badsum half never fires)")
	}
	c.FakeCount = 2
	if err := c.validate(); err != nil {
		t.Errorf("fake_mode=both with fake_count=2 rejected: %v", err)
	}
	c.FakeCount = 0
	if err := c.validate(); err != nil {
		t.Errorf("fake_mode=both with fake_count=0 (defaults to 2) rejected: %v", err)
	}

	for _, m := range []string{"ttl", "badsum"} {
		c.FakeMode = m
		c.FakeCount = 1
		if err := c.validate(); err != nil {
			t.Errorf("fake_mode=%s with fake_count=1 rejected: %v", m, err)
		}
	}
}

func TestRawTransportRejectsCover(t *testing.T) {
	c := validRaw()
	c.Cover = true
	c.CoverSNI = "example.com"
	if err := c.validate(); err == nil {
		t.Error("cover was accepted on the raw transport (it is TCP-only)")
	}
}

func TestWSPoolNoHost(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
			Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true,
			Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}

	c := base()
	c.WSEdgeIPs = []string{"104.16.0.1:443"}
	c.WSEdgeSNIs = []WSSNI{{Host: "cdn.example.com"}}
	if err := c.validate(); err != nil {
		t.Fatalf("ws edge pool without ws_host rejected: %v", err)
	}

	c = base()
	if err := c.validate(); err == nil {
		t.Error("single-edge wss client without ws_host was accepted")
	}
}

func TestWSEdgeIPsValidated(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
			Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true,
			WSEdgeSNIs: []WSSNI{{Host: "cdn.example.com"}},
			Crypto:     CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	if c := base(); func() bool { c.WSEdgeIPs = []string{"104.16.0.1:443", "104.17.0.1:443"}; return c.validate() != nil }() {
		t.Error("valid ip:port ws_edge_ips rejected")
	}
	c := base()
	c.WSEdgeIPs = []string{"cdn.example.com:443"}
	if err := c.validate(); err == nil {
		t.Error("ws_edge_ips with a hostname was accepted")
	}
	c = base()
	c.WSEdgeIPs = []string{"104.16.0.1"}
	if err := c.validate(); err == nil {
		t.Error("ws_edge_ips without a port was accepted")
	}
}

func TestListenIPsValidated(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "server", Mode: "packet", Profile: "core", Transport: "udp",
			Listen: "0.0.0.0:9000", TunAddr: "10.200.0.1/24",
			Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	c := base()
	c.ListenIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	if err := c.validate(); err != nil {
		t.Errorf("valid ip:port listen_ips rejected: %v", err)
	}
	c = base()
	c.ListenIPs = []string{"host.example.com:9000"}
	if err := c.validate(); err == nil {
		t.Error("listen_ips with a hostname was accepted")
	}
	c = base()
	c.ListenIPs = []string{"203.0.113.9"}
	if err := c.validate(); err == nil {
		t.Error("listen_ips without a port was accepted")
	}
	c = base()
	c.ListenIPs = []string{"203.0.113.9:70000"}
	if err := c.validate(); err == nil {
		t.Error("listen_ips with an out-of-range port was accepted")
	}
}

func TestListenIPsRejectedWhereItIsIgnored(t *testing.T) {
	psk := CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"}
	srv := func(tr string) *Config {
		return &Config{
			Role: "server", Mode: "packet", Profile: "core", Transport: tr,
			Listen: "0.0.0.0:9000", TunAddr: "10.200.0.1/24", Crypto: psk,
		}
	}
	for _, tr := range []string{"raw", "ws", "dns"} {
		c := srv(tr)
		switch tr {
		case "dns":
			c.DNSZone = "t.example.com"
		}
		if err := c.validate(); err != nil {
			t.Fatalf("%s: base server config is not valid, so this case proves nothing: %v", tr, err)
		}
		c.ListenIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
		err := c.validate()
		if err == nil {
			t.Errorf("%s server accepted listen_ips, which its data path never reads", tr)
			continue
		}
		if !strings.Contains(err.Error(), "listen_ips") {
			t.Errorf("%s: rejected for the wrong reason (%v)", tr, err)
		}
	}

	for _, tr := range []string{"", "udp", "tcp"} {
		c := srv(tr)
		c.ListenIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
		if err := c.validate(); err != nil {
			t.Errorf("transport %q must still accept listen_ips: %v", tr, err)
		}
	}
}

func TestRawProtoOnlyOnBare(t *testing.T) {
	for _, p := range []string{"ipip", "gre", "icmp", "udp", "tcp", "esp"} {
		c := validRaw()
		c.RawProfile = p
		if err := c.validate(); err != nil {
			t.Fatalf("%s: base raw config is not valid, so this case proves nothing: %v", p, err)
		}
		c.RawProto = 58
		err := c.validate()
		if err == nil {
			t.Errorf("raw_profile %q accepted raw_proto, which rawEffProto ignores for it", p)
			continue
		}
		if !strings.Contains(err.Error(), "raw_proto") {
			t.Errorf("%s: rejected for the wrong reason (%v)", p, err)
		}
	}

	for _, p := range []string{"bare", ""} {
		c := validRaw()
		c.RawProfile = p
		c.RawProto = 58
		if err := c.validate(); err != nil {
			t.Errorf("raw_profile %q must accept raw_proto: %v", p, err)
		}
	}

	c := validRaw()
	c.RawProfile = "bare"
	c.RawProto = 256
	if err := c.validate(); err == nil {
		t.Error("out-of-range raw_proto accepted on bare")
	}
}

func TestWSRotateSecsNonNegative(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
			Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true, WSHost: "cdn.example.com",
			Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	c := base()
	if err := c.validate(); err != nil {
		t.Fatalf("base ws config is not valid, so this test proves nothing: %v", err)
	}
	c.WSRotateSecs = -1
	err := c.validate()
	if err == nil {
		t.Fatal("negative ws_rotate_secs accepted; it silently disables edge rotation")
	}
	if !strings.Contains(err.Error(), "ws_rotate_secs") {
		t.Errorf("rejected for the wrong reason: %v", err)
	}
	for _, v := range []int{0, 60, 28800} {
		c = base()
		c.WSRotateSecs = v
		if err := c.validate(); err != nil {
			t.Errorf("ws_rotate_secs %d rejected: %v", v, err)
		}
	}
}

func validUDP() *Config {
	return &Config{
		Role: "client", Mode: "packet", Profile: "core", Transport: "udp",
		Peer: "203.0.113.9:9000", TunAddr: "10.200.0.2/24",
		Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
	}
}

func TestPeerPoolUDPValidAndSeedsPeer(t *testing.T) {
	c := validUDP()
	c.Peer = ""
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	if err := c.validate(); err != nil {
		t.Fatalf("valid udp peer pool rejected: %v", err)
	}
	c.applyDefaults()
	if c.Peer != "203.0.113.9:9000" {
		t.Errorf("applyDefaults should seed peer from the first pool entry, got %q", c.Peer)
	}

	c = validUDP()
	c.Peer = "198.51.100.7:9000"
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	c.applyDefaults()
	if c.Peer != "203.0.113.9:9000" {
		t.Errorf("pool must override a mismatched peer to PeerIPs[0], got %q", c.Peer)
	}
}

func TestPeerPoolUDPEntryNeedsPort(t *testing.T) {
	c := validUDP()
	c.PeerIPs = []string{"203.0.113.9", "198.51.100.7:9000"}
	if err := c.validate(); err == nil {
		t.Error("udp peer_ips entry without a port was accepted")
	}
}

func TestPeerPoolUDPRejectsHostname(t *testing.T) {
	c := validUDP()
	c.PeerIPs = []string{"cdn.example.com:9000"}
	if err := c.validate(); err == nil {
		t.Error("udp peer_ips entry with a hostname was accepted")
	}
}

func TestPeerPoolRawAcceptsBareIPRejectsV6(t *testing.T) {
	c := validRaw()
	c.PeerIPs = []string{"203.0.113.9", "198.51.100.7"}
	if err := c.validate(); err != nil {
		t.Fatalf("valid raw peer pool (bare IPv4) rejected: %v", err)
	}

	c = validRaw()
	c.PeerIPs = []string{"2001:db8::1"}
	if err := c.validate(); err == nil {
		t.Error("raw peer_ips entry with an IPv6 address was accepted")
	}
}

// The pool builds each entry's net.IPAddr and net.UDPAddr once, at construction, and hands the
// carrier the ready form. An IPv6 entry has no IPv4 form, so it would seat a cursor the carrier
// cannot follow: the destination silently stays where it was while the panel reports the move. The
// carriers write IPv4 headers, so the answer is to refuse it at the config, not to half-support it.
func TestPeerPoolRejectsV6WithAPortToo(t *testing.T) {
	for _, e := range []string{"[2001:db8::1]:9000", "2001:db8::1"} {
		c := validUDP()
		c.PeerIPs = []string{e, "198.51.100.7:9000"}
		if err := c.validate(); err == nil {
			t.Errorf("udp peer_ips accepted the IPv6 entry %q", e)
		}
	}
	c := validUDP()
	c.SrcIPs = []string{"[2001:db8::1]:0"}
	if err := c.validate(); err == nil {
		t.Error("src_ips accepted an IPv6 entry")
	}
}

func TestPeerPoolRejectedOnWSAndServer(t *testing.T) {

	c := &Config{
		Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
		Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true, WSHost: "cdn.example.com",
		Crypto:  CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		PeerIPs: []string{"203.0.113.9:443", "198.51.100.7:443"},
	}
	if err := c.validate(); err == nil {
		t.Error("peer_ips on the ws transport was accepted")
	}

	c = validUDP()
	c.Role = "server"
	c.Listen = "0.0.0.0:9000"
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	if err := c.validate(); err == nil {
		t.Error("peer_ips on a server was accepted")
	}
}

func TestPeerRotateSecsNonNegative(t *testing.T) {
	c := validUDP()
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	c.PeerRotateSecs = -5
	if err := c.validate(); err == nil {
		t.Error("negative peer_rotate_secs was accepted")
	}
}

func TestSrcIPsValidation(t *testing.T) {

	c := validUDP()
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	c.SrcIPs = []string{"192.0.2.10", "192.0.2.11"}
	if err := c.validate(); err != nil {
		t.Fatalf("valid src_ips pool rejected: %v", err)
	}

	c = validUDP()
	c.SrcIPs = []string{"2001:db8::1"}
	if err := c.validate(); err == nil {
		t.Error("src_ips with an IPv6 address was accepted")
	}

	c = &Config{
		Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
		Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true, WSHost: "cdn.example.com",
		Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		SrcIPs: []string{"192.0.2.10", "192.0.2.11"},
	}
	if err := c.validate(); err == nil {
		t.Error("src_ips on the ws transport was accepted")
	}
	c = validUDP()
	c.Role = "server"
	c.Listen = "0.0.0.0:9000"
	c.SrcIPs = []string{"192.0.2.10", "192.0.2.11"}
	if err := c.validate(); err == nil {
		t.Error("src_ips on a server was accepted")
	}
}

func validDNSClient() *Config {
	return &Config{
		Role:         "client",
		Mode:         "packet",
		Profile:      "core",
		Transport:    "dns",
		TunAddr:      "10.200.0.2/24",
		DNSZone:      "t.example.com",
		DNSResolvers: []string{"10.202.10.202"},
		Crypto:       CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
	}
}

func TestDNSTransportValidation(t *testing.T) {
	if err := validDNSClient().validate(); err != nil {
		t.Fatalf("valid dns client rejected: %v", err)
	}

	s := validDNSClient()
	s.Role, s.DNSResolvers, s.Listen = "server", nil, ":53"
	if err := s.validate(); err != nil {
		t.Fatalf("valid dns server rejected: %v", err)
	}

	for name, mut := range map[string]func(*Config){
		"no zone":      func(c *Config) { c.DNSZone = "" },
		"no resolvers": func(c *Config) { c.DNSResolvers = nil },
		"crypto off":   func(c *Config) { c.Crypto.Enabled = false },
	} {
		c := validDNSClient()
		mut(c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: dns config accepted but should be rejected", name)
		}
	}
}

func TestTheCarriersWithNoClearModeRefuseCryptoOff(t *testing.T) {
	for name, c := range map[string]*Config{
		"raw": validRaw(),
		"dns": validDNSClient(),
	} {
		if err := c.validate(); err != nil {
			t.Fatalf("%s: the baseline config is already invalid (%v) — the case below would prove nothing", name, err)
		}
		c.Crypto.Enabled = false
		if err := c.validate(); err == nil {
			t.Errorf("%s: accepted with crypto off; its carrier has no clear-mode path, so the tunnel would "+
				"come up and drop every frame", name)
		}
	}
}
