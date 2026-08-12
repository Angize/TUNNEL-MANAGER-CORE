package main

import (
	"strings"
	"testing"
)

// TestHTTPUpBatchMessageMatchesTheCheck guards that the rejection text names the range the predicate
// actually enforces. The check accepts 0..512 and SetHTTPUpstream then raises anything below 8 to 8, a
// safe direction, so the clamp stays. What cannot stay is a message naming 8 as the floor: an operator
// who set 4 got NO error, ran on 8, and on a later typo saw an error naming a range nothing enforces.
func TestHTTPUpBatchMessageMatchesTheCheck(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
			Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true, WSHost: "cdn.example.com",
			CDNCarrier: "http",
			Crypto:     CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	// Everything the predicate accepts must validate, including the 1..7 window that gets raised.
	for _, v := range []int{1, 4, 7, 8, 128, 512} {
		c := base()
		c.HTTPUpBatchKB = v
		if err := c.validate(); err != nil {
			t.Errorf("http_up_batch_kb=%d rejected: %v", v, err)
		}
	}
	// And the message for a value it does reject must not claim a floor it never enforces.
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

// validRaw returns a minimal, valid raw-transport client config to mutate in tests.
func validRaw() *Config {
	return &Config{
		Role:      "client",
		Mode:      "packet",
		Profile:   "core", // core profile (distinct from the raw encapsulation)
		Transport: "raw",
		Peer:      "203.0.113.9",
		TunAddr:   "10.200.0.2/24",
		Crypto:    CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
	}
}

// validSpoof returns a minimal, valid spoof-transport client config (forges a source) to mutate.
func validSpoof() *Config {
	return &Config{
		Role:      "client",
		Mode:      "packet",
		Profile:   "core",
		Transport: "spoof",
		Peer:      "203.0.113.9",
		TunAddr:   "10.200.0.2/24",
		SpoofSrc:  "192.0.2.7",
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

// TestFakeDesyncBothNeedsTwo guards that fake_mode="both" with fake_count=1 is rejected: specs()
// alternates ttl/badsum, so a single decoy is ONLY the ttl half and the badsum half the operator
// asked for silently never fires.
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
	c.FakeCount = 0 // 0 defaults to 2, so it must pass
	if err := c.validate(); err != nil {
		t.Errorf("fake_mode=both with fake_count=0 (defaults to 2) rejected: %v", err)
	}
	// "ttl" and "badsum" with a single decoy are fine — only "both" needs two.
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

func TestSpoofValidation(t *testing.T) {
	// A client forging a source is valid; a bogus IP is rejected.
	if err := validSpoof().validate(); err != nil {
		t.Errorf("valid spoof client rejected: %v", err)
	}
	c := validSpoof()
	c.SpoofSrc = "not-an-ip"
	if err := c.validate(); err == nil {
		t.Error("bogus spoof_src_ip accepted")
	}

	// A client forging a decoy destination is valid; a bogus IP is rejected.
	c = validSpoof()
	c.SpoofSrc = ""
	c.SpoofDst = "185.51.200.10"
	if err := c.validate(); err != nil {
		t.Errorf("valid spoof_dst client rejected: %v", err)
	}
	c = validSpoof()
	c.SpoofSrc = ""
	c.SpoofDst = "nope"
	if err := c.validate(); err == nil {
		t.Error("bogus spoof_dst_ip accepted")
	}

	// A client that forges nothing is just raw bare — rejected.
	c = validSpoof()
	c.SpoofSrc = ""
	c.SpoofDst = ""
	if err := c.validate(); err == nil {
		t.Error("spoof client with neither spoof_src nor spoof_dst accepted")
	}

	// Crypto is mandatory.
	c = validSpoof()
	c.Crypto = CryptoCfg{Enabled: false}
	if err := c.validate(); err == nil {
		t.Error("spoof transport without crypto accepted")
	}

	// raw_proto out of range is rejected; in range is accepted.
	c = validSpoof()
	c.RawProto = 300
	if err := c.validate(); err == nil {
		t.Error("spoof raw_proto=300 accepted")
	}
	c = validSpoof()
	c.RawProto = 58
	if err := c.validate(); err != nil {
		t.Errorf("spoof raw_proto=58 rejected: %v", err)
	}

	// Rotation is not allowed on the spoof carrier.
	c = validSpoof()
	c.PeerIPs = []string{"203.0.113.9", "203.0.113.10"}
	if err := c.validate(); err == nil {
		t.Error("spoof accepted a peer_ips rotation pool")
	}
	c = validSpoof()
	c.SrcIPs = []string{"192.0.2.7", "192.0.2.8"}
	if err := c.validate(); err == nil {
		t.Error("spoof accepted a src_ips rotation pool")
	}

	// A server must know the client's real IP to reply to (real_peer_ip), with or without a decoy.
	c = validSpoof()
	c.Role = "server"
	c.Listen = "0.0.0.0:9000"
	c.Peer = ""
	c.SpoofSrc = ""
	if err := c.validate(); err == nil {
		t.Error("spoof server without real_peer_ip accepted")
	}
	c.RealPeer = "198.51.100.9"
	if err := c.validate(); err != nil {
		t.Errorf("spoof server with real_peer_ip rejected: %v", err)
	}
	c.SpoofDst = "185.51.200.10" // decoy server, still needs real_peer (already set)
	if err := c.validate(); err != nil {
		t.Errorf("decoy spoof server with real_peer_ip rejected: %v", err)
	}
}

// TestWSPoolNoHost guards the regression where a rotating edge pool (which carries
// its own per-SNI hosts) was rejected because ws_host was empty — the same check
// that must still fire for a single-edge wss client.
func TestWSPoolNoHost(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
			Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true,
			Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	// A pool with no ws_host must be ACCEPTED (the SNI list supplies the hosts).
	c := base()
	c.WSEdgeIPs = []string{"104.16.0.1:443"}
	c.WSEdgeSNIs = []WSSNI{{Host: "cdn.example.com"}}
	if err := c.validate(); err != nil {
		t.Fatalf("ws edge pool without ws_host rejected: %v", err)
	}
	// A single-edge wss client with no ws_host and no pool must still be REJECTED.
	c = base()
	if err := c.validate(); err == nil {
		t.Error("single-edge wss client without ws_host was accepted")
	}
}

// TestWSEdgeIPsValidated locks in that ws_edge_ips are validated as literal ip:port like every other
// rotation pool — a hostname or a portless entry must be rejected at config load, not silently reach
// the data plane (where the pool dials the raw string with no DNS and the edge just burns).
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
	c.WSEdgeIPs = []string{"cdn.example.com:443"} // hostname — the pool dials IPs directly, no DNS
	if err := c.validate(); err == nil {
		t.Error("ws_edge_ips with a hostname was accepted")
	}
	c = base()
	c.WSEdgeIPs = []string{"104.16.0.1"} // missing the port
	if err := c.validate(); err == nil {
		t.Error("ws_edge_ips without a port was accepted")
	}
}

// TestListenIPsValidated checks that a pooled server's listen_ips must each be a literal IP:port —
// a hostname, a missing port, or an out-of-range port is rejected at load (we bind these directly).
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
	c.ListenIPs = []string{"host.example.com:9000"} // hostname — a bind needs a literal IP
	if err := c.validate(); err == nil {
		t.Error("listen_ips with a hostname was accepted")
	}
	c = base()
	c.ListenIPs = []string{"203.0.113.9"} // missing the port
	if err := c.validate(); err == nil {
		t.Error("listen_ips without a port was accepted")
	}
	c = base()
	c.ListenIPs = []string{"203.0.113.9:70000"} // port out of range
	if err := c.validate(); err == nil {
		t.Error("listen_ips with an out-of-range port was accepted")
	}
}

// TestListenIPsRejectedWhereItIsIgnored closes the class, not one line: listen_ips is validated in the
// shared `case "server"` arm, but main.go hands it ONLY to the tcp and udp listeners. Elsewhere the
// pool was checked, stored and advertised while the server bound cfg.Listen alone — and a pooled RAW
// server is worse than cosmetic, since a bound AF_INET raw socket is demuxed by destination.
func TestListenIPsRejectedWhereItIsIgnored(t *testing.T) {
	psk := CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"}
	srv := func(tr string) *Config {
		return &Config{
			Role: "server", Mode: "packet", Profile: "core", Transport: tr,
			Listen: "0.0.0.0:9000", TunAddr: "10.200.0.1/24", Crypto: psk,
		}
	}
	for _, tr := range []string{"raw", "flux", "ws", "dns", "spoof"} {
		c := srv(tr)
		switch tr {
		case "dns":
			c.DNSZone = "t.example.com" // the delegated zone this server is authoritative for
		case "spoof":
			c.RealPeer = "203.0.113.9" // the client's real IP to reply to
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
	// The two carriers that DO consume it must keep working, including the "" (=udp) default.
	for _, tr := range []string{"", "udp", "tcp"} {
		c := srv(tr)
		c.ListenIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
		if err := c.validate(); err != nil {
			t.Errorf("transport %q must still accept listen_ips: %v", tr, err)
		}
	}
}

// TestRawProtoOnlyOnBare guards that raw_proto is refused on the profiles that cannot honour it.
// rawEffProto applies it to the bare "bare" profile only — every other profile's protocol number is
// tied to its forged L4 header — so on icmp/udp/tcp/gre/esp the value validated, persisted and showed
// as set while the wire carried the profile's native number: a whitelist evasion believed to be on.
func TestRawProtoOnlyOnBare(t *testing.T) {
	for _, p := range []string{"ipip", "gre", "icmp", "udp", "tcp", "esp"} {
		c := validRaw()
		c.RawProfile = p
		if err := c.validate(); err != nil {
			t.Fatalf("%s: base raw config is not valid, so this case proves nothing: %v", p, err)
		}
		c.RawProto = 58 // ICMPv6's number, the classic whitelist-evasion pick
		err := c.validate()
		if err == nil {
			t.Errorf("raw_profile %q accepted raw_proto, which rawEffProto ignores for it", p)
			continue
		}
		if !strings.Contains(err.Error(), "raw_proto") {
			t.Errorf("%s: rejected for the wrong reason (%v)", p, err)
		}
	}
	// bare honours it, and an UNSET profile is bare (applyDefaults runs after validate).
	for _, p := range []string{"bare", ""} {
		c := validRaw()
		c.RawProfile = p
		c.RawProto = 58
		if err := c.validate(); err != nil {
			t.Errorf("raw_profile %q must accept raw_proto: %v", p, err)
		}
	}
	// The range check still applies on bare.
	c := validRaw()
	c.RawProfile = "bare"
	c.RawProto = 256
	if err := c.validate(); err == nil {
		t.Error("out-of-range raw_proto accepted on bare")
	}
}

// TestWSRotateSecsNonNegative guards the one rotation interval that had no check at all. A negative
// ws_rotate_secs became a negative Duration in main.go and tcp.go's `if b.rotate > 0` then skipped the
// rotation ticker entirely: the tunnel came up healthy and silently never rotated its edge. Its two
// siblings, peer_rotate_secs and flux_rotate_secs, have always been range-checked.
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
	for _, v := range []int{0, 60, 28800} { // 0 = rotate only on failure, and the node's own ceiling
		c = base()
		c.WSRotateSecs = v
		if err := c.validate(); err != nil {
			t.Errorf("ws_rotate_secs %d rejected: %v", v, err)
		}
	}
}

// The flux carrier set is exactly {udp, stun} (empty = udp). Both ride protocol 17, which is what makes
// the carrier's anti-leak DROP rules narrow enough to be safe: they match UDP on flux's own port pool,
// a shape nothing else on the host receives. A carrier that rode a bare IP protocol number instead
// would have those rules black-hole every co-located tunnel on that number, silently.
func TestFluxCarrierSetIsUDPOnly(t *testing.T) {
	base := func(carrier string) *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "flux", FluxCarrier: carrier,
			Peer: "203.0.113.9:9000", TunAddr: "10.200.0.2/24",
			Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	for _, ok := range []string{"", "udp", "stun"} {
		if err := base(ok).validate(); err != nil {
			t.Fatalf("flux_carrier %q must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"raw", "RAW", "icmp", "bare", "tcp"} {
		if err := base(bad).validate(); err == nil {
			t.Fatalf("flux_carrier %q was accepted", bad)
		}
	}
	c := base("")
	c.applyDefaults()
	if c.FluxCarrier != "udp" {
		t.Fatalf("an unset flux_carrier must resolve to udp, got %q", c.FluxCarrier)
	}
}

// TestFluxRotateHonoursTunedDefault checks that a flux tunnel with no explicit epoch length resolves
// FluxRotateSecs from the tuned global default (bounded), and falls back to 600 when the knob is unset.
func TestFluxRotateHonoursTunedDefault(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "flux",
			Peer: "203.0.113.9:9000", TunAddr: "10.200.0.2/24",
			Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	c := base() // no tuning -> default 600
	c.applyDefaults()
	if c.FluxRotateSecs != 600 {
		t.Errorf("unset flux rotate should default to 600, got %d", c.FluxRotateSecs)
	}
	c = base()
	c.FluxRotateSecs = 42 // an explicit value is never overridden by the default
	c.applyDefaults()
	if c.FluxRotateSecs != 42 {
		t.Errorf("an explicit flux rotate must be preserved, got %d", c.FluxRotateSecs)
	}
}

// validUDP is a minimal valid udp-transport client config to mutate in peer-pool tests.
func validUDP() *Config {
	return &Config{
		Role: "client", Mode: "packet", Profile: "core", Transport: "udp",
		Peer: "203.0.113.9:9000", TunAddr: "10.200.0.2/24",
		Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
	}
}

func TestPeerPoolUDPValidAndSeedsPeer(t *testing.T) {
	c := validUDP()
	c.Peer = "" // the pool alone must satisfy the client "peer" requirement
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	if err := c.validate(); err != nil {
		t.Fatalf("valid udp peer pool rejected: %v", err)
	}
	c.applyDefaults()
	if c.Peer != "203.0.113.9:9000" {
		t.Errorf("applyDefaults should seed peer from the first pool entry, got %q", c.Peer)
	}
	// The pool is authoritative: a Peer that disagrees with PeerIPs[0] must be OVERRIDDEN to the
	// pool's starting endpoint, so the initial dial and the pool's cur=0 can't desync.
	c = validUDP()
	c.Peer = "198.51.100.7:9000" // deliberately != PeerIPs[0]
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	c.applyDefaults()
	if c.Peer != "203.0.113.9:9000" {
		t.Errorf("pool must override a mismatched peer to PeerIPs[0], got %q", c.Peer)
	}
}

func TestPeerPoolUDPEntryNeedsPort(t *testing.T) {
	c := validUDP()
	c.PeerIPs = []string{"203.0.113.9", "198.51.100.7:9000"} // first entry missing the port
	if err := c.validate(); err == nil {
		t.Error("udp peer_ips entry without a port was accepted")
	}
}

func TestPeerPoolUDPRejectsHostname(t *testing.T) {
	c := validUDP()
	c.PeerIPs = []string{"cdn.example.com:9000"} // the pool dials IPs directly, no DNS
	if err := c.validate(); err == nil {
		t.Error("udp peer_ips entry with a hostname was accepted")
	}
}

func TestPeerPoolRawAcceptsBareIPRejectsV6(t *testing.T) {
	c := validRaw()
	c.PeerIPs = []string{"203.0.113.9", "198.51.100.7"} // raw addresses a bare IPv4
	if err := c.validate(); err != nil {
		t.Fatalf("valid raw peer pool (bare IPv4) rejected: %v", err)
	}
	// raw/flux are IPv4-only (parseIP4 rejects v6) — an IPv6 entry must be a clean config error,
	// not a silently-skipped endpoint at rotation time.
	c = validRaw()
	c.PeerIPs = []string{"2001:db8::1"}
	if err := c.validate(); err == nil {
		t.Error("raw peer_ips entry with an IPv6 address was accepted")
	}
}

func TestPeerPoolRejectedOnWSAndServer(t *testing.T) {
	// ws has its own edge pool; peer_ips is meaningless there.
	c := &Config{
		Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
		Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true, WSHost: "cdn.example.com",
		Crypto:  CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		PeerIPs: []string{"203.0.113.9:443", "198.51.100.7:443"},
	}
	if err := c.validate(); err == nil {
		t.Error("peer_ips on the ws transport was accepted")
	}
	// A server listens; it never dials a pool.
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
	// Valid source pool (bare IPv4) on a direct client — accepted alongside a dest pool.
	c := validUDP()
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	c.SrcIPs = []string{"192.0.2.10", "192.0.2.11"}
	if err := c.validate(); err != nil {
		t.Fatalf("valid src_ips pool rejected: %v", err)
	}
	// A source is a bare IPv4 regardless of carrier — "ip:port" host must still be an IP, v6 rejected.
	c = validUDP()
	c.SrcIPs = []string{"2001:db8::1"}
	if err := c.validate(); err == nil {
		t.Error("src_ips with an IPv6 address was accepted")
	}
	// Meaningless on ws (own edge pool) and on a server (it does not dial).
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

// validDNSClient returns a minimal, valid dns-transport client config to mutate in tests.
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
	// A dns server needs no peer/resolvers, just the zone and a listen address.
	s := validDNSClient()
	s.Role, s.DNSResolvers, s.Listen = "server", nil, ":53"
	if err := s.validate(); err != nil {
		t.Fatalf("valid dns server rejected: %v", err)
	}
	// Missing zone, missing client resolvers, and crypto-off must all be rejected.
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
