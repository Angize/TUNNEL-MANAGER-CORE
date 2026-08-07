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

// CryptoCfg controls confidentiality on the wire. When Enabled is false the
// raw L3 packet travels in the clear (useful for debugging or when an outer
// transport already provides TLS). The PSK is used to derive the AEAD key and
// is NEVER echoed back to the panel or node public config.
type CryptoCfg struct {
	Enabled bool   `json:"enabled"`
	PSK     string `json:"psk"`
	Cipher  string `json:"cipher"` // "aes-256-gcm" (default / only for now)
}

// WSSNI is one fronting domain in the ws edge pool, with its own base64 ECHConfigList
// (empty = no ECH for this domain) and request path (empty = "/").
type WSSNI struct {
	Host string `json:"host"`
	ECH  string `json:"ech"`
	Path string `json:"path"`
}

// cdnIsHTTP reports whether this carrier sends HTTP REQUESTS rather than a WebSocket upgrade — true
// for both "http" and "grpc", since both ride ordinary requests through the CDN.
func (c *Config) cdnIsHTTP() bool { return c.CDNCarrier == "http" || c.CDNCarrier == "grpc" }

// cdnMode is the upstream style the data plane is told: "grpc", else "post".
func (c *Config) cdnMode() string {
	if c.CDNCarrier == "grpc" {
		return "grpc"
	}
	return "post"
}

// Config is the full contract between the Python node agent and this core.
// The node writes it to core-<id>.json and launches the binary with
// --config <path>. Nothing here is invented at runtime; the node owns it.
type Config struct {
	Role    string `json:"role"`    // "server" (public, listens) | "client" (behind NAT, dials)
	Mode    string `json:"mode"`    // "packet" (only mode implemented in this slice)
	Profile string `json:"profile"` // "core" (the core profile identifier)

	// Transport selects the carrier for core frames: "udp" (default, NAT-friendly datagrams), "tcp"
	// (stream, length-prefixed frames), "raw" (each frame in a raw IPv4 packet of a chosen protocol —
	// see RawProfile), "flux" (a polymorphic raw carrier whose shape rotates per epoch off a
	// clock-derived schedule, with no wire signal), or "ws" (CDN-frontable — see WSHost).
	Transport string `json:"transport"`

	// RawProfile selects the raw-transport encapsulation (Transport=="raw" only): "bare" (native, proto
	// 253), "ipip" (4), "gre" (47), "icmp" (1), "udp" (17), "tcp" (6) or "esp" (50). The sealed frame is
	// identical across profiles; only the IP-layer carrier header changes. Raw sockets need CAP_NET_RAW
	// and Linux; ipip/gre often do not cross NAT.
	RawProfile string `json:"raw_profile"`

	// RawProto overrides the outer IP protocol number for the "bare" profile only — it carries no L4
	// header, so only the number on the wire changes (0/unset keeps 253). Set it to slip past a
	// protocol-whitelist filter that passes a "known" number, e.g. 58 (ICMPv6), which the IPv4 kernel
	// ignores. Ignored for the other profiles, whose number is tied to their forged header. Range 1..255.
	RawProto int `json:"raw_proto"`

	// RawPort overrides the SERVER port the "udp" and "tcp" profiles stamp on their forged L4 header
	// (0/unset keeps 443). No socket ever binds it — raw carriers open a socket on a PROTOCOL NUMBER, not
	// a port — so this only changes what a middlebox reads. It exists because the default makes the udp
	// profile look like QUIC, and a path that drops UDP/443 wholesale therefore drops the whole carrier.
	// Both ends must be given the same number. Ignored by every profile that forges no ports.
	RawPort int `json:"raw_port"`

	// RawSportRandom re-rolls the CLIENT's forged source port over Linux's ephemeral range for the life
	// of the tunnel, instead of the one constant 51820. A stateful middlebox keys a flow on the whole
	// 4-tuple, so a constant source port means every packet of every raw tunnel from a host hits the
	// same one — and once that tuple is burned the carrier is dead until something else changes. Only
	// the profiles that forge ports have a port to roll. The server is told too: it does not roll
	// anything, but its anti-leak rule has to cover the range the client can draw from.
	RawSportRandom bool `json:"raw_sport_random"`

	// SpoofSrc (client) forges the outer IPv4 source address of "spoof"-transport packets so a
	// per-source egress filter cannot pin the real IP. RealPeer (server) is the client's REAL IP: with a
	// forged source the server cannot learn where to reply, so it is told here — the AEAD still
	// authenticates every frame. Transport "spoof" + crypto only; needs CAP_NET_RAW. Both empty = off.
	SpoofSrc string `json:"spoof_src_ip"`
	RealPeer string `json:"real_peer_ip"`

	// SpoofDst forges the outer IPv4 DESTINATION to a decoy IP, so an on-path censor sees traffic to the
	// decoy while the packet still routes to the real server. The server therefore cannot receive on an
	// ordinary AF_INET raw socket — the kernel drops packets whose dst is not local — and reads with
	// AF_PACKET, replying as the decoy. It must also set RealPeer. Transport "spoof" + crypto only.
	SpoofDst string `json:"spoof_dst_ip"`

	// DNS-tunnel carrier (Transport=="dns"): the AEAD/KCP session rides inside DNS queries and responses.
	// DNSZone is the delegated zone whose authoritative NS is the server; DNSResolvers is the client's
	// list of recursive resolvers, typically DOMESTIC ones, so the client never sends a packet to the
	// server IP. It round-robins EVERY resolver, and there is no health FSM — a dead one costs a timeout.
	DNSZone      string   `json:"dns_zone"`
	DNSResolvers []string `json:"dns_resolvers"`

	Listen string `json:"listen"` // server: bind address, e.g. "0.0.0.0:9000"
	// ListenIPs is the server-side rotation-pool bind list: one "ip:port" per SELECTED pool IP. When set
	// (a pooled udp/tcp server), the server binds each of these instead of the single Listen/0.0.0.0, so
	// only the pool IPs listen and each reply leaves from the IP the client dialed. Empty = use Listen.
	ListenIPs []string `json:"listen_ips"`
	Peer      string   `json:"peer"` // client: server address, e.g. "1.2.3.4:9000"
	// PeerIPs is a rotation pool of DESTINATION endpoints for the direct transports (tcp/udp/raw/flux):
	// the client cycles them and burns a blocked one. With >1 entry it overrides the single Peer; each
	// entry is "ip:port" for udp/tcp or "ip" for raw/flux. PeerRotateSecs is the proactive interval (0 =
	// on failure only); PeerAutoBurn needs a liveness signal, so it is inert on a crypto-off udp pool.
	PeerIPs        []string `json:"peer_ips"`
	PeerRotateSecs int      `json:"peer_rotate_secs"`
	PeerAutoBurn   bool     `json:"peer_auto_burn"`
	PeerStatusPath string   `json:"peer_status_path"`
	// SrcIPs is the SOURCE rotation pool: the client's OWN IPs that it sends FROM, cycled alongside
	// PeerIPs on the same interval and burn policy. Each is a bare IPv4. Client + direct transports only,
	// and ignored on raw under spoof_src, where a forged source is a deliberate decoy. raw/flux stamp the
	// source per packet, udp rebinds its socket, tcp re-dials. When set it supersedes the single BindIP.
	SrcIPs []string `json:"src_ips"`
	// SrcStatusPath is the status file the SOURCE pool writes (its own live state + the pin cmd file),
	// separate from PeerStatusPath so the panel can show and drive both the source and destination pools.
	// Empty = the source pool has no panel-facing status / manual pin (it still rotates and self-heals).
	SrcStatusPath string `json:"src_status_path"`
	// PeerSrcIPs (SERVER, raw/flux only) is the client's SOURCE pool. Those servers see every host on the
	// wire and pre-filter by the learned peer source, so without this a rotated client source is dropped
	// before crypto and never re-bound — stranding the tunnel until a rebuild. Empty = strict
	// single-source filter. udp/tcp bind a socket per source and re-learn on their own.
	PeerSrcIPs []string `json:"peer_src_ips"`
	// BindIP is the source IP the client dials FROM (its own node IP). On a host with
	// several IPs the kernel would otherwise egress from the primary IP; binding pins the
	// outbound socket to this node's registered IP so the peer/CDN sees the expected source.
	// Empty = let the kernel choose. TCP-family carriers only (tcp/ws/http).
	BindIP string `json:"bind_ip"`

	TunName string `json:"tun_name"` // requested interface name, e.g. "tnl0"
	TunAddr string `json:"tun_addr"` // local L3 address with prefix, e.g. "10.200.0.1/24"
	MTU     int    `json:"mtu"`      // TUN MTU, e.g. 1400

	Keepalive int `json:"keepalive"` // client ping interval in seconds (default 15)
	// SockBuf is the send/receive socket-buffer size (bytes) pinned on the datagram carriers via
	// SO_SNDBUFFORCE/SO_RCVBUFFORCE, which bypass net.core.{r,w}mem_max. It matters on high-latency links
	// where the bandwidth-delay product exceeds the default and a burst overflows before the reader
	// drains it. TCP/WS autotune and are left alone. 0 = 4 MiB; negative = kernel default. Max 64 MiB.
	SockBuf int `json:"sock_buf"`
	// DeadAfterSecs (client) is the per-tunnel self-heal deadline: the carrier is declared dead, and the
	// client re-establishes or fails over, if no authenticated inbound frame arrives within this many
	// seconds. It sets the read-deadline ceiling for tcp/ws/http and the stale window for udp/raw/flux.
	// 0 = the default formula. Clamped to >=2×keepalive, so a very short window needs a lower Keepalive.
	DeadAfterSecs int       `json:"dead_after_secs"`
	Crypto        CryptoCfg `json:"crypto"`

	// Obfs turns on anti-DPI framing: the constant magic byte is dropped, the frame type is folded into
	// the AEAD-sealed plaintext, random padding and keepalive jitter break size and timing fingerprints,
	// and on TCP the length prefix is masked with a PSK-derived keystream. It requires crypto, because
	// both the obfuscation and the probe resistance rely on the AEAD key.
	Obfs bool `json:"obfs"`

	// Cover wraps the TCP transport in a REALITY-style TLS session that fingerprints as Chrome, so the
	// wire looks like ordinary HTTPS. Our client hides a PSK-authenticated token in its ClientHello; the
	// server terminates TLS for us and transparently proxies every OTHER connection to CoverSNI:443, so
	// CoverSNI must be a REAL, reachable, unblocked HTTPS site — it is the cover the server borrows.
	Cover    bool   `json:"cover"`
	CoverSNI string `json:"cover_sni"`

	// WebSocket carrier (Transport=="ws"): the core stream rides RFC 6455 binary frames after an HTTP
	// Upgrade, so it can be fronted through a CDN. WSHost is the Host header and TLS SNI — the fronting
	// domain; WSPath the request path ("/" default); WSTLS makes the client speak wss:// to the edge. The
	// server stays plain, since the CDN terminates TLS. TCP-family; obfs/crypto apply as with tcp.
	WSHost string `json:"ws_host"`
	WSPath string `json:"ws_path"`
	WSTLS  bool   `json:"ws_tls"`
	// SNISplit fragments the wss ClientHello across two TCP segments so the cleartext SNI lands on the
	// segment boundary and a stateless SNI-blocklist DPI cannot match the hostname. It is the ALTERNATIVE
	// to ECH where ECH is unavailable — under ECH the SNI is encrypted, so the split is a no-op. ws/http
	// client + wss only. SplitPos is the offset into the ClientHello (0 = auto: middle of the hostname).
	SNISplit bool `json:"sni_split"`
	SplitPos int  `json:"split_pos"`
	// SNIMode picks how the split is sent; SplitTTL is the disorder head TTL (0 = default):
	//
	//	"split"    (default) two in-order segments
	//	"disorder" also sends the head at a low TTL so it expires in transit and a reassembling DPI sees
	//	           the ClientHello out of order; the kernel retransmits it, so the server gets the real bytes
	//	"fake"     injects a decoy ClientHello with a substituted SNI, killed before the server by a bad
	//	           TCP checksum, so the DPI ingests the decoy and the server never sees it
	SNIMode  string `json:"sni_mode"`
	SplitTTL int    `json:"split_ttl"`
	// CDNCarrier picks the SHAPE the CDN-frontable carrier takes on the wire. All three share the
	// fronting fields (ws_host / ws_tls / ws_ech / ws_path) and differ only in what they send. The server
	// auto-detects the client's style per request and serves h2c, so only the client is told:
	//
	//	"ws"    a WebSocket upgrade — the default; empty means this
	//	"http"  a GET-down + POST-up request pair, which passes a CDN that blocks WebSocket. Short
	//	        discrete POSTs are what a body-buffering CDN still forwards at once
	//	"grpc"  one full-duplex request dressed as a real gRPC call, which a CDN streams to the origin
	//	        over h2c instead of buffering (needs ws_tls)
	CDNCarrier string `json:"cdn_carrier"`
	// HTTPUpWorkers / HTTPUpBatchKB / HTTPUpRate size the POST-ladder upstream (cdn_carrier "http") for
	// the CDN in front: a WAF-protected one needs fewer, larger POSTs or it blocks the source IP.
	// HTTPUpRate is the portable knob — a worker count means a different request rate on a fast path than
	// on a slow one. All zero = compiled defaults.
	HTTPUpWorkers int `json:"http_up_workers"`
	HTTPUpBatchKB int `json:"http_up_batch_kb"`
	HTTPUpRate    int `json:"http_up_rate"`

	// WSECH is a base64 ECHConfigList (RFC 9460 HTTPS-record "ech="). On a wss client it encrypts the
	// real SNI inside the ClientHello, leaving only a benign public name on the wire, so an
	// SNI-blocklisting censor must block the whole CDN IP range to stop it. The node fetches it from the
	// domain's HTTPS DNS record over DoH, since ordinary DNS is often poisoned. Empty = no ECH.
	WSECH string `json:"ws_ech"`

	// WSEdgeIPs / WSEdgeSNIs form a rotation POOL for the ws client: the core cycles (edge-IP × SNI)
	// combinations so no single IP or domain stays exposed long enough to be fingerprinted, and drops a
	// blocked one from rotation. Each SNI carries its own ECH and path. A non-empty WSEdgeIPs overrides
	// the single WSHost/WSECH/peer. WSRotateSecs is the proactive interval (0 = on failure only).
	WSEdgeIPs    []string `json:"ws_edge_ips"`
	WSEdgeSNIs   []WSSNI  `json:"ws_edge_snis"`
	WSRotateSecs int      `json:"ws_rotate_secs"`
	WSAutoBurn   bool     `json:"ws_auto_burn"`
	// WSStatusPath is where the pool writes its live status (active edge + burned
	// IP/SNI lists) so the node/panel can surface and persist auto-burns. Set by main.
	WSStatusPath string `json:"ws_status_path"`

	// StatusPath is the general per-core status file for the connectionless datagram transports
	// (udp/raw/flux): the client writes its precise self-heal event ring here so the node/panel log can
	// surface disconnects and recoveries with a core-observed reason. Empty = off. The ws pool uses
	// WSStatusPath instead, which is how the node tells a pool core apart from a plain datagram one.
	StatusPath string `json:"status_path"`

	// WSWarmStandby keeps a SECOND, fully-handshaked carrier to another pool edge warm in the background
	// (make-before-break), so the active's failure or a proactive rotation promotes it instantly and the
	// TUN never sees a gap. Client + ws edge pool only; default false. The server side — no connect-time
	// eviction, downstream follows data — is always on and safe for a single connection.
	WSWarmStandby bool `json:"ws_warm_standby"`

	// FluxCarrier selects how "flux" frames ride the wire: "udp" (default) sends
	// real UDP datagrams on protocol 17 whose ports rotate each epoch among common
	// QUIC/STUN/WebRTC ports — internet-safe, since transit forwards UDP; "stun"
	// additionally wraps every frame in a real STUN Binding header on STUN/TURN
	// ports, so the flow parses as WebRTC signalling; "raw" rotates the IP protocol
	// number itself among an experimental pool, which is stealthier but only survives
	// where those protocols reach the peer (same-segment / L2-adjacent / a cooperative
	// datacenter), not across the open internet. Empty defaults to "udp".
	FluxCarrier string `json:"flux_carrier"`

	// FluxShape is the statistical size profile the carrier mimics: "random"
	// (default), "quic", "video", or "webrtc". It shapes the padding budget of small
	// control frames (keepalives) — the most fingerprintable fixed-size packets — so
	// their size histogram resembles the mimicked traffic. Coarse shaping only: it
	// adds no latency and no MTU cost.
	FluxShape string `json:"flux_shape"`

	// FluxEpochOffset manually advances the shape epoch ("rotate now"): the effective
	// epoch is floor(unixtime / FluxRotateSecs) + FluxEpochOffset. Both ends must
	// carry the same offset (the panel sets it on both on a "rotate now"), which moves
	// the target fleet-wide with no wire signal. 0 = follow the clock only.
	FluxEpochOffset int64 `json:"flux_epoch_offset"`

	// FluxRotateSecs is the epoch length for the "flux" transport: every
	// floor(unixtime / FluxRotateSecs) the carrier shape (protocol/ports and the
	// padding budget, later size/timing) rotates. Both ends derive the shape from
	// HKDF(PSK, epoch) off their own clocks, so rotation needs NO packet on the
	// wire; a few-epoch grace window absorbs clock skew. 0 defaults to 600.
	FluxRotateSecs int `json:"flux_rotate_secs"`

	// Fec turns on forward error correction on the datagram carriers. Data frames are grouped into blocks
	// of FecData shards with FecParity parity shards alongside, and the receiver reconstructs up to
	// FecParity lost shards per block WITHOUT a retransmit, so a high-loss link stays usable instead of
	// collapsing the inner TCP. It costs FecParity/FecData extra bandwidth. Both ends must match.
	Fec bool `json:"fec"`

	// FecData / FecParity are the block geometry: FecData data shards per block,
	// FecParity parity shards. E.g. 10/3 = "10 + 3" (30% overhead, recovers up to 3
	// of every 13). Defaults 10/3 when Fec is on. Constraint: FecData>=1, FecParity>=1,
	// FecData+FecParity<=255.
	FecData   int `json:"fec_data"`
	FecParity int `json:"fec_parity"`

	// FakeDesync (client; raw/flux/tcp/ws only) emits FakeCount decoy packets to the peer just before
	// each handshake to mis-sync a stateful DPI. A low-TTL decoy expires before the server, a
	// bad-checksum one is dropped by its IP stack — either way the DPI ingests it and mis-tracks the flow
	// while the AEAD session is untouched. Plain udp has no hook. Needs CAP_NET_RAW.
	FakeDesync bool   `json:"fake_desync"`
	FakeTTL    int    `json:"fake_ttl"`   // low-TTL decoy hop budget (default 4)
	FakeCount  int    `json:"fake_count"` // decoys per handshake (default 2)
	FakeMode   string `json:"fake_mode"`  // "ttl" (default) | "badsum" | "both"

	// GSO opens the TUN with a virtio-net header and TCP/UDP segmentation offload, so the kernel hands
	// the core large super-packets on bulk transfers instead of many MTU-sized ones — fewer syscalls and
	// copies, higher throughput. A local optimization only: the wire format is unchanged and each side
	// can enable it independently. Linux only.
	GSO bool `json:"gso"`

	// Tuning carries the operator-tunable operational timing knobs (pool health FSM, dead-detection
	// windows, rotation default). Optional: any zero/empty field leaves the compiled-in default. The
	// packet layer applies these once at startup (packet.ApplyTuning) — safe because one core process
	// serves one tunnel. nil = all defaults.
	Tuning *TuningCfg `json:"tuning"`
}

// TuningCfg is the JSON shape of the config's `tuning` object. Every field is optional (zero/empty =
// keep default); the packet layer clamps each to a sane range before applying it.
type TuningCfg struct {
	SuspectBackoff      []int64 `json:"suspect_backoff"`        // retest schedule (secs) for a suspect pool entry
	DeadRetestSecs      int64   `json:"dead_retest_secs"`       // slow retest interval (secs) for a dead entry
	IdleMult            int64   `json:"idle_mult"`              // ws/tcp read deadline = mult × keepalive
	IdleMinSecs         int64   `json:"idle_min_secs"`          // …floored at this many seconds
	SessionStaleMult    int64   `json:"session_stale_mult"`     // udp/raw/flux stale window = mult × keepalive
	SessionStaleMinSecs int64   `json:"session_stale_min_secs"` // …floored at this many seconds
	PingLossThreshold   int     `json:"ping_loss_threshold"`    // unanswered keepalives before a client closes
	MinLivenessSecs     int64   `json:"min_liveness_secs"`      // shortest session that still counts as healthy
	ProbeTimeoutSecs    int64   `json:"probe_timeout_secs"`     // per-edge reachability probe timeout
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

func (c *Config) applyDefaults() {
	if c.MTU <= 0 { // <=0 (not just ==0): a negative MTU would reach `ip link set … mtu N` and fail
		c.MTU = 1400
	}
	if c.Keepalive <= 0 { // <=0: a negative keepalive makes jitter() fire immediately -> ping busy-loop
		c.Keepalive = 15
	}
	if c.SockBuf == 0 { // 0 = pick the default; a negative value means "leave the kernel default" (off)
		c.SockBuf = 4 << 20 // 4 MiB
	}
	if c.SockBuf > 64<<20 { // cap the pin so a typo can't reserve absurd kernel memory
		c.SockBuf = 64 << 20
	}
	if c.Crypto.Cipher == "" {
		c.Crypto.Cipher = "aes-256-gcm"
	}
	if c.Transport == "" {
		c.Transport = "udp"
	}
	// A destination rotation pool OWNS the dial target: seed the single Peer from the pool's first entry
	// so the initial dial and the pool's starting endpoint always agree — otherwise a fail() at cur=0
	// burns the wrong entry and the mismatched Peer is dropped on the first rotation. The pool is
	// authoritative, so this overrides any Peer the caller also set.
	if len(c.PeerIPs) > 0 {
		c.Peer = c.PeerIPs[0]
	}
	if c.Transport == "raw" && c.RawProfile == "" {
		c.RawProfile = "bare"
	}
	if c.Transport == "flux" {
		if c.FluxRotateSecs == 0 {
			// Resolve the flux epoch to a concrete default HERE so both ends compute the same epoch and
			// fluxEpochAt cannot divide by zero. The panel always sends an explicit per-tunnel
			// flux_rotate_secs; 600 is the fallback for a config that omits it.
			c.FluxRotateSecs = 600
		}
		if c.FluxCarrier == "" {
			c.FluxCarrier = "udp"
		}
		if c.FluxShape == "" { // '' already means random in the carrier; make it explicit so the startup log prints "random" not blank
			c.FluxShape = "random"
		}
	}
	if c.Fec { // FEC defaults apply on any datagram carrier that has it enabled
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
	if c.FakeDesync { // fake-packet desync defaults (raw/flux client)
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

// validatePoolEndpoint checks one rotation-pool entry (field names it for the error). The pool swaps
// the endpoint with no DNS step, so every entry must be a literal IP. With needPort (the udp/tcp
// DESTINATION) it is "ip:port" — the host must be an IP and the port valid; otherwise (raw/flux
// destinations, and every SOURCE IP) it is a bare IPv4 — an accidental ":port" is tolerated/dropped.
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
	if h, _, err := net.SplitHostPort(e); err == nil { // tolerate an accidental ip:port
		host = h
	}
	if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
		return errors.New(field + " entry " + strconv.Quote(e) + " must be an IPv4 address")
	}
	return nil
}

// rawProtoBorrowed refuses an outer protocol number that some raw PROFILE owns. It applies to the two
// headerless carriers that can set one — bare and spoof — and to nothing else.
//
// Neither writes an L4 header, so the outer IP header announcing (say) TCP leaves ciphertext exactly
// where the TCP header belongs: a different random port pair on every packet, no SYN any stateful box
// ever saw, a checksum that cannot verify. The flow is dropped in the PATH, which reaches the operator
// as unexplained packet loss rather than as an error. The owning profile exists precisely because it
// forges that header too, so the message names it.
func rawProtoBorrowed(proto int) error {
	owner, taken := packet.RawProfileOwning(proto)
	if !taken || owner == "bare" { // bare's own native number is not a borrowed one
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
		// Only the tcp and udp servers ever READ listen_ips; raw, flux, ws and dns are given cfg.Listen
		// alone. Accepting it elsewhere validates a bind list the data path then discards, so the server
		// binds ONE address while its config, its status file and the panel all describe a pool. raw cannot
		// honour it at all: a bound AF_INET raw socket is demuxed by DESTINATION.
		if len(c.ListenIPs) > 0 && c.Transport != "" && c.Transport != "udp" && c.Transport != "tcp" {
			return errors.New("listen_ips is read only by the udp and tcp servers; transport \"" + c.Transport + "\" binds \"listen\" alone")
		}
		for _, la := range c.ListenIPs { // pooled server: each bind must be a valid IP:port (we bind these directly)
			if err := validatePoolEndpoint("listen_ips", la, true); err != nil { // same ip:port check as a dest pool entry
				return err
			}
		}
	case "client":
		// The dns carrier has no "peer": the client queries recursive resolvers (dns_resolvers),
		// never the server IP — that is the whole point. Its endpoint is validated in the dns case.
		if c.Transport != "dns" && c.Peer == "" && len(c.PeerIPs) == 0 {
			return errors.New("client role requires \"peer\" (or a peer_ips rotation pool)")
		}
	default:
		return errors.New("role must be \"server\" or \"client\"")
	}
	if c.BindIP != "" && net.ParseIP(c.BindIP) == nil {
		return errors.New("bind_ip must be a valid IP address")
	}
	if c.DeadAfterSecs != 0 && (c.DeadAfterSecs < 10 || c.DeadAfterSecs > 300) {
		return errors.New("dead_after_secs must be 0 (default) or between 10 and 300")
	}
	switch c.Transport {
	case "", "udp", "tcp":
		// ok ("" defaults to udp in applyDefaults)
	case "raw":
		if c.RawProfile != "" && !packet.RawProfileValid(c.RawProfile) {
			return errors.New("raw_profile must be one of " + strings.Join(packet.RawProfileNames(), "|"))
		}
		// rawEffProto honours raw_proto for the "bare" profile ONLY — every other profile's number is
		// tied to its forged L4 header. Left unchecked the value validates, persists and shows as set while
		// the wire keeps the native number: a protocol-whitelist evasion the operator believes is on and is
		// not. RawProfile "" is bare here, since validate() runs BEFORE applyDefaults.
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
		// raw_port is the mirror rule: only the profiles that FORGE ports have one to override. Left
		// unchecked it would validate, persist and read as set while the wire keeps 443 — the same silent
		// no-op raw_proto used to be on the wrong profile.
		if c.RawPort != 0 {
			if !packet.RawProfileHasPorts(c.RawProfile) {
				return errors.New("raw_port sets the forged server port of the \"udp\" and \"tcp\" profiles only" +
					" (raw_profile \"" + c.RawProfile + "\" forges no ports)")
			}
			if c.RawPort < 1 || c.RawPort > 65535 {
				return errors.New("raw_port must be in 1..65535 (0 = the profile default 443)")
			}
		}
		// Same rule for the same reason: a profile with no ports has no source port to roll, and
		// accepting it would persist and read back as set while the wire never changed.
		if c.RawSportRandom && !packet.RawProfileHasPorts(c.RawProfile) {
			return errors.New("raw_sport_random rolls the forged SOURCE port of the \"udp\" and \"tcp\"" +
				" profiles only (raw_profile \"" + c.RawProfile + "\" forges no ports)")
		}
		if !c.Crypto.Enabled {
			return errors.New("raw transport requires crypto enabled (the AEAD both encrypts and authenticates each raw packet)")
		}
	case "spoof":
		// Standalone IP-spoofing carrier: a bare-like raw-IP datapath that forges the outer source
		// and/or destination. NO rotation of any kind. Crypto is mandatory (the AEAD authenticates
		// every forged-header frame, and there is no other integrity on a raw IP packet). rawProto
		// (1..255) overrides the outer IP protocol number like a bare carrier does.
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
		// spoof is headerless by definition, so it has no forged port to override. Accepting raw_port
		// here would be the silent no-op the raw case refuses: it validates, persists and reads back as
		// set while nothing on the wire changes.
		if c.RawPort != 0 {
			return errors.New("raw_port sets a forged L4 port, and the spoof carrier writes no L4 header at all")
		}
		if c.RawSportRandom {
			return errors.New("raw_sport_random rolls a forged L4 source port, and the spoof carrier writes no L4 header at all")
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
			// The client is the one that forges. A carrier that forges nothing is just raw bare.
			if c.SpoofSrc == "" && c.SpoofDst == "" {
				return errors.New("spoof transport requires at least one of spoof_src_ip / spoof_dst_ip on the client")
			}
		case "server":
			// The client's real IP is never on the wire (its source is forged, or a decoy dst hides
			// the flow), so the server must be told where to reply.
			if c.RealPeer == "" {
				return errors.New("spoof server requires real_peer_ip (the client's real IP to reply to)")
			}
		}
	case "flux":
		// The polymorphic carrier rides raw sockets and rotates its protocol from
		// the AEAD-shared key; without crypto there is no key to derive a shape from
		// and no authentication for the shape-independent decode.
		if !c.Crypto.Enabled {
			return errors.New("flux transport requires crypto enabled (the shape is derived from the PSK and the AEAD authenticates every frame)")
		}
		if c.FluxRotateSecs < 0 {
			return errors.New("flux_rotate_secs must be >= 0 (0 defaults to 600)")
		}
		switch c.FluxCarrier {
		case "", "udp", "raw", "stun":
		default:
			return errors.New("flux_carrier must be \"udp\", \"stun\", or \"raw\"")
		}
		switch c.FluxShape {
		case "", "random", "quic", "video", "webrtc":
		default:
			return errors.New("flux_shape must be \"random\", \"quic\", \"video\", or \"webrtc\"")
		}
	case "dns":
		// DNS-tunnel carrier (last resort under a full protocol+destination whitelist). The reliable
		// session rides inside DNS; crypto is mandatory — the handshake authenticates with the PSK and
		// every datagram is AEAD-sealed. The server is the delegated zone's authoritative NS (binds
		// Listen, e.g. ":53"); the client queries recursive resolvers listed in DNSResolvers.
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
		// WebSocket carrier. Client-side TLS to a CDN edge needs an SNI/Host, so
		// ws_tls requires ws_host; the server side (plain, behind the CDN) needs neither.
		// A rotating edge POOL carries its own per-SNI hosts (WSEdgeSNIs) instead of a
		// single WSHost, so ws_host is not required when a pool is configured.
		if c.WSTLS && c.Role == "client" && c.WSHost == "" && len(c.WSEdgeIPs) == 0 {
			return errors.New("ws_tls requires ws_host (the TLS SNI / fronting domain)")
		}
		// ECH hides the SNI, so it only makes sense on a wss client (it is carried in
		// the TLS ClientHello). Reject a config that asks for ECH without wss, and make
		// sure the supplied ECHConfigList actually decodes.
		if c.WSECH != "" {
			if !c.WSTLS || c.Role != "client" {
				return errors.New("ws_ech requires ws_tls on a client")
			}
			if _, err := base64.StdEncoding.DecodeString(c.WSECH); err != nil {
				return errors.New("ws_ech is not valid base64")
			}
		}
		// SNI fragmentation splits the wss ClientHello, so it needs wss on a client. split_pos is a byte
		// offset into the ClientHello (0 = auto: middle of the hostname), capped so a runaway value cannot
		// push the split past a plausible ClientHello. The upstream shape only exists on an http-carrier
		// client, so it is rejected elsewhere rather than stored doing nothing.
		if c.HTTPUpWorkers != 0 || c.HTTPUpBatchKB != 0 || c.HTTPUpRate != 0 {
			if c.Role != "client" || c.CDNCarrier != "http" {
				return errors.New("http_up_workers/http_up_batch_kb/http_up_rate apply to an http-carrier CLIENT only")
			}
			if c.HTTPUpWorkers < 0 || c.HTTPUpWorkers > 16 {
				return errors.New("http_up_workers must be between 1 and 16 (0 = default)")
			}
			// The message used to name 8 as the floor while the predicate accepted 1..7, which
			// SetHTTPUpstream then raises to 8 (tclamp). The clamp is the safe direction and rejecting a
			// working config to satisfy a sentence would be the wrong trade, so the sentence is what
			// changes: say the range that is actually enforced, and say what happens below 8.
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
			// The disorder head exists to EXPIRE in transit. A hop budget the peer can be reached
			// with makes it arrive whole, so the mode silently becomes a plain split while the
			// panel, the node and this core all keep reporting disorder.
			if c.SplitTTL < 0 || c.SplitTTL > packet.MaxHopBudget {
				return fmt.Errorf("split_ttl must be between 0 and %d (0 = default); above that the "+
					"disorder head reaches the server and the mode is a no-op", packet.MaxHopBudget)
			}
		}
		// httpc upstream style: post (default) or grpc. grpc is a single full-duplex
		// request and needs HTTP/2 to the edge, so on a single-edge client it requires ws_tls
		// (a pool is always wss; the server auto-detects).
		switch c.CDNCarrier {
		case "", "ws", "http", "grpc":
		default:
			return errors.New("cdn_carrier must be \"ws\", \"http\" or \"grpc\"")
		}
		if c.CDNCarrier == "grpc" && c.Role == "client" && !c.WSTLS && len(c.WSEdgeIPs) == 0 {
			return errors.New("cdn_carrier \"" + c.CDNCarrier + "\" requires ws_tls (needs HTTP/2 to the edge)")
		}
		// ws_rotate_secs is the proactive edge-rotation interval, and it was the one rotation knob with
		// no check at all — peer_rotate_secs and flux_rotate_secs are both range-checked. A negative
		// value reached main.go as a negative Duration and tcp.go's `if b.rotate > 0` then skipped the
		// rotation ticker outright, so the tunnel came up healthy and simply never rotated its edge.
		if c.WSRotateSecs < 0 {
			return errors.New("ws_rotate_secs must be >= 0 (0 = rotate only on a failed edge)")
		}
		// Edge pool: a client+wss rotation set; every SNI's ECH must decode.
		if len(c.WSEdgeIPs) > 0 || len(c.WSEdgeSNIs) > 0 {
			if c.Role != "client" || !c.WSTLS {
				return errors.New("ws edge pool requires ws_tls on a client")
			}
			if len(c.WSEdgeIPs) == 0 || len(c.WSEdgeSNIs) == 0 {
				return errors.New("ws edge pool needs at least one edge IP and one SNI")
			}
			// Every edge is dialed directly as "ip:port" with no DNS step, exactly like the other
			// rotation pools — so validate the literal IP+port here instead of letting a malformed/
			// hostname entry reach the data plane and silently burn the edge.
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
	// PeerIPs is the DESTINATION rotation pool for the direct transports — a client-side dial-layer
	// feature, so it is meaningless on a server (which listens) and on ws (which has its own edge pool).
	// Each entry must be a literal IP the pool can swap to with no DNS step: "ip:port" for udp/tcp, a
	// bare IPv4 for raw/flux. The single Peer is still allowed alongside it.
	if len(c.PeerIPs) > 0 {
		if c.Role != "client" {
			return errors.New("peer_ips is a client rotation pool (a server listens, it does not dial)")
		}
		switch c.Transport {
		case "", "udp", "tcp", "raw", "flux":
		default:
			return errors.New("peer_ips is only for the direct transports (udp, tcp, raw, flux) — ws has its own edge pool")
		}
		// udp/tcp dial "ip:port"; raw/flux address a bare IPv4 (parseIP4 rejects v6 and a hostname).
		needPort := c.Transport != "raw" && c.Transport != "flux"
		for _, e := range c.PeerIPs {
			if err := validatePoolEndpoint("peer_ips", e, needPort); err != nil {
				return err
			}
		}
	}
	// SrcIPs is the client-side SOURCE rotation pool (the node's own IPs). Same scoping as PeerIPs, but
	// every entry is a bare IPv4 regardless of carrier (a source is never "ip:port").
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
		// peer_src_ips is the SERVER's copy of the client's source pool (raw/flux only). Validate it like
		// src_ips so a typo fails the config load loudly instead of being silently dropped in
		// SetPeerSources — a dropped source would re-strand the tunnel on the client's next rotation.
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
	// The dns carrier has no obfs framing: ListenDNS/DialDNS take no obfs flag and nothing in
	// internal/dnstun references it, while every OTHER carrier is handed cfg.Obfs. Left unchecked,
	// obfs+dns validates, persists and shows as enabled while doing nothing — false assurance that
	// anti-DPI framing is running, on the most sensitive carrier there is.
	if c.Obfs && c.Transport == "dns" {
		return errors.New("obfs is not supported on the dns transport (the DNS carrier has no obfs framing)")
	}
	if c.Fec {
		// FEC repairs lost datagrams from parity — it only makes sense on the datagram
		// carriers (udp / raw / flux / spoof). On tcp/ws the stream is already reliable, so FEC
		// there is wasted bandwidth that fights TCP's own retransmit/congestion control.
		switch c.Transport {
		case "", "udp", "raw", "flux", "spoof":
		default:
			// Name the carrier the operator actually configured. The old text listed "tcp/ws" only, so a
			// dns tunnel was rejected by a message that never mentioned dns — and the operator reasonably
			// concluded the error belonged to some other tunnel.
			return fmt.Errorf("fec is not supported on the %s carrier — only on the datagram carriers (udp, raw, flux, spoof)", c.Transport)
		}
		if c.FecData < 0 || c.FecParity < 0 {
			return errors.New("fec_data / fec_parity must be >= 0 (0 defaults to 10 / 3)")
		}
		// Validate the EFFECTIVE geometry — the same defaulting applyDefaults() will do AFTER validate()
		// runs. Checking the raw values would let fec_data=254 with fec_parity omitted pass and then become
		// 257, which the codec rejects (n+k<=256), so newFecPair silently disables FEC even though the
		// operator asked for it. An out-of-range request must be a clean config error, not silence.
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
		// ...and the receiver has to be able to REPAIR the block, which the sum rule says nothing about. The
		// decoder delivers intact shards on arrival and recovered ones last, so a repaired frame reaches the
		// AEAD up to blocksize-1 sequences behind the newest — and the replay guard refuses anything a full
		// window behind. Past that, the parity costs its full bandwidth and repairs nothing.
		if ed > packet.MaxFecData {
			return fmt.Errorf("fec_data must be at most %d: above that a parity-recovered frame lands outside the receiver's replay window and is discarded, so FEC would cost its full bandwidth and repair nothing", packet.MaxFecData)
		}
	}
	if c.FakeDesync {
		// Desync is delivered two ways: raw/flux/spoof build the whole IPv4 header, so they forge decoy
		// packets directly; tcp/ws own a kernel TCP connection, so they INJECT decoy TCP segments
		// on its 4-tuple via AF_PACKET (see tcp_inject_linux.go). Plain udp has no such hook. It is
		// a client-side mechanism; a server that carries the same fields simply ignores them.
		switch c.Transport {
		case "raw", "flux", "spoof", "tcp", "ws":
		default:
			return errors.New("fake_desync is supported on the raw, flux, spoof, tcp and ws carriers (not plain udp)")
		}
		// ws is only half true: the injector mirrors the connection's real 4-tuple, and an httpc session has
		// no single kernel socket to mirror — its conn is synthetic, so the *net.TCPAddr assertion fails and
		// nothing is emitted. Accepting the flag there means desync is stored, forwarded and logged as ON
		// while not one decoy ever leaves the box.
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
		// "both" alternates ttl/badsum decoys (specs(): even index ttl, odd index badsum), so a single
		// decoy is ONLY the ttl half — the badsum half never fires. That silently drops half the defence
		// the operator asked for, so require at least two. (fake_count 0 defaults to 2, so only an
		// explicit 1 is rejected.)
		if c.FakeMode == "both" && c.FakeCount == 1 {
			return errors.New("fake_mode \"both\" needs fake_count >= 2 (one decoy cannot be both a low-TTL and a bad-checksum packet)")
		}
	}
	if c.Cover && c.Transport != "tcp" {
		return errors.New("cover (TLS) requires transport \"tcp\"")
	}
	// The REALITY ClientHello auth token is keyed on the PSK (deriveKey/authKey over
	// the PSK); with crypto off the token is derived over an empty key, so any observer
	// could forge it. Require crypto so the cover token is actually authenticated.
	if c.Cover && !c.Crypto.Enabled {
		return errors.New("cover (TLS) requires crypto enabled (the REALITY auth token is keyed on the PSK)")
	}
	if c.Cover && c.CoverSNI == "" {
		return errors.New("cover (TLS) requires cover_sni (the SNI to present)")
	}
	return nil
}
