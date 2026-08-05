package packet

// SpoofProbe reports whether this host can run IP spoofing for the raw bare transport. It is a LOCAL
// capability check only: it does NOT prove the upstream network will forward a forged source, since a
// datacenter may still drop spoofed egress (BCP38), which only shows up once a real tunnel fails.
type SpoofProbe struct {
	OK        bool   `json:"ok"`          // CapNetRaw && AFPacket
	CapNetRaw bool   `json:"cap_net_raw"` // can open an IP_HDRINCL raw socket (forge headers)
	AFPacket  bool   `json:"af_packet"`   // can open an AF_PACKET socket (receive decoy dst)
	Reason    string `json:"reason"`      // why OK is false (empty when OK)
}
