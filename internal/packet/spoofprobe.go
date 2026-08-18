package packet

type SpoofProbe struct {
	OK        bool   `json:"ok"`
	CapNetRaw bool   `json:"cap_net_raw"`
	AFPacket  bool   `json:"af_packet"`
	Reason    string `json:"reason"`
}
