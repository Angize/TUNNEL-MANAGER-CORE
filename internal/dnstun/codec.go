package dnstun

import (
	"encoding/base32"
	"errors"
	"strings"
)

var lowB32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

const (
	maxLabel = 63
	maxName  = 255
	maxTXT   = 255

	nonceLen = 8
)

const nonceWire = 1 + nonceLen

var (
	errTooBig   = errors.New("dns codec: datagram exceeds one-message capacity")
	errBadName  = errors.New("dns codec: query name not under the zone")
	errBadNonce = errors.New("dns codec: nonce label empty or too long")
)

type Codec struct {
	zone  string
	maxUp int
}

func NewCodec(zone string) (*Codec, error) {
	z := strings.ToLower(strings.TrimSpace(zone))
	z = strings.TrimSuffix(z, ".")
	if z == "" {
		return nil, errors.New("dns codec: empty zone")
	}
	for _, lbl := range strings.Split(z, ".") {
		if lbl == "" || len(lbl) > maxLabel {
			return nil, errors.New("dns codec: malformed zone label (empty or too long)")
		}
	}
	c := &Codec{zone: z + "."}
	c.maxUp = c.computeMaxUpstream()
	if c.maxUp < 16 {
		return nil, errors.New("dns codec: zone too long, no room for tunnel data")
	}
	return c, nil
}

func (c *Codec) MaxUpstream() int { return c.maxUp }

func (c *Codec) Zone() string { return c.zone }

var ErrBareZone = errors.New("dns codec: bare-zone query (no nonce label)")

func zoneWireLen(zone string) int {
	n := 1
	for _, lbl := range strings.Split(strings.TrimSuffix(zone, "."), ".") {
		if lbl != "" {
			n += 1 + len(lbl)
		}
	}
	return n
}

func (c *Codec) computeMaxUpstream() int {
	dataWire := maxName - zoneWireLen(c.zone) - nonceWire
	if dataWire <= 0 {
		return 0
	}

	chars := 0
	for {
		next := chars + 1
		if next+(next+maxLabel-1)/maxLabel > dataWire {
			break
		}
		chars = next
	}
	return chars * 5 / 8
}

func (c *Codec) EncodeName(data []byte, nonce string) (string, error) {
	if len(data) > c.maxUp {
		return "", errTooBig
	}
	if nonce == "" || len(nonce) > maxLabel {
		return "", errBadNonce
	}
	var b strings.Builder
	b.WriteString(nonce)
	b.WriteByte('.')
	s := lowB32.EncodeToString(data)
	for len(s) > 0 {
		n := len(s)
		if n > maxLabel {
			n = maxLabel
		}
		b.WriteString(s[:n])
		b.WriteByte('.')
		s = s[n:]
	}
	b.WriteString(c.zone)
	return b.String(), nil
}

func (c *Codec) DecodeName(name string) ([]byte, error) {
	nl := normName(name)

	if nl != c.zone && !strings.HasSuffix(nl, "."+c.zone) {
		return nil, errBadName
	}
	prefix := strings.TrimSuffix(nl[:len(nl)-len(c.zone)], ".")
	if prefix == "" {

		return nil, ErrBareZone
	}
	labels := strings.Split(prefix, ".")
	data := labels[1:]
	if len(data) == 0 {
		return []byte{}, nil
	}
	return lowB32.DecodeString(strings.Join(data, ""))
}

func (c *Codec) EncodeTXT(data []byte) []string {
	if len(data) == 0 {
		return []string{""}
	}
	var out []string
	for len(data) > 0 {
		n := len(data)
		if n > maxTXT {
			n = maxTXT
		}
		out = append(out, string(data[:n]))
		data = data[n:]
	}
	return out
}

func (c *Codec) DecodeTXT(txt []string) []byte {
	var out []byte
	for _, s := range txt {
		out = append(out, s...)
	}
	return out
}
