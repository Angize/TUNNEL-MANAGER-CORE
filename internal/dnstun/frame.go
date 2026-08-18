package dnstun

import (
	"encoding/binary"
	"errors"
	"io"
)

var errFrameTooLong = errors.New("dns frame: packet exceeds 65535 bytes")

func WritePacket(w io.Writer, pkt []byte) error {
	if len(pkt) > 0xFFFF {
		return errFrameTooLong
	}
	out := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(out[:2], uint16(len(pkt)))
	copy(out[2:], pkt)
	_, err := w.Write(out)
	return err
}

func ReadPacket(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
