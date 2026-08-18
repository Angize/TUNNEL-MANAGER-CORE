package dnstun

import "encoding/hex"

type ClientID [8]byte

func (c ClientID) Network() string { return "clientid" }

func (c ClientID) String() string { return hex.EncodeToString(c[:]) }
