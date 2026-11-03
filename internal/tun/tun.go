package tun

import "errors"

var ErrGSOUnsupported = errors.New("the gso-specific part of the tun open failed")
