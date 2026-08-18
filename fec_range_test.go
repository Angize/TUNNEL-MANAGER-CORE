package main

import "testing"

func TestFecDataBoundedByTheReplayWindow(t *testing.T) {
	base := func(fd, fp int) *Config {
		return &Config{
			Mode: "packet", Profile: "core", Role: "client", Peer: "198.51.100.7:51820",
			TunAddr: "10.9.0.2/30", Transport: "udp", Crypto: CryptoCfg{Enabled: true, PSK: "x", Cipher: "aes-256-gcm"},
			Fec: true, FecData: fd, FecParity: fp,
		}
	}
	for _, tc := range []struct {
		fd, fp int
		ok     bool
		why    string
	}{
		{10, 3, true, "the shipped default"},
		{64, 3, true, "the largest block whose parity still lands inside the replay window"},
		{65, 3, false, "one past it: every recovered frame is discarded as too old"},
		{200, 3, false, "well past it, and comfortably inside the fec_data+fec_parity<=255 rule"},
	} {
		err := base(tc.fd, tc.fp).validate()
		if tc.ok && err != nil {
			t.Errorf("fec_data=%d (%s) was refused: %v", tc.fd, tc.why, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("fec_data=%d (%s) was ACCEPTED — the sum rule lets it through, and then every parity-recovered frame is silently discarded by the replay guard: full FEC bandwidth, zero repair", tc.fd, tc.why)
		}
	}
}
