package main

import "testing"

// fec_data has an upper bound the sum rule (fec_data+fec_parity<=255) says nothing about: the
// RECEIVER has to be able to repair the block.
//
// The decoder delivers intact data shards on arrival and parity-recovered ones last, so a repaired
// frame reaches the AEAD up to blocksize-1 sequence numbers behind the newest one already delivered
// — and the replay guard refuses anything a full window behind as too old to prove it is not a
// replay. Past that size the parity is computed, transmitted, reconstructed and then discarded:
// FEC costs its full bandwidth and repairs nothing, in silence, for the life of the tunnel.
//
// Measured on the guard itself before this bound was written: 63 and 64 recover, 65 and above do not.
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
