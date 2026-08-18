package main

import (
	"encoding/json"
	"testing"
)

func FuzzConfig(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"role":"client","mode":"packet","profile":"core"}`))
	f.Add([]byte(`{"role":"server","peer_ips":[],"listen_ips":["1.2.3.4:443"]}`))
	f.Add([]byte(`{"role":"client","peer_ips":["1.2.3.4:443","5.6.7.8:443"],"ws_edge_ips":["9.9.9.9"]}`))
	f.Add([]byte(`{"tuning":{"dead_mult":999},"ws_rotate_secs":-1,"keepalive_secs":0}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var c Config
		if err := json.Unmarshal(data, &c); err != nil {
			return
		}
		c.applyDefaults()
		_ = c.validate()
	})
}
