package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The panel offers a timing knob, the node writes it into the config file, and the core is supposed to
// read it. Two silent ways that chain breaks, and neither shows up anywhere: a json tag that no longer
// spells what the node writes, and a field added to TuningCfg but never copied into the packet layer's
// input. Either one leaves the core on its compiled-in default while Settings shows the operator a
// number that travelled the whole way and was then dropped.
//
// Reflection on purpose: naming the knobs here would only pin the ones someone remembered to add.
func TestEveryTuningKnobReachesThePacketLayer(t *testing.T) {
	// Exactly the keys the node's _core_tuning emits, with values nothing else would produce.
	raw := []byte(`{"tuning":{
		"suspect_backoff":  [11, 22],
		"dead_retest_secs":  33,
		"min_liveness_secs": 44,
		"ladder_revive":    [55, 66]
	}}`)

	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("the config the node writes does not parse: %v", err)
	}
	if c.Tuning == nil {
		t.Fatal("the tuning object did not unmarshal at all")
	}

	cv := reflect.ValueOf(*c.Tuning)
	for i := 0; i < cv.NumField(); i++ {
		if cv.Field(i).IsZero() {
			t.Errorf("TuningCfg.%s stayed zero: its json tag no longer spells the key the node writes, "+
				"so the operator's value is dropped between the file and the struct",
				cv.Type().Field(i).Name)
		}
	}

	iv := reflect.ValueOf(tuningFrom(c.Tuning))
	for i := 0; i < iv.NumField(); i++ {
		if iv.Field(i).IsZero() {
			t.Errorf("TuningInput.%s stayed zero: tuningFrom does not carry it, so the knob reaches the "+
				"core and is then never handed to the packet layer", iv.Type().Field(i).Name)
		}
	}

	// The two structs must also stay the same SIZE. A knob added to the packet layer's input and never
	// given a config field would pass both loops above by simply not existing on this side.
	if cv.NumField() != iv.NumField() {
		t.Errorf("TuningCfg has %d knobs and TuningInput has %d -- one side grew a knob the other cannot "+
			"carry", cv.NumField(), iv.NumField())
	}
}
