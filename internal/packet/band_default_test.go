package packet

// The band is per-tunnel now, so there is no package constant to reach for. Everything that was
// written against the old fixed band is asking about the DEFAULT band, which is what a tunnel that
// says nothing gets, so that is what these name. A test that wants a different band builds its own
// rotPerm with sportBand(lo, hi).
const (
	sportBandLo   = SportBandLoDefault
	sportBandSpan = SportBandHiDefault - SportBandLoDefault + 1
)

func testPerm(psk string, isClient bool) rotPerm {
	return rotPermFrom(psk, isClient, sportBandLo, sportBandSpan)
}
