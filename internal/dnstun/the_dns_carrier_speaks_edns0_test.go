package dnstun

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A real stub resolver puts an EDNS0 OPT record in every query, advertising the UDP payload size it can
// accept; a real authoritative server echoes one back. The carrier sent neither -- a TXT query with an
// empty additional section and no OPT is a shape almost no genuine resolver produces, and it was identical
// on every query the tunnel ever sent. Both the query and the response now carry an OPT.
func optOf(t *testing.T, msg []byte) (dnsmessage.ResourceHeader, bool) {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	for _, r := range m.Additionals {
		if r.Header.Type == dnsmessage.TypeOPT {
			return r.Header, true
		}
	}
	return dnsmessage.ResourceHeader{}, false
}

func TestTheDNSCarrierSpeaksEDNS0(t *testing.T) {
	q, err := buildQuery(0x1234, "abc.example.com.")
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	h, ok := optOf(t, q)
	if !ok {
		t.Fatal("the query carries no EDNS0 OPT record")
	}
	if h.Class != ednsUDPSize {
		t.Errorf("query OPT advertises UDP size %d, want %d", h.Class, ednsUDPSize)
	}

	name, nerr := dnsmessage.NewName("abc.example.com.")
	if nerr != nil {
		t.Fatal(nerr)
	}
	resp, rerr := buildResponse(0x1234, name, dnsmessage.TypeTXT,
		[]dnsmessage.Resource{txtResource(name, []string{"payload"})}, nil)
	if rerr != nil {
		t.Fatalf("buildResponse: %v", rerr)
	}
	if _, ok := optOf(t, resp); !ok {
		t.Fatal("the response carries no EDNS0 OPT record")
	}

	// the OPT in the additional section must not disturb the TXT read the tunnel depends on
	out, perr := parseResponseTXT(resp, 0x1234)
	if perr != nil {
		t.Fatalf("parseResponseTXT: %v", perr)
	}
	if string(out) != "payload" {
		t.Fatalf("TXT read got %q, want payload", out)
	}

	// and the server still reads the question out of a query that now has an OPT of its own
	id, qn, qt, ok := parseQuery(q)
	if !ok || id != 0x1234 || qt != dnsmessage.TypeTXT || qn != "abc.example.com." {
		t.Fatalf("parseQuery on an EDNS0 query: id=%d name=%q type=%v ok=%v", id, qn, qt, ok)
	}
}
