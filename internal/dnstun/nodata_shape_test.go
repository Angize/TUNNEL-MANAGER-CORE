package dnstun

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestApexAnswersLookLikeAnOrdinaryNODATA pins the SHAPE of the answer, which the drain fix never
// looked at.
//
// That fix reasoned only about not being SILENT — "a resolver that gets nothing marks the zone lame"
// — and reached for write(), which always attaches txtResource(EncodeTXT(down)); EncodeTXT(nil) is
// []string{""}. So `dig TXT <zone>` came back with an actual TXT RR carrying a zero-length string at
// TTL 0. Essentially no real zone answers that: a zone with no apex TXT returns NOERROR with an EMPTY
// answer section and its SOA in AUTHORITY. The one probe the branch was added to handle was therefore
// the probe that most clearly marked the zone as something other than an ordinary authoritative
// server — which for an anti-censorship carrier is the opposite of what the branch was for.
//
// It drives the REAL server over a real socket and reads the packed message, because the defect is
// invisible to parseResponseTXT (both shapes yield zero payload bytes) and that is exactly why the
// existing apex tests could not see it.
func TestApexAnswersLookLikeAnOrdinaryNODATA(t *testing.T) {
	const zone = "t.example.com"
	codec, err := NewCodec(zone)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	tr, addr, err := NewDNSServerTransport("127.0.0.1:0", codec)
	if err != nil {
		t.Fatalf("NewDNSServerTransport: %v", err)
	}
	defer tr.Close()

	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer cli.Close()

	askRaw := func(t *testing.T, name string, qtype dnsmessage.Type) dnsmessage.Message {
		t.Helper()
		n, nerr := dnsmessage.NewName(name)
		if nerr != nil {
			t.Fatalf("NewName(%q): %v", name, nerr)
		}
		q := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: 0x5151, RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: n, Type: qtype, Class: dnsmessage.ClassINET}},
		}
		raw, perr := q.Pack()
		if perr != nil {
			t.Fatalf("pack query: %v", perr)
		}
		if _, werr := cli.WriteToUDP(raw, addr.(*net.UDPAddr)); werr != nil {
			t.Fatalf("send: %v", werr)
		}
		buf := make([]byte, 1500)
		_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
		rn, _, rerr := cli.ReadFromUDP(buf)
		if rerr != nil {
			t.Fatalf("no answer to %q/%v: %v", name, qtype, rerr)
		}
		var msg dnsmessage.Message
		if uerr := msg.Unpack(buf[:rn]); uerr != nil {
			t.Fatalf("answer to %q did not unpack: %v", name, uerr)
		}
		return msg
	}

	// A NODATA is: NOERROR, authoritative, no answers, and the zone's SOA in AUTHORITY so a resolver
	// can cache the negative. Anything in ANSWER is a record we are claiming to have.
	wantNODATA := func(t *testing.T, what string, msg dnsmessage.Message) {
		t.Helper()
		if msg.Header.RCode != dnsmessage.RCodeSuccess {
			t.Errorf("%s: RCode=%v, want NOERROR", what, msg.Header.RCode)
		}
		if !msg.Header.Authoritative {
			t.Errorf("%s: the AA bit is not set, so we are not answering as the zone's authority", what)
		}
		if len(msg.Answers) != 0 {
			t.Errorf("%s: %d record(s) in ANSWER, want 0 — a NODATA claims no record of that type. "+
				"An empty TXT RR here is what marked this zone as not an ordinary authoritative server: "+
				"got %v", what, len(msg.Answers), msg.Answers[0].Header.Type)
		}
		if len(msg.Authorities) != 1 || msg.Authorities[0].Header.Type != dnsmessage.TypeSOA {
			t.Errorf("%s: AUTHORITY has %d record(s), want exactly the zone SOA — without it no resolver "+
				"can negatively cache the answer, and no ordinary zone omits it", what, len(msg.Authorities))
		}
	}

	// The probe the drain fix added its branch for.
	wantNODATA(t, "TXT at the apex", askRaw(t, zone+".", dnsmessage.TypeTXT))
	// ...and the non-TXT paths that already chose NODATA, so the two cannot drift apart again.
	wantNODATA(t, "MX at the apex", askRaw(t, zone+".", dnsmessage.TypeMX))
	wantNODATA(t, "A under the zone", askRaw(t, "probe."+zone+".", dnsmessage.TypeA))

	// The positive half: a real record must still come back IN the answer section, or "no answers
	// anywhere" would satisfy everything above.
	soa := askRaw(t, zone+".", dnsmessage.TypeSOA)
	if len(soa.Answers) != 1 || soa.Answers[0].Header.Type != dnsmessage.TypeSOA {
		t.Fatalf("a direct SOA query returned %d answer(s); the apex must still serve its own records",
			len(soa.Answers))
	}

	// ...and so must a real tunnel poll, which is the only TXT this zone genuinely has.
	if err := tr.Send([]byte("downstream")); err != nil {
		t.Fatalf("queue a downstream datagram: %v", err)
	}
	poll, perr := codec.EncodeName(nil, "abcdefgh")
	if perr != nil {
		t.Fatalf("EncodeName: %v", perr)
	}
	got := askRaw(t, poll, dnsmessage.TypeTXT)
	if len(got.Answers) != 1 || got.Answers[0].Header.Type != dnsmessage.TypeTXT {
		t.Fatalf("the client's poll got %d answer(s), want one TXT — the NODATA shape must not have "+
			"leaked onto the path that really carries the tunnel", len(got.Answers))
	}
}
