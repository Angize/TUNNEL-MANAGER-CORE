package dnstun

import (
	"net"
	"testing"
	"time"
)

// The drain lived in the SERVER's reply path, and no test ever built a server.
//
// bare_zone_test.go next door calls Codec.DecodeName and checks its error value. That is the
// mechanism the fix used, not the thing the fix was about: what was stolen was a datagram off
// `s.downstream`, and nothing in that file — or in codec_test.go, or in
// TestDNSServerAuthoritativeBehavior — ever constructs a dnsServer, queues a downstream datagram, or
// counts what is left in the queue afterwards. So the whole class stayed invisible: an apex query
// could go back to popping the queue and every one of those tests would still pass.
//
// This drives the real server over a real UDP socket and MEASURES the queue.
func TestApexQueryDoesNotStealADownstreamDatagram(t *testing.T) {
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
	srv := tr.(*dnsServer)

	// One datagram waiting to go server -> client, exactly as a live tunnel would have.
	payload := []byte("downstream owed to the real client")
	if err := tr.Send(payload); err != nil {
		t.Fatalf("queue a downstream datagram: %v", err)
	}
	if got := len(srv.downstream); got != 1 {
		t.Fatalf("the downstream queue holds %d datagrams, want 1 — this test would prove nothing", got)
	}

	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer cli.Close()

	ask := func(t *testing.T, name string) []byte {
		t.Helper()
		q, qerr := buildQuery(0x4242, name)
		if qerr != nil {
			t.Fatalf("buildQuery(%q): %v", name, qerr)
		}
		if _, werr := cli.WriteToUDP(q, addr.(*net.UDPAddr)); werr != nil {
			t.Fatalf("send query: %v", werr)
		}
		buf := make([]byte, 1500)
		_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, rerr := cli.ReadFromUDP(buf)
		if rerr != nil {
			t.Fatalf("no answer to %q: %v", name, rerr)
		}
		txt, perr := parseResponseTXT(buf[:n], 0x4242)
		if perr != nil {
			t.Fatalf("answer to %q did not parse: %v", name, perr)
		}
		return txt
	}

	// A stranger who read the zone off the public delegation. `dig TXT <zone>`, in a loop.
	for i := 0; i < 5; i++ {
		if got := ask(t, zone+"."); len(got) != 0 {
			t.Fatalf("the apex query was answered with %d bytes of the tunnel's downstream", len(got))
		}
	}
	if got := len(srv.downstream); got != 1 {
		t.Fatalf("after 5 apex queries the downstream queue holds %d datagrams, want 1: a stranger who "+
			"knows the (public) zone is taking the server->client stream off the real client, one datagram "+
			"per query, with no auth and no rate limit", got)
	}

	// ...and the REAL client's poll must still be served, or the fix would have broken every idle
	// tunnel instead. This is the half that makes the assertion above meaningful.
	poll, err := codec.EncodeName(nil, "abcdefgh")
	if err != nil {
		t.Fatalf("EncodeName: %v", err)
	}
	got := ask(t, poll)
	if string(got) != string(payload) {
		t.Fatalf("the client's poll got %q, want the queued datagram %q", got, payload)
	}
	if left := len(srv.downstream); left != 0 {
		t.Fatalf("the client's poll left %d datagrams queued, want 0 — it did not consume the one it was given", left)
	}

	// The apex must still ANSWER (silence on our own zone is its own signal, and a resolver that gets
	// nothing marks the delegation lame) — it just must not answer with the tunnel's data.
	if got := ask(t, zone+"."); len(got) != 0 {
		t.Fatalf("apex answered with %d bytes after the queue drained", len(got))
	}
}
