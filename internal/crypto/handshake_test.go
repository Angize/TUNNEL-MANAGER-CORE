package crypto

import (
	"bytes"
	"testing"
)

func doHandshake(t *testing.T, psk string) (client, server *Sealer) {
	t.Helper()
	ci, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	msg1 := InitMsg(psk, ci)

	eInit, err := ParseInit(psk, msg1)
	if err != nil {
		t.Fatalf("ParseInit: %v", err)
	}
	sr, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	msg2 := RespMsg(psk, eInit, sr)
	server, err = SessionSealer(CipherChaCha, psk, sr, eInit, eInit, sr.Pub, false)
	if err != nil {
		t.Fatalf("server SessionSealer: %v", err)
	}

	eResp, err := ParseResp(psk, ci.Pub, msg2)
	if err != nil {
		t.Fatalf("ParseResp: %v", err)
	}
	client, err = SessionSealer(CipherChaCha, psk, ci, eResp, ci.Pub, eResp, true)
	if err != nil {
		t.Fatalf("client SessionSealer: %v", err)
	}
	return client, server
}

func TestHandshakeRoundTrip(t *testing.T) {
	c, s := doHandshake(t, "handshake-psk-abcdefghij")
	ct, _ := c.Seal([]byte("hello via ephemeral session"), nil)
	_, _, pt, err := s.Open(ct, nil)
	if err != nil || !bytes.Equal(pt, []byte("hello via ephemeral session")) {
		t.Fatalf("c->s open: %v", err)
	}
	ct2, _ := s.Seal([]byte("reply"), nil)
	if _, _, pt, err := c.Open(ct2, nil); err != nil || !bytes.Equal(pt, []byte("reply")) {
		t.Fatalf("s->c open: %v", err)
	}
}

func TestHandshakeWrongPSKRejected(t *testing.T) {
	ci, _ := GenerateEphemeral()
	msg1 := InitMsg("psk-one", ci)
	if _, err := ParseInit("psk-two", msg1); err == nil {
		t.Fatal("init MAC verified under the wrong PSK (no probe resistance)")
	}
}

func TestHandshakeRespBinding(t *testing.T) {

	ci, _ := GenerateEphemeral()
	other, _ := GenerateEphemeral()
	sr, _ := GenerateEphemeral()
	msg2 := RespMsg("psk", ci.Pub, sr)
	if _, err := ParseResp("psk", other.Pub, msg2); err == nil {
		t.Fatal("resp verified against the wrong initiator key")
	}
	if _, err := ParseResp("psk", ci.Pub, msg2); err != nil {
		t.Fatalf("resp failed against the right initiator key: %v", err)
	}
}

func TestForwardSecrecyFreshKeys(t *testing.T) {
	psk := "same-psk-two-sessions"
	c1, _ := doHandshake(t, psk)
	_, s2 := doHandshake(t, psk)
	ct, _ := c1.Seal([]byte("session-1 data"), nil)
	if _, _, _, err := s2.Open(ct, nil); err == nil {
		t.Fatal("a session-1 frame opened under session-2 keys — replay across sessions still works")
	}
}

func TestEphemeralPublicVaries(t *testing.T) {
	a, _ := GenerateEphemeral()
	b, _ := GenerateEphemeral()
	if a.Pub == b.Pub {
		t.Fatal("two ephemerals share a public key")
	}
}
