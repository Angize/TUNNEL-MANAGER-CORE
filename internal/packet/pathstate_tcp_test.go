package packet

import (
	"net"
	"testing"
)

// TestTCPLivePathReadsTheRealSocket.
//
// Every field of a stream carrier's key except the SNI comes out of the conn, and that conn is
// wrapped — TLS, then the ws framing — before it reaches livePath. So this drives a REAL accepted
// connection instead of a stub: if a wrapper ever stopped forwarding LocalAddr/RemoteAddr the key
// would come back unnamed, the node would read a path it cannot judge, and failover would stop
// without one error anywhere.
//
// It also pins the two gates around it: no conn is no path, and a conn that has not been adopted as
// the tunnel is not ready.
func TestTCPLivePathReadsTheRealSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if sc := <-accepted; sc != nil {
		defer sc.Close()
	}

	b := &TCP{}
	if k, ready := b.livePath(); k != (pathKey{}) || ready {
		t.Errorf("with no connection the path must be empty and not ready, got %+v ready=%v", k, ready)
	}

	cc := conn
	b.curConn.Store(&cc)
	sni := "edge.example"
	b.liveSNI.Store(&sni)

	k, ready := b.livePath()
	if ready {
		t.Error("a connection that has not been adopted as the tunnel must not read as ready")
	}
	// Ground truth from the kernel's own structs, NOT from addrParts — comparing the key against the
	// helper it was built with would pass on any consistent nonsense.
	local := conn.LocalAddr().(*net.TCPAddr)
	remote := ln.Addr().(*net.TCPAddr)
	if k.Src != local.IP.String() || k.Sport != uint16(local.Port) {
		t.Errorf("source %s:%d, the socket is bound to %s:%d", k.Src, k.Sport, local.IP, local.Port)
	}
	if k.Dst != "127.0.0.1" || k.Dport != uint16(remote.Port) {
		t.Errorf("destination %s:%d, the listener is on 127.0.0.1:%d", k.Dst, k.Dport, remote.Port)
	}
	if k.Sport == 0 || k.Dport == 0 {
		t.Fatal("a live TCP connection reported no ports — the key would name a path nothing can judge")
	}
	if k.SNI != sni {
		t.Errorf("SNI %q, want %q", k.SNI, sni)
	}

	b.cur.Store(&connFramer{conn: conn})
	if _, ready := b.livePath(); !ready {
		t.Error("an adopted connection IS the session for a stream carrier — it must read as ready")
	}
}
