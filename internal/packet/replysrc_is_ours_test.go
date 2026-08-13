//go:build linux

package packet

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// oobWithDst builds the IP_PKTINFO control message the kernel hands ReadMsgIP, with ipi_addr set to
// dst — the destination the SENDER put in the header. Same layout the receive path parses.
func oobWithDst(dst net.IP) []byte {
	b := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.IPPROTO_IP
	h.Type = unix.IP_PKTINFO
	h.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
	pi := (*unix.Inet4Pktinfo)(unsafe.Pointer(&b[unix.CmsgLen(0)]))
	copy(pi.Addr[:], dst.To4())
	return b
}

// The server answers from the address the client dialed, read out of IP_PKTINFO. ipi_addr is whatever
// the SENDER wrote in the header, and a raw socket bound to 0.0.0.0 is handed broadcast-addressed
// packets of its protocol too — so an address this host does not hold must never become the reply
// source. It is committed before the AEAD, and once it is wrong iplink's IP_PKTINFO send fails
// outright: the udp and tcp profiles then answer NOTHING until an inbound frame corrects it.
func TestTheReplySourceIsAlwaysAnAddressWeHold(t *testing.T) {
	local := oneLocalIP4(t)

	t.Run("an address we hold is adopted", func(t *testing.T) {
		r := &Raw{}
		r.learnReplySrc(oobWithDst(local))
		if got := r.replySrc.Load(); got == nil || !got.Equal(local) {
			t.Fatalf("the dialed address %s was not adopted as the reply source (got %v)", local, got)
		}
	})

	for _, dst := range []string{"255.255.255.255", "10.99.99.255", "224.0.0.1", "198.51.100.77"} {
		t.Run("a frame aimed at "+dst+" cannot steer it", func(t *testing.T) {
			r := &Raw{}
			r.learnReplySrc(oobWithDst(local)) // the tunnel is up and answering from our own IP
			r.learnReplySrc(oobWithDst(net.ParseIP(dst)))
			got := r.replySrc.Load()
			if got == nil || !got.Equal(local) {
				t.Errorf("a frame addressed to %s moved the reply source to %v; every reply now leaves "+
					"from an address we do not hold, and the udp/tcp profiles send nothing at all", dst, got)
			}
		})
	}

	t.Run("no IP_PKTINFO leaves it alone", func(t *testing.T) {
		r := &Raw{}
		r.learnReplySrc(oobWithDst(local))
		r.learnReplySrc(nil)
		if got := r.replySrc.Load(); got == nil || !got.Equal(local) {
			t.Errorf("a frame with no control message cleared the reply source: %v", got)
		}
	})

	// The steady state is one atomic load: the same destination, packet after packet, must not
	// re-allocate or re-read the interface list on the receive path.
	t.Run("the unchanged case allocates nothing", func(t *testing.T) {
		r := &Raw{}
		oob := oobWithDst(local)
		r.learnReplySrc(oob)
		if n := testing.AllocsPerRun(200, func() { r.learnReplySrc(oob) }); n != 0 {
			t.Errorf("%v allocation(s) per received server packet for a destination that has not changed", n)
		}
	})

	// A pool IP the node adds while the core is running has to be picked up, and a sender spraying
	// unknown destinations must not be able to spin the interface scan.
	t.Run("the ownership answer is cached and refreshed", func(t *testing.T) {
		var o ourIPs
		if !o.has(local) {
			t.Fatalf("%s is configured on this host but was not recognised", local)
		}
		defer func(d time.Duration) { localIPRescan = d }(localIPRescan)
		localIPRescan = time.Hour
		before := o.scanned
		for i := 0; i < 50; i++ {
			o.has(net.IPv4(198, 51, 100, byte(i)))
		}
		if !o.scanned.Equal(before) {
			t.Error("50 unknown destinations re-read the interface list; a sprayer can drive that scan from the wire")
		}
	})
}

// ...and the receive loop still asks. The check is worth nothing if recvConnLoop stops calling it,
// and that is the half a test of the function alone can never see.
func TestTheServerReceiveLoopStillLearnsItsReplySource(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "raw_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var loop *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok && fd.Name.Name == "recvConnLoop" {
			loop = fd
		}
		return true
	})
	if loop == nil {
		t.Fatal("recvConnLoop is gone; this guard no longer knows what it is guarding")
	}
	found := false
	ast.Inspect(loop, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "learnReplySrc" {
			found = true
		}
		return true
	})
	if !found {
		t.Error("recvConnLoop no longer calls learnReplySrc — the reply source is either unset (a " +
			"destination pool burns every IP but the primary) or set somewhere that does not check it")
	}
}

// oneLocalIP4 is any IPv4 address this host really holds, so the test asserts against the same source
// of truth the code uses rather than a hardcoded address.
func oneLocalIP4(t *testing.T) net.IP {
	t.Helper()
	for k := range scanLocalIP4() {
		return net.IP(k).To4()
	}
	t.Skip("this host has no IPv4 address configured")
	return nil
}
