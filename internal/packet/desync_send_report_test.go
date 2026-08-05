package packet

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"net"
	"os"
	"strings"
	"testing"
)

// A decoy that never reaches the wire must SAY so. With every transmit error discarded, an L2 next hop
// that will not resolve produced zero decoys and zero log lines, while startup had already printed that
// the camouflage was on — so a blocked tunnel gave no way to tell it never ran. Drives the REAL path
// (Raw.sendFakes) with a resolver that fails, not the reporter.
func TestDecoyTransmitFailureIsReported(t *testing.T) {
	f := &fakeResolver{err: errors.New("no next hop")}
	r := &Raw{isClient: true, proto: protoBare, profile: "bare", fakeFd: -1}
	r.link = &directLink{r: r}
	r.localIP.Store(&net.IPAddr{IP: net.IPv4(192, 0, 2, 1)})
	r.desync = newDesyncCfg(true, 4, 2, "badsum") // every decoy is badsum -> every one goes via the injector
	r.inj = testInjector(f)
	want := int64(len(r.desync.specs()))

	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	peer := &net.IPAddr{IP: net.IPv4(203, 0, 113, 5)}
	r.peer.Store(peer)
	r.sendFakes(peer)

	if got := r.dsSend.bad.Load(); got != want {
		t.Errorf("counted %d failed decoys, want %d — a transmit that failed was booked as fine", got, want)
	}
	if got := r.dsSend.ok.Load(); got != 0 {
		t.Errorf("counted %d delivered decoys; none could have been delivered", got)
	}
	if !strings.Contains(out.String(), "fake-desync decoy NOT sent") {
		t.Fatalf("a carrier whose every decoy failed logged nothing.\nlog was: %q", out.String())
	}

	// The repeat is paced, so a permanently-broken next hop cannot flood the journal — but the
	// COUNT must keep moving, or a rate limit would recreate the silence it exists to bound.
	before := strings.Count(out.String(), "fake-desync decoy NOT sent")
	r.sendFakes(peer)
	if got := r.dsSend.bad.Load(); got != 2*want {
		t.Errorf("second batch: counted %d failures, want %d — the pacing must throttle the LOG, not the count", got, 2*want)
	}
	if after := strings.Count(out.String(), "fake-desync decoy NOT sent"); after != before {
		t.Errorf("logged %d lines for %d failed decoys; the repeat is meant to be paced at %v", after, 2*want, desyncReportEvery)
	}
}

// The class guard. Fixing the sites one by one does not stop the next from being written the same way —
// a discarded send error is invisible in review, because `_ =` reads as deliberate. Every decoy transmit
// in this package must hand its error to something. Bare-call statements count too: Go lets
// `syscall.Sendto(fd, …)` stand alone as a statement and silently drop the error, with no `_ =` to see.
func TestNoSendErrorIsDiscarded(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	fset := token.NewFileSet()
	var bad []string
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue // tests may ignore a send: they assert on the recorder, not on delivery
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			var call *ast.CallExpr
			switch s := n.(type) {
			case *ast.ExprStmt: // a bare call statement: the error is dropped with nothing to see
				call, _ = s.X.(*ast.CallExpr)
			case *ast.AssignStmt: // `_ = send(...)` / `_, _ = send(...)`
				if len(s.Rhs) != 1 || !allBlank(s.Lhs) {
					return true
				}
				call, _ = s.Rhs[0].(*ast.CallExpr)
			default:
				return true
			}
			if call == nil {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "sendTo", "Sendto":
				bad = append(bad, fset.Position(call.Pos()).String()+" "+sel.Sel.Name)
			}
			return true
		})
	}
	if len(bad) > 0 {
		t.Fatalf("a packet transmit discards its error:\n  %s\n"+
			"Hand it to dsSend.note (decoys) or check it (data path) — a silently dropped send is a "+
			"feature that is configured, logged as on, and doing nothing.", strings.Join(bad, "\n  "))
	}
}

func allBlank(xs []ast.Expr) bool {
	for _, x := range xs {
		id, ok := x.(*ast.Ident)
		if !ok || id.Name != "_" {
			return false
		}
	}
	return len(xs) > 0
}
