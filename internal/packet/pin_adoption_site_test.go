package packet

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The ws-pool half of the pre-pin carrier fix has to be guarded AT THE SITE THAT CONSULTS IT.
//
// TestWSPoolPinMatches next door builds a bare wsPool and calls p.pinMatches four times. That pins
// what the predicate MEANS and nothing about whether anything still asks it — delete the whole `if`
// block in dialLoopWarm's activeReady arm and that test stays green, which is the same shape as the
// two dead_after_secs tests that both passed on the pre-fix tree.
//
// The direct-TCP half does have an end-to-end test (TestPinIsNotConsumedByAPreBuiltRotationCarrier
// drives a real dialLoop against a real server and asserts the tunnel lands on the pinned endpoint).
// The pool half cannot be driven the same way, and it is worth writing down why rather than leaving
// the gap unexplained: current() FORCES the pinned edge, so every ordinary dial already lands on it
// and passes the check. The only way to produce a mismatched carrier is the race the block documents
// — a background active dial that resolved its edge BEFORE the pin arrived, landing after it — and
// reaching that window on demand needs an outage, an adopted standby, an in-flight active dial and a
// pin, all interleaved in one order. A test that tried would be timing-dependent, and a flaky guard
// on a rare window is worth less than no guard at all.
//
// So this reads the call site, exactly as dead_after_wiring_test.go does for main.go's applyDeadAfter
// and as the panel's browser-gate guards do. It walks the AST rather than grepping, so reformatting
// or a renamed variable cannot fool it, and it is deliberately narrow: it asserts that the arm which
// adopts a finished active dial still asks the pool whether that carrier matches a live pin, and
// still refuses it when the answer is no.
//
// What it does NOT prove: that pinMatches returns the right answer (TestWSPoolPinMatches does), or
// that the discard path re-dials correctly. It proves the question is still being asked.
func TestActiveAdoptionStillConsultsThePin(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "tcp.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse tcp.go: %v", err)
	}

	var loop *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok && fd.Name.Name == "dialLoopWarm" {
			loop = fd
			return false
		}
		return true
	})
	if loop == nil {
		t.Fatal("dialLoopWarm is gone from tcp.go — this guard cannot read its subject, so it must not " +
			"report success. If the warm-standby loop was renamed or restructured, re-point it.")
	}

	// The arm that adopts a finished background ACTIVE dial: `case wc := <-activeReady:`.
	var arm *ast.CommClause
	ast.Inspect(loop, func(n ast.Node) bool {
		cc, ok := n.(*ast.CommClause)
		if !ok || cc.Comm == nil {
			return true
		}
		as, ok := cc.Comm.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		un, ok := as.Rhs[0].(*ast.UnaryExpr)
		if !ok || un.Op != token.ARROW {
			return true
		}
		if id, ok := un.X.(*ast.Ident); ok && id.Name == "activeReady" {
			arm = cc
			return false
		}
		return true
	})
	if arm == nil {
		t.Fatal("no `case <-activeReady:` arm in dialLoopWarm — the background active dial no longer " +
			"lands here, so this guard is reading the wrong place and must not report success")
	}

	// Inside it: a call to pinMatches, and a `continue` reachable from the branch it guards. Both,
	// because a call whose result is dropped would satisfy the first alone.
	asks, refuses := false, false
	ast.Inspect(arm, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "pinMatches" {
			asks = true
		}
		if ifs, ok := n.(*ast.IfStmt); ok && callsPinMatches(ifs.Cond) && hasContinue(ifs.Body) {
			refuses = true
		}
		return true
	})
	if !asks {
		t.Fatal("the activeReady arm no longer calls pool.pinMatches. A background active dial that " +
			"resolved its edge BEFORE an operator pin can then be adopted as the live carrier: the " +
			"operator lands on an edge they did not pick, and because that edge does not match, " +
			"pinApplied never clears the pin — so proactive rotation stays frozen for the rest of " +
			"pinTTL. That is the report core #204 was written for.")
	}
	if !refuses {
		t.Fatal("the activeReady arm still calls pool.pinMatches, but no `if` that tests it leaves the " +
			"arm with `continue` — so a carrier on the wrong edge is no longer DISCARDED, only asked " +
			"about. Asking without acting is the same bug with an extra step.")
	}
}

// callsPinMatches reports whether an expression contains a pinMatches call anywhere inside it.
func callsPinMatches(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "pinMatches" {
			found = true
			return false
		}
		return true
	})
	return found
}

// hasContinue reports whether a block leaves its enclosing loop iteration via `continue`, ignoring
// nested loops (whose continue belongs to them, not to this select arm).
func hasContinue(b *ast.BlockStmt) bool {
	found := false
	ast.Inspect(b, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.ForStmt, *ast.RangeStmt, *ast.FuncLit:
			return false // a continue in here is not this arm's
		}
		if br, ok := n.(*ast.BranchStmt); ok && br.Tok == token.CONTINUE {
			found = true
			return false
		}
		return true
	})
	return found
}
