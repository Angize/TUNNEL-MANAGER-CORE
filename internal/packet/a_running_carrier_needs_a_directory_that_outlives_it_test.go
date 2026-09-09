//go:build linux

package packet

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// A carrier that has been Run() writes its status file from a one-second sampler, and t.TempDir() is
// removed the moment the test returns. The sampler is still in flight, so the removal races it and
// the test fails in CLEANUP, long after its own assertions passed:
//
//	TempDir RemoveAll cleanup: unlinkat /tmp/TestNodeVerdictsDriveTheLiveDirectPool.../001: directory not empty
//
// That is what it looked like in CI, on a test whose subject is the node's verdicts. It reads as a
// failure of the thing under test and is a teardown race, which is the worst kind of red: nobody
// believes it, so nobody looks.
//
// runningStatusPath exists for exactly this -- its own directory, closed and given 150ms before it
// goes. Six call sites already used it and nine did not. A grep cannot tell them apart, because
// pool_harness_test.go both runs carriers (probePair) and builds ones that are never run
// (edgeCarrier, peerCarrier), so this asks per FUNCTION instead: does this function body start a
// carrier AND point a status file at a directory the test framework will delete?
func TestNoRunningCarrierWritesIntoADirectoryTheTestIsDeleting(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var bad []string

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			runs, doomed := false, ""
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if g, ok := n.(*ast.GoStmt); ok && calleeName(g.Call) == "Run" {
					runs = true
				}
				call, ok := n.(*ast.CallExpr)
				if !ok || calleeName(call) != "SetStatusPath" || len(call.Args) != 1 {
					return true
				}
				if src := transientDir(call.Args[0]); src != "" {
					doomed = src
				}
				return true
			})
			if runs && doomed != "" {
				bad = append(bad, e.Name()+": "+fn.Name.Name+" (status path built from "+doomed+")")
			}
		}
	}

	for _, b := range bad {
		t.Errorf("%s — a Run() carrier keeps writing after the test returns; use "+
			"runningStatusPath(t, carrier), which owns its directory and lets the sampler stop first", b)
	}
}

func calleeName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

// The status path is doomed when it is joined onto t.TempDir(), directly or through a local that was
// assigned from it. Anything else -- runningStatusPath, os.MkdirTemp, a caller's argument -- is fine.
func transientDir(arg ast.Expr) string {
	call, ok := arg.(*ast.CallExpr)
	if !ok || calleeName(call) != "Join" {
		return ""
	}
	for _, a := range call.Args {
		if inner, ok := a.(*ast.CallExpr); ok && calleeName(inner) == "TempDir" {
			return "t.TempDir()"
		}
		if id, ok := a.(*ast.Ident); ok && id.Obj != nil {
			if as, ok := id.Obj.Decl.(*ast.AssignStmt); ok {
				for _, rhs := range as.Rhs {
					if c, ok := rhs.(*ast.CallExpr); ok && calleeName(c) == "TempDir" {
						return id.Name + " := t.TempDir()"
					}
				}
			}
		}
	}
	return ""
}
