package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// The role gate must not come back at the CALL SITE, which is where it lived. Neither regression test
// written with that fix can catch its return: one pokes SetDeadAfter, which was never gated, and the
// other asserts applyDeadAfter forwards — but `if cfg.Role == "client" { applyDeadAfter(...) }` puts
// the gate back without touching the signature. main() is not callable from a test, so this walks the AST.
func TestApplyDeadAfterIsCalledUnconditionally(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	// The chain of enclosing `if` conditions above each applyDeadAfter call.
	type site struct {
		line   int
		guards []string
	}
	var sites []site
	var stack []*ast.IfStmt

	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.IfStmt:
			stack = append(stack, v)
			// Walk the body ourselves so the stack unwinds correctly.
			ast.Inspect(v.Body, func(inner ast.Node) bool {
				if call, ok := inner.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "applyDeadAfter" {
						var conds []string
						for _, s := range stack {
							conds = append(conds, exprText(fset, s.Cond))
						}
						sites = append(sites, site{fset.Position(call.Pos()).Line, conds})
					}
				}
				return true
			})
			stack = stack[:len(stack)-1]
			return false // its body has been walked
		case *ast.CallExpr:
			if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "applyDeadAfter" {
				sites = append(sites, site{fset.Position(v.Pos()).Line, nil})
			}
		}
		return true
	})

	if len(sites) == 0 {
		t.Fatal("main.go never calls applyDeadAfter: dead_after_secs reaches no carrier at all")
	}
	for _, s := range sites {
		for _, c := range s.guards {
			if strings.Contains(c, "Role") || strings.Contains(c, "role") {
				t.Errorf("main.go:%d calls applyDeadAfter inside `if %s` — that is the role gate coming back. "+
					"dead_after_secs is written onto BOTH ends and on tcp/ws the server has a read deadline of "+
					"its own, so gating it leaves half the tunnel self-healing at the operator's speed and half "+
					"at its ~60s default", s.line, c)
			}
		}
	}
}

func exprText(fset *token.FileSet, e ast.Expr) string {
	var b bytes.Buffer
	if printer.Fprint(&b, fset, e) != nil {
		return "<unprintable>"
	}
	return b.String()
}
