package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestEveryQueueingCarrierIsHandedItsQueues(t *testing.T) {
	fset := token.NewFileSet()
	carriers := queueingCarrierNames(t, fset)
	if len(carriers) == 0 {
		t.Fatal("no carrier names found in queueingCarrier: this guard would pass on anything")
	}

	byName, dflt := transportCases(t, fset)
	for _, name := range carriers {
		clause, ok := byName[name]
		if !ok {
			if dflt == nil {
				t.Fatalf("carrier %q has no case in the transport switch and there is no default", name)
			}
			clause = dflt
		}
		ctors := 0
		ast.Inspect(clause, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isCarrierCtor(call) {
				return true
			}
			ctors++
			if !passesExtraQueues(call) {
				t.Errorf("carrier %q: %s is not handed devs[1:], so every queue past the first is a "+
					"blackhole for whatever the kernel steers onto it", name, ctorName(call))
			}
			return true
		})
		if ctors == 0 {
			t.Errorf("carrier %q: found no constructor call to check, so nothing here was verified", name)
		}
	}
}

func queueingCarrierNames(t *testing.T, fset *token.FileSet) []string {
	t.Helper()
	f, err := parser.ParseFile(fset, "config.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "queueingCarrier" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					out = append(out, s)
				}
			}
			return true
		})
	}
	return out
}

func transportCases(t *testing.T, fset *token.FileSet) (map[string]*ast.CaseClause, *ast.CaseClause) {
	t.Helper()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*ast.CaseClause{}
	var dflt *ast.CaseClause
	ast.Inspect(f, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || !isSelector(sw.Tag, "cfg", "Transport") {
			return true
		}
		for _, stmt := range sw.Body.List {
			clause, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			if clause.List == nil {
				dflt = clause
				continue
			}
			for _, e := range clause.List {
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if s, err := strconv.Unquote(lit.Value); err == nil {
						byName[s] = clause
					}
				}
			}
		}
		return true
	})
	if len(byName) == 0 {
		t.Fatal("no switch on cfg.Transport found in main.go")
	}
	return byName, dflt
}

func isCarrierCtor(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "packet" {
		return false
	}
	return strings.HasPrefix(sel.Sel.Name, "Listen") || strings.HasPrefix(sel.Sel.Name, "Dial")
}

func ctorName(call *ast.CallExpr) string {
	return "packet." + call.Fun.(*ast.SelectorExpr).Sel.Name
}

func passesExtraQueues(call *ast.CallExpr) bool {
	if !call.Ellipsis.IsValid() || len(call.Args) == 0 {
		return false
	}
	sl, ok := call.Args[len(call.Args)-1].(*ast.SliceExpr)
	if !ok || sl.High != nil {
		return false
	}
	if x, ok := sl.X.(*ast.Ident); !ok || x.Name != "devs" {
		return false
	}
	lo, ok := sl.Low.(*ast.BasicLit)
	return ok && lo.Value == "1"
}

func isSelector(e ast.Expr, x, sel string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != sel {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == x
}
