package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This file is the ratchet for a defect class the 2026-07-31 review found twice and that turned out to
// exist eleven more times: a comment that documents something OTHER than the thing it is attached to.
//
// It happens the same way every time. A new helper is inserted into a file, and its doc block lands
// BETWEEN an existing doc comment and the declaration that comment belongs to. Nothing complains —
// gofmt is happy, the compiler is happy, `go vet` is happy — but from then on godoc shows one function's
// prose on another, and the original declaration has no doc at all. In a repository where the comments
// carry the reasoning (why a number is what it is, which bug a branch exists to prevent), a comment
// pointing at the wrong code is not cosmetic: it is the reasoning filed under the wrong name.
//
// Neither check needs a build tag: go/parser reads the source, so the linux-only files are covered from
// any host.

// goFiles walks the module and calls fn for every non-test .go file's parsed AST.
func goFiles(t *testing.T, fn func(path string, f *ast.File, fset *token.FileSet)) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.Walk(".", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if perr != nil {
			return perr
		}
		fn(p, f, fset)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
}

// docHead is the first word of a doc comment, which by Go convention is the name of what it documents.
func docHead(doc string) string {
	f := strings.FieldsFunc(strings.TrimSpace(doc), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '(' || r == ',' || r == ':'
	})
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// TestDocCommentsDocumentWhatTheyAreAttachedTo fails when a doc comment opens with the name of a
// DIFFERENT top-level declaration in the same package.
//
// The rule is deliberately narrow. Plenty of good comments start with prose ("Deadlines are…",
// "Non-linux stub…") and those are none of its business; measured over the tree, 88 of 961 documented
// declarations do not begin with their own name and only these eleven named something else. What the
// narrow form catches is exactly the insertion accident, because the orphaned comment necessarily still
// opens with the name of the declaration it was written for.
func TestDocCommentsDocumentWhatTheyAreAttachedTo(t *testing.T) {
	type documented struct {
		pkgDir, name, head, pos string
	}
	var docs []documented
	names := map[string]map[string]bool{} // package dir -> declared identifiers

	note := func(dir, name string) {
		if names[dir] == nil {
			names[dir] = map[string]bool{}
		}
		names[dir][name] = true
	}

	goFiles(t, func(p string, f *ast.File, fset *token.FileSet) {
		dir := filepath.Dir(p)
		for _, d := range f.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				note(dir, x.Name.Name)
				if x.Doc != nil {
					docs = append(docs, documented{dir, x.Name.Name, docHead(x.Doc.Text()),
						fset.Position(x.Pos()).String()})
				}
			case *ast.GenDecl:
				for _, sp := range x.Specs {
					switch s := sp.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							note(dir, n.Name)
						}
					case *ast.TypeSpec:
						note(dir, s.Name.Name)
					}
				}
				// Only a single-spec block has one obvious owner; a grouped var/const block's doc
				// documents the group, so it is out of scope by construction.
				if x.Doc == nil || len(x.Specs) != 1 {
					continue
				}
				var nm string
				switch s := x.Specs[0].(type) {
				case *ast.ValueSpec:
					if len(s.Names) == 1 {
						nm = s.Names[0].Name
					}
				case *ast.TypeSpec:
					nm = s.Name.Name
				}
				if nm != "" {
					docs = append(docs, documented{dir, nm, docHead(x.Doc.Text()),
						fset.Position(x.Pos()).String()})
				}
			}
		}
	})

	if len(docs) < 300 {
		t.Fatalf("only %d documented declarations were parsed — this check cannot have read the tree, "+
			"so it must not report success", len(docs))
	}
	for _, d := range docs {
		if d.head == d.name || !names[d.pkgDir][d.head] {
			continue
		}
		t.Errorf("%s: the doc comment on %s opens with %q, which is a different declaration in this "+
			"package. A new declaration was almost certainly inserted between that comment and the one "+
			"it was written for — so godoc now shows %s's prose on %s, and %s has no doc at all.",
			d.pos, d.name, d.head, d.head, d.name, d.head)
	}
}

var testNameRe = regexp.MustCompile(`\b(?:Test|Fuzz|Benchmark)[A-Z][A-Za-z0-9_]*`)

// TestCommentsDoNotNameATestThatDoesNotExist fails when a comment in non-test code points at a test by
// a name nothing declares.
//
// The comments here routinely name the test that keeps two layers together, or that pins an invariant,
// and that is the only thread tying a subtle rule to the thing defending it. A name that no longer resolves — renamed,
// never written, or invented — reads exactly like a guarantee while guaranteeing nothing, and it sends
// the next reader looking for a safety net that is not there. Nothing else in the toolchain checks it:
// a comment is a comment.
func TestCommentsDoNotNameATestThatDoesNotExist(t *testing.T) {
	declared := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.Walk(".", func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return nil // a parse failure is the other checks' problem, not this one's
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				declared[fd.Name.Name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	// Comments in TEST files count too: a "see the other half" reference written beside one test is the
	// same thread and rots the same way. That is also what makes the floor below meaningful — production
	// code holds only a handful of these references, so a floor over those alone could not tell
	// "nothing to check" from "read nothing".
	refs := 0
	err = filepath.Walk(".", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if perr != nil {
			return nil
		}
		for _, cg := range f.Comments {
			for _, name := range testNameRe.FindAllString(cg.Text(), -1) {
				refs++
				if !declared[name] {
					t.Errorf("%s: a comment names %s, but no such function exists anywhere in the tree. "+
						"Either the test was renamed and this reference was not, or it was never written — "+
						"and the comment reads as a guarantee either way.",
						fset.Position(cg.Pos()).String(), name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if refs < 50 {
		t.Fatalf("only %d test references were found in comments — this check cannot have read the "+
			"tree, so it must not report success", refs)
	}
}
