// Package detcheck enforces the rules that keep a deterministic package
// deterministic, so a simulator seed replays its run exactly and a core
// behaves the same in a daemon and in the simulator.
//
// A package opts in with a `//wirenet:deterministic` line comment in any of its
// files. Its non-test files may then:
//
//   - import only the standard packages in allowedStd, the third-party
//     packages in allowedExternal, and other deterministic packages;
//   - not read a clock, sleep, or start a timer;
//   - not start a goroutine, select, or use a channel;
//   - not range over a map, nor collect a map's keys or values except in
//     sorted order;
//   - not declare package-level variables other than errors and interface
//     assertions, since parallel simulator runs share them.
package detcheck

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Directive marks a package deterministic.
const Directive = "//wirenet:deterministic"

var allowedStd = map[string]bool{
	"bytes": true, "cmp": true, "context": true, "container/heap": true, "crypto/hmac": true,
	"crypto/sha256": true, "crypto/subtle": true, "encoding/base32": true, "encoding/base64": true,
	"encoding/binary": true, "encoding/hex": true, "encoding/json": true,
	"errors": true, "fmt": true, "hash": true, "io": true, "iter": true,
	"maps": true, "math": true, "math/bits": true, "net/netip": true,
	"slices": true, "sort": true, "strconv": true, "strings": true,
	"time": true, "unicode": true, "unicode/utf8": true,
}

var allowedExternal = map[string]bool{
	"golang.org/x/crypto/curve25519":  true,
	"golang.org/x/crypto/blake2s":     true,
	"golang.org/x/net/dns/dnsmessage": true,
}

// Clock and timer functions in package time.
var forbiddenTime = map[string]bool{
	"Now": true, "Since": true, "Until": true, "Sleep": true, "After": true,
	"AfterFunc": true, "NewTimer": true, "NewTicker": true, "Tick": true,
}

// Functions whose iteration order follows a map's.
var mapIterators = map[string]bool{"Keys": true, "Values": true, "All": true}

// Functions that impose an order on what they consume.
var sorters = map[string]bool{"Sorted": true, "SortedFunc": true, "SortedStableFunc": true}

// Finding is one violation.
type Finding struct {
	Pos     token.Position
	Package string
	Rule    string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: %s (%s)", f.Pos, f.Rule, f.Package)
}

// Load loads the packages matching patterns with syntax and types.
func Load(dir string, patterns ...string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports,
		Dir: dir,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			return nil, fmt.Errorf("%s: %v", p.PkgPath, p.Errors[0])
		}
	}
	return pkgs, nil
}

// IsDeterministic reports whether a package carries the directive.
func IsDeterministic(p *packages.Package) bool {
	for _, f := range p.Syntax {
		for _, g := range f.Comments {
			for _, c := range g.List {
				if strings.TrimSpace(c.Text) == Directive {
					return true
				}
			}
		}
	}
	return false
}

// Check returns every violation in the deterministic packages among pkgs.
func Check(pkgs []*packages.Package) []Finding {
	det := map[string]bool{}
	for _, p := range pkgs {
		if IsDeterministic(p) {
			det[p.PkgPath] = true
		}
	}
	var out []Finding
	for _, p := range pkgs {
		if det[p.PkgPath] {
			out = append(out, checkPackage(p, det)...)
		}
	}
	slices.SortFunc(out, func(a, b Finding) int { return strings.Compare(a.String(), b.String()) })
	return out
}

func checkPackage(p *packages.Package, det map[string]bool) []Finding {
	var out []Finding
	report := func(pos token.Pos, format string, args ...any) {
		out = append(out, Finding{Pos: p.Fset.Position(pos), Package: p.PkgPath, Rule: fmt.Sprintf(format, args...)})
	}
	for _, f := range p.Syntax {
		if strings.HasSuffix(p.Fset.Position(f.Pos()).Filename, "_test.go") {
			continue
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if !allowedStd[path] && !allowedExternal[path] && !det[path] {
				report(imp.Pos(), "imports %s", path)
			}
		}
		for _, decl := range f.Decls {
			if g, ok := decl.(*ast.GenDecl); ok && g.Tok == token.VAR {
				checkGlobals(p, g, report)
			}
		}
		sortedArgs := map[ast.Expr]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.GoStmt:
				report(n.Pos(), "starts a goroutine")
			case *ast.SelectStmt:
				report(n.Pos(), "selects on channels")
			case *ast.SendStmt:
				report(n.Pos(), "sends on a channel")
			case *ast.UnaryExpr:
				if n.Op == token.ARROW {
					report(n.Pos(), "receives from a channel")
				}
			case *ast.ChanType:
				report(n.Pos(), "uses a channel type")
			case *ast.RangeStmt:
				if t := p.TypesInfo.TypeOf(n.X); t != nil {
					if _, ok := t.Underlying().(*types.Map); ok {
						report(n.Pos(), "ranges over a map")
					}
				}
			case *ast.CallExpr:
				fn := calledFunc(p.TypesInfo, n)
				if fn == nil || fn.Pkg() == nil {
					break
				}
				switch fn.Pkg().Path() {
				case "time":
					if forbiddenTime[fn.Name()] && fn.Type().(*types.Signature).Recv() == nil {
						report(n.Pos(), "calls time.%s", fn.Name())
					}
				case "slices":
					if sorters[fn.Name()] && len(n.Args) > 0 {
						sortedArgs[n.Args[0]] = true
					}
				case "maps":
					if mapIterators[fn.Name()] && !sortedArgs[ast.Expr(n)] {
						report(n.Pos(), "iterates maps.%s outside slices.Sorted", fn.Name())
					}
				}
			}
			return true
		})
	}
	return out
}

func checkGlobals(p *packages.Package, g *ast.GenDecl, report func(token.Pos, string, ...any)) {
	errType := types.Universe.Lookup("error").Type()
	for _, spec := range g.Specs {
		vs := spec.(*ast.ValueSpec)
		for _, name := range vs.Names {
			if name.Name == "_" {
				continue
			}
			obj := p.TypesInfo.Defs[name]
			if obj != nil && types.Identical(obj.Type(), errType) {
				continue
			}
			report(name.Pos(), "declares package variable %s", name.Name)
		}
	}
}

func calledFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fun
	case *ast.SelectorExpr:
		id = fun.Sel
	case *ast.IndexExpr:
		if sel, ok := fun.X.(*ast.SelectorExpr); ok {
			id = sel.Sel
		} else if i, ok := fun.X.(*ast.Ident); ok {
			id = i
		}
	default:
		return nil
	}
	if id == nil {
		return nil
	}
	fn, _ := info.Uses[id].(*types.Func)
	return fn
}
