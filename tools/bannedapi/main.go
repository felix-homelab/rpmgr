// SPDX-License-Identifier: Apache-2.0

// Command bannedapi fails when Go code names a TLS or QUIC setting that rpmgr bans
// (docs/12-testing-and-quality.md, "Security testing"): skipping certificate verification, 0-RTT,
// renegotiation, and checks in VerifyPeerCertificate, which resumed connections skip.
//
// It complements golangci-lint's forbidigo, which does not see the keys of composite literals
// such as tls.Config{InsecureSkipVerify: true}. Names are matched as composite-literal keys and as
// selectors (x.Name), so comments and strings never match. A reviewed decision may allow one name
// in one function of one file of a module (exceptions); a file is known by its module, which the
// nearest go.mod above it declares, and its path from that module's root, so neither another
// module, such as a spike's, nor a path that only ends alike matches. A module inside another is
// known by no path, whatever its go.mod declares, so it cannot borrow an exception.
//
// Usage: go run ./tools/bannedapi [<dir> ...]   (default: the current directory)
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// banned maps each banned name to the reason printed with a finding.
var banned = map[string]string{
	"InsecureSkipVerify":    "certificate verification is never skipped; tests use a generated test CA",
	"VerifyPeerCertificate": "every check belongs in VerifyConnection, which also runs on resumed connections",
	"Renegotiation":         "renegotiation disables exported keying material, which binds CSRs",
	"Allow0RTT":             "0-RTT data can be replayed",
	"ListenEarly":           "0-RTT data can be replayed",
	"ListenAddrEarly":       "0-RTT data can be replayed",
	"DialEarly":             "0-RTT data can be replayed",
	"DialAddrEarly":         "0-RTT data can be replayed",
}

// rpmgr is the module path of the repository's own code.
const rpmgr = "github.com/felix-homelab/rpmgr"

// exception allows one banned name in one function, Name or Type.Name, of one file of a module.
type exception struct{ Source, Func, Name string }

// exceptions are the allowed uses; every addition is a reviewed decision, named here.
var exceptions = []exception{
	// A route target whose user marked it unverified (ADR-0017) or pinned its key only (ADR-0018).
	// The gateway checks the route's traffic with it, and the connector the target's HTTPS health
	// check, which must succeed or fail as the traffic does (D133).
	{Source: rpmgr + "/internal/upstreamtls/upstreamtls.go", Func: "Settings.Config", Name: "InsecureSkipVerify"},
	// The connector reads the certificate a target presents, for its key pin (ADR-0018).
	{Source: rpmgr + "/internal/connector/probe.go", Func: "readCertificate", Name: "InsecureSkipVerify"},
}

// allowed reports whether an exception allows name in function fn of source: a file's module path
// and its path from the module's root, joined by "/"; "" for a file in no known module.
func allowed(source, fn, name string) bool {
	for _, e := range exceptions {
		if source != "" && e.Source == source && e.Func == fn && e.Name == name {
			return true
		}
	}
	return false
}

// sourceOf returns a file's module path and path from the module's root, joined by "/", or ""
// outside a module and inside a module that lies in another; modules caches the module path by
// directory.
func sourceOf(path string, modules map[string]string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	dir := moduleRoot(filepath.Dir(abs), modules)
	if dir == "" {
		return ""
	}
	if up := filepath.Dir(dir); up != dir && moduleRoot(up, modules) != "" {
		return "" // a module inside another
	}
	rel, err := filepath.Rel(dir, abs)
	if err != nil {
		return ""
	}
	return modules[dir] + "/" + filepath.ToSlash(rel)
}

// moduleRoot returns the nearest directory from dir up whose go.mod declares a module, "" if none;
// modules caches the module path by directory.
func moduleRoot(dir string, modules map[string]string) string {
	for ; ; dir = filepath.Dir(dir) {
		mod, ok := modules[dir]
		if !ok {
			b, err := os.ReadFile(filepath.Join(dir, "go.mod")) //nolint:gosec // G304: a developer tool that reads the tree it is given
			if err == nil {
				mod = modulePath(b)
			}
			modules[dir] = mod
		}
		if mod != "" {
			return dir
		}
		if filepath.Dir(dir) == dir {
			return ""
		}
	}
}

// modulePath returns the module path a go.mod file declares, "" if none.
func modulePath(gomod []byte) string {
	for line := range strings.Lines(string(gomod)) {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "module" {
			return strings.Trim(f[1], `"`)
		}
	}
	return ""
}

// funcName is a function's name, or Type.Name for a method.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return "?." + fd.Name.Name
}

// Finding is one use of a banned name.
type Finding struct {
	Pos  token.Position
	Name string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: %s is banned: %s", f.Pos, f.Name, banned[f.Name])
}

// CheckFile reports the banned names used in one Go source file, which lies in no known module,
// so no exception applies.
func CheckFile(fset *token.FileSet, name string, src any) ([]Finding, error) {
	return checkFile(fset, name, src, "")
}

// checkFile is CheckFile for a file of source (see allowed).
func checkFile(fset *token.FileSet, name string, src any, source string) ([]Finding, error) {
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []Finding
	inspect := func(node ast.Node, fn string) {
		report := func(id *ast.Ident) {
			if _, ok := banned[id.Name]; ok && !allowed(source, fn, id.Name) {
				out = append(out, Finding{Pos: fset.Position(id.Pos()), Name: id.Name})
			}
		}
		ast.Inspect(node, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.KeyValueExpr:
				if id, ok := n.Key.(*ast.Ident); ok {
					report(id)
				}
			case *ast.SelectorExpr:
				report(n.Sel)
			}
			return true
		})
	}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			inspect(fd, funcName(fd))
		} else {
			inspect(d, "")
		}
	}
	return out, nil
}

// CheckTree reports the banned names in every .go file below root, skipping testdata, vendor and
// hidden directories, as the go command does.
func CheckTree(root string) ([]Finding, error) {
	fset := token.NewFileSet()
	modules := map[string]string{}
	var out []Finding
	//nolint:gosec // G703: a developer tool that walks the directories it is given on purpose
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") ||
				strings.HasPrefix(name, "_") || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := checkFile(fset, path, nil, sourceOf(path, modules))
		if err != nil {
			return err
		}
		out = append(out, f...)
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pos.Filename != out[j].Pos.Filename {
			return out[i].Pos.Filename < out[j].Pos.Filename
		}
		return out[i].Pos.Offset < out[j].Pos.Offset
	})
	return out, err
}

func run(dirs []string, stdout, stderr io.Writer) int {
	if len(dirs) == 0 {
		dirs = []string{"."}
	}
	found := 0
	for _, dir := range dirs {
		findings, err := CheckTree(dir)
		if err != nil {
			fmt.Fprintf(stderr, "bannedapi: %v\n", err)
			return 2
		}
		for _, f := range findings {
			fmt.Fprintln(stdout, f)
		}
		found += len(findings)
	}
	if found > 0 {
		fmt.Fprintf(stderr, "bannedapi: %d use(s) of banned TLS or QUIC settings\n", found)
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
