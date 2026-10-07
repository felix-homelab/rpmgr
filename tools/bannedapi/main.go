// SPDX-License-Identifier: Apache-2.0

// Command bannedapi fails when Go code names a TLS or QUIC setting that rpmgr bans
// (docs/12-testing-and-quality.md, "Security testing"): skipping certificate verification, 0-RTT,
// renegotiation, and checks in VerifyPeerCertificate, which resumed connections skip.
//
// It complements golangci-lint's forbidigo, which does not see the keys of composite literals
// such as tls.Config{InsecureSkipVerify: true}. Names are matched as composite-literal keys and as
// selectors (x.Name), so comments and strings never match.
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

// Finding is one use of a banned name.
type Finding struct {
	Pos  token.Position
	Name string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: %s is banned: %s", f.Pos, f.Name, banned[f.Name])
}

// CheckFile reports the banned names used in one Go source file.
func CheckFile(fset *token.FileSet, name string, src any) ([]Finding, error) {
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []Finding
	report := func(id *ast.Ident) {
		if _, ok := banned[id.Name]; ok {
			out = append(out, Finding{Pos: fset.Position(id.Pos()), Name: id.Name})
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
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
	return out, nil
}

// CheckTree reports the banned names in every .go file below root, skipping testdata, vendor and
// hidden directories, as the go command does.
func CheckTree(root string) ([]Finding, error) {
	fset := token.NewFileSet()
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
		f, err := CheckFile(fset, path, nil)
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
