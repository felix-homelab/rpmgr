// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func names(t *testing.T, src string) []string {
	t.Helper()
	findings, err := CheckFile(token.NewFileSet(), "x.go", src)
	if err != nil {
		t.Fatalf("CheckFile: %v", err)
	}
	var out []string
	for _, f := range findings {
		out = append(out, f.Name)
	}
	return out
}

func TestCheckFile(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string // comma-separated banned names, in source order
	}{
		{"composite literal key", `package p
import "crypto/tls"
var c = &tls.Config{InsecureSkipVerify: true}`, "InsecureSkipVerify"},
		{"key set to false is still banned", `package p
import "crypto/tls"
var c = tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: false}`, "InsecureSkipVerify"},
		{"field assignment", `package p
import "crypto/tls"
func f(c *tls.Config) { c.InsecureSkipVerify = true; c.Renegotiation = tls.RenegotiateNever }`,
			"InsecureSkipVerify,Renegotiation"},
		{"verify peer certificate", `package p
import "crypto/tls"
var c = tls.Config{VerifyPeerCertificate: nil}`, "VerifyPeerCertificate"},
		{"quic 0-RTT", `package p
type Config struct{ Allow0RTT bool }
var c = Config{Allow0RTT: true}
var l = quic.ListenEarly
var d = quic.DialAddrEarly
var e = quic.ListenAddrEarly
var g = quic.DialEarly`, "Allow0RTT,ListenEarly,DialAddrEarly,ListenAddrEarly,DialEarly"},
		{"comments and strings never match", `package p
// InsecureSkipVerify is never used; see VerifyConnection, not VerifyPeerCertificate.
var s = "InsecureSkipVerify"`, ""},
		{"allowed settings", `package p
import "crypto/tls"
var c = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, VerifyConnection: nil}`, ""},
		{"a local variable with a banned name is not a field", `package p
func f() { InsecureSkipVerify := true; _ = InsecureSkipVerify }`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Join(names(t, tt.src), ","); got != tt.want {
				t.Errorf("banned names = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExceptions: exactly one use is allowed, InsecureSkipVerify in UpstreamTLS.config of the
// rpmgr module's internal/gateway/upstreamtls.go (ADR-0017).
func TestExceptions(t *testing.T) {
	want := []exception{{Source: "github.com/felix-homelab/rpmgr/internal/gateway/upstreamtls.go", Func: "UpstreamTLS.config",
		Name: "InsecureSkipVerify"}}
	if !slices.Equal(exceptions, want) {
		t.Fatalf("exceptions %v, want %v", exceptions, want)
	}
}

// exceptionSrc uses InsecureSkipVerify in the allowed function (line 4) and elsewhere, and another
// banned name in the allowed function.
const exceptionSrc = `package gateway
import "crypto/tls"
type UpstreamTLS struct{}
func (u UpstreamTLS) config() *tls.Config { c := &tls.Config{}; c.InsecureSkipVerify = true; return c }
func (u *UpstreamTLS) pointer() { _ = tls.Config{InsecureSkipVerify: true} }
func other(c *tls.Config) { c.InsecureSkipVerify = true }
func (u UpstreamTLS) renegotiate(c *tls.Config) { c.Renegotiation = 0 }
var v = tls.Config{InsecureSkipVerify: true}
`

// TestCheckTree_Exception: the allowed use passes only in its function of its file of the rpmgr
// module, whichever directory the check starts in. Every other use in that file, the same function
// in another file of the package, a path that only ends alike, a spike's module with the same
// layout, a nested module that declares rpmgr's own path, and a file in no module are still
// reported.
func TestCheckTree_Exception(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "go.mod"), "module github.com/felix-homelab/rpmgr\n\ngo 1.26\n")
	write(t, filepath.Join(root, "internal", "gateway", "upstreamtls.go"), exceptionSrc)
	write(t, filepath.Join(root, "internal", "gateway", "http.go"), exceptionSrc)
	write(t, filepath.Join(root, "x", "internal", "gateway", "upstreamtls.go"), exceptionSrc)
	write(t, filepath.Join(root, "spikes", "s9", "go.mod"), "module \"github.com/felix-homelab/rpmgr/spikes/s9\"\n")
	write(t, filepath.Join(root, "spikes", "s9", "internal", "gateway", "upstreamtls.go"), exceptionSrc)
	write(t, filepath.Join(root, "tools", "x", "go.mod"), "module github.com/felix-homelab/rpmgr\n")
	write(t, filepath.Join(root, "tools", "x", "internal", "gateway", "upstreamtls.go"), exceptionSrc)
	lines := func(dir string) map[string]string {
		t.Helper()
		findings, err := CheckTree(dir)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, f := range findings {
			rel, _ := filepath.Rel(root, f.Pos.Filename)
			got[filepath.ToSlash(rel)] += strconv.Itoa(f.Pos.Line)
		}
		return got
	}
	want := map[string]string{"internal/gateway/upstreamtls.go": "5678", "internal/gateway/http.go": "45678",
		"x/internal/gateway/upstreamtls.go": "45678", "spikes/s9/internal/gateway/upstreamtls.go": "45678",
		"tools/x/internal/gateway/upstreamtls.go": "45678"}
	if got := lines(root); !maps.Equal(got, want) {
		t.Errorf("from the root: %v, want %v", got, want)
	}
	if got := lines(filepath.Join(root, "internal", "gateway")); got["internal/gateway/upstreamtls.go"] != "5678" {
		t.Errorf("from the package: %v", got)
	}
	if got := strings.Join(names(t, exceptionSrc), ","); got != strings.Repeat("InsecureSkipVerify,", 2)+"InsecureSkipVerify,Renegotiation,InsecureSkipVerify" {
		t.Errorf("a file in no module: %s", got)
	}
}

func TestCheckFileSyntaxError(t *testing.T) {
	if _, err := CheckFile(token.NewFileSet(), "x.go", "package p\nfunc {"); err == nil {
		t.Error("CheckFile accepted a file with a syntax error")
	}
}

func write(t *testing.T, path, src string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	root := t.TempDir()
	bad := "package p\nimport \"crypto/tls\"\nvar c = tls.Config{InsecureSkipVerify: true}\n"
	write(t, filepath.Join(root, "ok", "ok.go"), "package ok\n")
	write(t, filepath.Join(root, "testdata", "bad.go"), bad) // skipped, like the go command does
	write(t, filepath.Join(root, ".hidden", "bad.go"), bad)  // skipped
	write(t, filepath.Join(root, "notgo.txt"), bad)          // not Go

	var out, errOut bytes.Buffer
	if code := run([]string{root}, &out, &errOut); code != 0 {
		t.Fatalf("clean tree: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}

	write(t, filepath.Join(root, "pkg", "bad.go"), bad)
	out.Reset()
	errOut.Reset()
	if code := run([]string{root}, &out, &errOut); code != 1 {
		t.Fatalf("tree with a banned name: exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), "bad.go:3:") || !strings.Contains(out.String(), "InsecureSkipVerify is banned") {
		t.Errorf("finding not reported with position and reason: %q", out.String())
	}

	write(t, filepath.Join(root, "broken", "broken.go"), "package broken\nfunc {")
	if code := run([]string{root}, &out, &errOut); code != 2 {
		t.Errorf("tree with a syntax error: exit %d, want 2", code)
	}
	if code := run([]string{filepath.Join(root, "missing")}, &out, &errOut); code != 2 {
		t.Errorf("missing directory: exit %d, want 2", code)
	}
}
