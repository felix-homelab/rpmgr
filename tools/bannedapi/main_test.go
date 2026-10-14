// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"go/token"
	"os"
	"path/filepath"
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

// TestCheckFile_Exception: the one allowed use passes only with its name, in its function, in
// its file; anything else in that file, or that function anywhere else, is still reported.
func TestCheckFile_Exception(t *testing.T) {
	const src = `package gateway
import "crypto/tls"
type UpstreamTLS struct{}
func (u UpstreamTLS) config() *tls.Config { c := &tls.Config{}; c.InsecureSkipVerify = true; return c }
func (u *UpstreamTLS) pointer() { _ = tls.Config{InsecureSkipVerify: true} }
func other(c *tls.Config) { c.InsecureSkipVerify = true }
func (u UpstreamTLS) renegotiate(c *tls.Config) { c.Renegotiation = 0 }
var v = tls.Config{InsecureSkipVerify: true}`
	for _, tt := range []struct{ file, want string }{
		{"internal/gateway/upstreamtls.go", "pointer:5,other:6,renegotiate:7,var:8"},
		{"/src/rpmgr/internal/gateway/upstreamtls.go", "pointer:5,other:6,renegotiate:7,var:8"},
		{"internal/gateway/http.go", "config:4,pointer:5,other:6,renegotiate:7,var:8"},
		{"xinternal/gateway/upstreamtls.go", "config:4,pointer:5,other:6,renegotiate:7,var:8"},
	} {
		findings, err := CheckFile(token.NewFileSet(), tt.file, src)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range findings {
			got = append(got, map[int]string{4: "config", 5: "pointer", 6: "other", 7: "renegotiate", 8: "var"}[f.Pos.Line]+":"+strconv.Itoa(f.Pos.Line))
		}
		if strings.Join(got, ",") != tt.want {
			t.Errorf("%s: findings %v, want %s", tt.file, got, tt.want)
		}
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
