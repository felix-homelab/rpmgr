// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"go/token"
	"os"
	"path/filepath"
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
