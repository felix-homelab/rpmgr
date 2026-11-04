// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tokenFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadToken(t *testing.T) {
	good := tokenFile(t, "  abc123def\n", 0o600)
	rep := &report{w: &bytes.Buffer{}}
	v, err := readToken(good, nil, rep)
	if err != nil || !v.EqualString("abc123def") {
		t.Fatalf("%v", err)
	}
	if v, err = readToken("-", strings.NewReader("from-stdin\n"), rep); err != nil || !v.EqualString("from-stdin") {
		t.Fatalf("%v", err)
	}
	for name, in := range map[string]string{
		"empty":       "",
		"blank":       " \n\n",
		"two words":   "abc def",
		"two lines":   "abc\ndef",
		"control":     "abc\x00def",
		"too long":    strings.Repeat("a", 4097),
		"binary junk": "\xff\xfe\x01",
	} {
		_, err := readToken(tokenFile(t, in, 0o600), nil, rep)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "abc") && name != "too long" {
			t.Errorf("%s: the error holds the content: %v", name, err)
		}
	}
	if _, err := readToken(filepath.Join(t.TempDir(), "missing"), nil, rep); err == nil {
		t.Error("a missing file was accepted")
	}
}

func TestReadTokenWarnsAboutOpenPermissions(t *testing.T) {
	var out bytes.Buffer
	p := tokenFile(t, "abc", 0o644)
	if err := os.Chmod(p, 0o644); err != nil { //nolint:gosec // G302: the test needs a token file others can read
		t.Fatal(err)
	}
	if _, err := readToken(p, nil, &report{w: &out}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "INFO SETUP") || strings.Contains(out.String(), "abc\n") {
		t.Fatalf("%q", out.String())
	}
}

func TestUsageErrors(t *testing.T) {
	tok := tokenFile(t, "secret-main-value", 0o600)
	under := tokenFile(t, "secret-under-value", 0o600)
	for name, args := range map[string][]string{
		"no arguments":           {},
		"missing under-scoped":   {"-zone", "z.example", "-token-file", tok},
		"token as argument":      {"-zone", "z.example", "-token-file", tok, "-under-scoped-token-file", under, "secret-main-value"},
		"zone given as its ID":   {"-zone", strings.Repeat("ab", 16), "-token-file", tok, "-under-scoped-token-file", under},
		"unknown flag":           {"-zone", "z.example", "-token", "secret-main-value"},
		"burst without confirm":  {"-zone", "z.example", "-token-file", tok, "-under-scoped-token-file", under, "-burst", "10"},
		"confirm without burst":  {"-zone", "z.example", "-token-file", tok, "-under-scoped-token-file", under, "-confirm-burst"},
		"burst too large":        {"-zone", "z.example", "-token-file", tok, "-under-scoped-token-file", under, "-burst", "999999", "-confirm-burst"},
		"negative burst":         {"-zone", "z.example", "-token-file", tok, "-under-scoped-token-file", under, "-burst", "-1"},
		"account token only":     {"-zone", "z.example", "-token-file", tok, "-under-scoped-token-file", under, "-account-token-file", tok},
		"account id only":        {"-zone", "z.example", "-token-file", tok, "-under-scoped-token-file", under, "-account-id", strings.Repeat("a", 32)},
		"two tokens from stdin":  {"-zone", "z.example", "-token-file", "-", "-under-scoped-token-file", "-"},
		"unreadable token file":  {"-zone", "z.example", "-token-file", filepath.Join(t.TempDir(), "none"), "-under-scoped-token-file", under},
		"empty token from stdin": {"-zone", "z.example", "-token-file", "-", "-under-scoped-token-file", under},
	} {
		var stdout, stderr bytes.Buffer
		code := runMain(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
		if all := stdout.String() + stderr.String(); strings.Contains(all, "secret-main-value") || strings.Contains(all, "secret-under-value") {
			t.Errorf("%s: a token is in the output: %s", name, all)
		}
	}
}
