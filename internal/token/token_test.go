// SPDX-License-Identifier: Apache-2.0

package token_test

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/token"
)

var kinds = []token.Kind{token.Enrollment, token.PersonalAPI, token.ServiceAccount, token.Session, token.PasswordReset}

func newToken(t *testing.T, k token.Kind) string {
	t.Helper()
	s, err := token.New(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewAndParse(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range kinds {
		for i := 0; i < 250; i++ {
			s := newToken(t, k)
			if got, err := token.Parse(s); err != nil || got != k || len(s) != token.Len {
				t.Fatalf("Parse(%s) = %q, %v", s, got, err)
			}
			if seen[s] {
				t.Fatal("a token repeated")
			}
			seen[s] = true
		}
	}
	if _, err := token.New("xyz"); err == nil {
		t.Error("a token of an unknown kind")
	}
}

// TestSecretScannerRecognisesTokens: every kind matches the rpmgr-token rule of .gitleaks.toml, so
// a token committed by accident fails the secrets check.
func TestSecretScannerRecognisesTokens(t *testing.T) {
	cfg, err := os.ReadFile("../../.gitleaks.toml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^regex = '''(.*)'''$`).FindSubmatch(cfg)
	if m == nil || !strings.Contains(string(m[1]), "rpmgr_") {
		t.Fatal("no rpmgr-token rule in .gitleaks.toml")
	}
	rule := regexp.MustCompile(string(m[1]))
	for _, k := range kinds {
		s := newToken(t, k)
		if !rule.MatchString("token: " + s + "\n") {
			t.Errorf("the secret scanner misses %s", s)
		}
	}
}

// TestParse_DetectsTypos: changing any one character of a token, or swapping two neighbours,
// makes it fail its checksum or its form.
func TestParse_DetectsTypos(t *testing.T) {
	s := newToken(t, token.Enrollment)
	body := len("rpmgr_enr_")
	for i := body; i < len(s); i++ {
		if s[i] == '_' {
			continue
		}
		b := []byte(s)
		b[i] = map[bool]byte{true: 'A', false: 'B'}[b[i] != 'A']
		if _, err := token.Parse(string(b)); !errors.Is(err, token.ErrChecksum) {
			t.Fatalf("character %d changed: %v", i, err)
		}
		if i+1 < len(s) && s[i] != s[i+1] && s[i+1] != '_' {
			b := []byte(s)
			b[i], b[i+1] = b[i+1], b[i]
			if _, err := token.Parse(string(b)); !errors.Is(err, token.ErrChecksum) {
				t.Fatalf("characters %d and %d swapped: %v", i, i+1, err)
			}
		}
	}
}

func TestParse_Malformed(t *testing.T) {
	s := newToken(t, token.PersonalAPI)
	for name, bad := range map[string]string{
		"empty":             "",
		"other prefix":      "rpmgx" + s[5:],
		"unknown kind":      "rpmgr_abc" + s[9:],
		"too short":         s[:len(s)-1],
		"too long":          s + "A",
		"no separator":      s[:10] + "-" + s[11:],
		"no checksum mark":  s[:len(s)-7] + "-" + s[len(s)-6:],
		"not base62":        s[:20] + "+" + s[21:],
		"upper-case kind":   "rpmgr_PAT" + s[9:],
		"surrounding space": " " + s[:len(s)-1],
	} {
		if _, err := token.Parse(bad); !errors.Is(err, token.ErrMalformed) {
			t.Errorf("%s: %v, want ErrMalformed", name, err)
		}
	}
}

func TestHash(t *testing.T) {
	a, b := newToken(t, token.Session), newToken(t, token.Session)
	if h := token.Hash(a); len(h) != 32 || !bytes.Equal(h, token.Hash(a)) || bytes.Equal(h, token.Hash(b)) {
		t.Error("Hash is not a deterministic SHA-256 per token")
	}
}

func FuzzTokenParse(f *testing.F) {
	// A token of zeros, built at run time so that the secret scanner does not flag this file.
	f.Add("rpmgr_" + "enr_" + strings.Repeat("0", 43) + "_" + strings.Repeat("0", 6))
	for _, k := range kinds {
		s, err := token.New(k)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		k, err := token.Parse(s)
		if err == nil && (len(s) != token.Len || !strings.HasPrefix(s, "rpmgr_"+string(k)+"_")) {
			t.Fatalf("accepted %q as %q", s, k)
		}
	})
}
