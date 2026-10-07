// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newKEK(t *testing.T) KEK {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	k, err := NewKEK(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newSealer(t *testing.T, cur KEK, prev ...KEK) *Sealer {
	t.Helper()
	s, err := NewSealer(cur, prev...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var where = Context{Table: "ca_keys", Column: "key_enc", RowID: "cak_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R"}

func TestSealOpen(t *testing.T) {
	s := newSealer(t, newKEK(t))
	for _, plain := range []string{"", "x", strings.Repeat("k", 4096)} {
		sealed, err := s.Seal(where, New(plain))
		if err != nil {
			t.Fatal(err)
		}
		// A short plaintext can occur in random ciphertext by chance; a long one cannot.
		if len(plain) >= 8 && bytes.Contains(sealed, []byte(plain)) {
			t.Fatal("sealed bytes contain the plaintext")
		}
		got, err := s.Open(where, sealed)
		if err != nil || got.Reveal() != plain {
			t.Errorf("Open = %q, %v; want %q", got.Reveal(), err, plain)
		}
	}
}

func TestSealIsRandomised(t *testing.T) {
	s := newSealer(t, newKEK(t))
	a, _ := s.Seal(where, New("same"))
	b, _ := s.Seal(where, New("same"))
	if bytes.Equal(a, b) {
		t.Error("two seals of the same secret are identical")
	}
}

func TestOpenRefuses(t *testing.T) {
	kek := newKEK(t)
	s := newSealer(t, kek)
	sealed, err := s.Seal(where, New("secret"))
	if err != nil {
		t.Fatal(err)
	}
	other := []Context{
		{Table: "ca_keys", Column: "key_enc", RowID: "cak_other"},
		{Table: "ca_keys", Column: "other", RowID: where.RowID},
		{Table: "other", Column: "key_enc", RowID: where.RowID},
		// Without length prefixes these two would encode alike.
		{Table: "ca_keyskey_enc", Column: "", RowID: where.RowID},
	}
	for _, ctx := range other {
		if _, err := s.Open(ctx, sealed); !errors.Is(err, ErrOpen) {
			t.Errorf("Open with context %+v: %v, want ErrOpen", ctx, err)
		}
	}
	for i := range sealed {
		tampered := append([]byte(nil), sealed...)
		tampered[i] ^= 0x01
		if _, err := s.Open(where, tampered); !errors.Is(err, ErrOpen) {
			t.Fatalf("byte %d flipped: %v, want ErrOpen", i, err)
		}
	}
	for _, n := range []int{0, 1, headerLen, len(sealed) - 1} {
		if _, err := s.Open(where, sealed[:n]); !errors.Is(err, ErrOpen) {
			t.Errorf("truncated to %d bytes: %v, want ErrOpen", n, err)
		}
	}
	if _, err := newSealer(t, newKEK(t)).Open(where, sealed); !errors.Is(err, ErrOpen) {
		t.Errorf("Open with another KEK: %v, want ErrOpen", err)
	}
}

func TestRotation(t *testing.T) {
	old, cur := newKEK(t), newKEK(t)
	sealed, _ := newSealer(t, old).Seal(where, New("rotate me"))

	s := newSealer(t, cur, old)
	if got, err := s.Open(where, sealed); err != nil || got.Reveal() != "rotate me" {
		t.Fatalf("Open with the previous KEK = %q, %v", got.Reveal(), err)
	}
	rewrapped, err := s.Rewrap(where, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := KEKVersion(rewrapped); v != cur.Version() {
		t.Errorf("KEKVersion after rewrap = %s, want %s", v, cur.Version())
	}
	// The encrypted secret itself is unchanged; only the wrapped data key differs.
	if !bytes.Equal(rewrapped[headerLen:], sealed[headerLen:]) {
		t.Error("rewrap changed the encrypted secret")
	}
	if got, err := newSealer(t, cur).Open(where, rewrapped); err != nil || got.Reveal() != "rotate me" {
		t.Errorf("Open with only the new KEK = %q, %v", got.Reveal(), err)
	}
	if again, _ := s.Rewrap(where, rewrapped); !bytes.Equal(again, rewrapped) {
		t.Error("rewrapping a secret already under the current KEK changed it")
	}
	if _, err := s.Rewrap(Context{Table: "x"}, sealed); !errors.Is(err, ErrOpen) {
		t.Errorf("Rewrap with the wrong context: %v, want ErrOpen", err)
	}
}

func TestKEKVersionAndErrors(t *testing.T) {
	k := newKEK(t)
	if len(k.Version()) != 16 {
		t.Errorf("Version() = %q, want 16 hex digits", k.Version())
	}
	if _, err := KEKVersion([]byte{2}); !errors.Is(err, ErrOpen) {
		t.Errorf("KEKVersion of garbage: %v", err)
	}
	if _, err := NewKEK(make([]byte, 31)); err == nil {
		t.Error("NewKEK accepted a 31-byte key")
	}
	if _, err := NewSealer(KEK{}); err == nil {
		t.Error("NewSealer accepted no KEK")
	}
	if _, err := NewSealer(k, KEK{}); err == nil {
		t.Error("NewSealer accepted an empty previous KEK")
	}
	if _, err := newSealer(t, k).Seal(where, New(strings.Repeat("x", maxSealSize+1))); err == nil {
		t.Error("Seal accepted a secret above the size limit")
	}
	if strings.Contains(ErrOpen.Error(), "ca_keys") {
		t.Error("ErrOpen names the context")
	}
}

func writeKEK(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadKEKFile(t *testing.T) {
	dir := t.TempDir()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	good := writeKEK(t, dir, "kek", key+"\n", 0o600)
	k, err := LoadKEKFile(good)
	if err != nil {
		t.Fatalf("LoadKEKFile: %v", err)
	}
	want, _ := NewKEK(bytes.Repeat([]byte{7}, 32))
	if k.Version() != want.Version() {
		t.Error("loaded KEK has another version")
	}
	if _, err := LoadKEKFile(writeKEK(t, dir, "ro", key, 0o400)); err != nil {
		t.Errorf("mode 0400 refused: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKEKFile(link); err != nil {
		t.Errorf("symbolic link to a good file refused: %v", err)
	}
	for name, path := range map[string]string{
		"group-readable": writeKEK(t, dir, "g", key, 0o640),
		"world-readable": writeKEK(t, dir, "w", key, 0o644),
		"not base64":     writeKEK(t, dir, "b", "not base64!", 0o600),
		"31 bytes":       writeKEK(t, dir, "s", base64.StdEncoding.EncodeToString(make([]byte, 31)), 0o600),
		"too large":      writeKEK(t, dir, "l", strings.Repeat("A", 2000), 0o600),
		"empty":          writeKEK(t, dir, "e", "", 0o600),
		"missing":        filepath.Join(dir, "missing"),
		"directory":      dir,
	} {
		if _, err := LoadKEKFile(path); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), key) {
			t.Errorf("%s: error contains the key", name)
		}
	}
}

func TestLoadSystemdCredential(t *testing.T) {
	dir := t.TempDir()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	writeKEK(t, dir, "rpmgr-kek", key, 0o400)
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "CREDENTIALS_DIRECTORY" {
				return v
			}
			return ""
		}
	}
	if _, err := LoadSystemdCredential("rpmgr-kek", env(dir)); err != nil {
		t.Errorf("credential refused: %v", err)
	}
	if _, err := LoadSystemdCredential("rpmgr-kek", env("")); err == nil {
		t.Error("accepted without CREDENTIALS_DIRECTORY")
	}
	for _, name := range []string{"", ".", "..", "../etc/passwd", "a/b", `a\b`} {
		if _, err := LoadSystemdCredential(name, env(dir)); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if _, err := LoadSystemdCredential("other", env(dir)); err == nil {
		t.Error("missing credential accepted")
	}
}
