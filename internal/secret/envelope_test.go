// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	for _, n := range []int{0, 1, 4, minV2Header, minV2Header + 8 + 60, len(sealed) - 1} {
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
	n := nonceLen + len("rotate me") + tagLen
	if v, _ := KEKVersion(rewrapped); v != cur.Version() {
		t.Errorf("KEKVersion after rewrap = %s, want %s", v, cur.Version())
	}
	// The encrypted secret itself is unchanged; only the wrapped data key differs.
	if !bytes.Equal(rewrapped[len(rewrapped)-n:], sealed[len(sealed)-n:]) {
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
	if _, err := KEKVersion([]byte{9}); !errors.Is(err, ErrOpen) {
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

// TestLoadSystemdCredential_GroupReadable (#455): newer systemd versions pass a service that runs
// as another user its credential with mode 0440, in the service's group. A credential that its own
// group may read is accepted; one other users may read, or its group may write, is not; and a KEK
// file is still held to 0600 or 0400.
func TestLoadSystemdCredential_GroupReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix groups")
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "CREDENTIALS_DIRECTORY" {
				return v
			}
			return ""
		}
	}
	for _, c := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o440, true}, {0o400, true}, {0o444, false}, {0o460, false}, {0o404, false}} {
		dir := t.TempDir() // the file gets this process's group
		writeKEK(t, dir, "rpmgr-kek", key, c.mode)
		_, err := LoadSystemdCredential("rpmgr-kek", env(dir))
		if (err == nil) != c.ok {
			t.Errorf("credential with mode %04o: %v, want accepted %v", c.mode, err, c.ok)
		}
	}
	dir := t.TempDir()
	writeKEK(t, dir, "kek", key, 0o440)
	if _, err := LoadKEKFile(filepath.Join(dir, "kek")); err == nil {
		t.Error("a KEK file with mode 0440 accepted")
	}
}

// sealV1 writes a Phase 1 value, to test that it stays readable.
func sealV1(t *testing.T, k KEK, c Context, plain string) []byte {
	t.Helper()
	dataKey := bytes.Repeat([]byte{7}, keyLen)
	out := append([]byte{formatV1}, k.id[:]...)
	out, err := sealGCM(out, []byte(k.key.Reveal()), dataKey, wrapADV1(c, k.id))
	if err != nil {
		t.Fatal(err)
	}
	out, err = sealGCM(out, dataKey, []byte(plain), dataAD(formatV1, c))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestV2Layout: a sealed value is laid out as docs/04-security.md, "Envelope format v2", says.
func TestV2Layout(t *testing.T) {
	k := newKEK(t)
	sealed, err := newSealer(t, k).Seal(where, New("abc"))
	if err != nil {
		t.Fatal(err)
	}
	want := 1 + 1 + 2 + 8 + 2 + 60 + 12 + 3 + 16
	if len(sealed) != want {
		t.Fatalf("len = %d, want %d", len(sealed), want)
	}
	if sealed[0] != 2 || sealed[1] != 1 || binary.BigEndian.Uint16(sealed[2:]) != 8 ||
		!bytes.Equal(sealed[4:12], k.id[:]) || binary.BigEndian.Uint16(sealed[12:]) != 60 {
		t.Errorf("header % x", sealed[:14])
	}
}

// TestV1V2: a version 1 value opens, is rewrapped into version 2 (also under the same KEK), and
// version 2 values do not open as version 1 or the other way round.
func TestV1V2(t *testing.T) {
	k := newKEK(t)
	s := newSealer(t, k)
	v1 := sealV1(t, k, where, "old")
	if got, err := s.Open(where, v1); err != nil || got.Reveal() != "old" {
		t.Fatalf("Open v1 = %q, %v", got.Reveal(), err)
	}
	if v, err := KEKVersion(v1); err != nil || v != k.Version() {
		t.Errorf("KEKVersion v1 = %s, %v", v, err)
	}
	re, err := s.Rewrap(where, v1)
	if err != nil || re[0] != formatV2 {
		t.Fatalf("Rewrap v1: format %v, %v", re[:1], err)
	}
	if got, err := s.Open(where, re); err != nil || got.Reveal() != "old" {
		t.Errorf("Open rewrapped = %q, %v", got.Reveal(), err)
	}
	if v, _ := KEKVersion(re); v != k.Version() {
		t.Errorf("KEKVersion v2 = %s", v)
	}
	// Another KEK takes a v1 value over too.
	cur := newKEK(t)
	if re, err = newSealer(t, cur, k).Rewrap(where, v1); err != nil || re[0] != formatV2 {
		t.Fatalf("Rewrap v1 to another KEK: %v", err)
	}
	if got, err := newSealer(t, cur).Open(where, re); err != nil || got.Reveal() != "old" {
		t.Errorf("Open under only the new KEK = %q, %v", got.Reveal(), err)
	}
	// A version byte changed is a value of the other layout and does not open.
	v2, _ := s.Seal(where, New("new"))
	for _, b := range [][]byte{append([]byte{formatV1}, v2[1:]...), append([]byte{formatV2}, v1[1:]...), append([]byte{3}, v2[1:]...)} {
		if _, err := s.Open(where, b); !errors.Is(err, ErrOpen) {
			t.Errorf("Open with a wrong version byte: %v", err)
		}
	}
	// A v1 value moved to another row does not open or rewrap.
	if _, err := s.Rewrap(Context{Table: "x"}, v1); !errors.Is(err, ErrOpen) {
		t.Errorf("Rewrap v1 for another row: %v", err)
	}
}

// TestV2Bounds: values shorter than their lengths say, longer than the bounds, or of an unknown
// kind do not open, and none is told apart from any other.
func TestV2Bounds(t *testing.T) {
	k := newKEK(t)
	s := newSealer(t, k)
	sealed, err := s.Seal(where, New("abc"))
	if err != nil {
		t.Fatal(err)
	}
	mod := func(f func(b []byte)) []byte {
		b := append([]byte(nil), sealed...)
		f(b)
		return b
	}
	cases := map[string][]byte{
		"kind 2 without a wrapper": mod(func(b []byte) { b[1] = 2 }),
		"kind 0":                   mod(func(b []byte) { b[1] = 0 }),
		"K zero":                   mod(func(b []byte) { binary.BigEndian.PutUint16(b[2:], 0) }),
		"K too long for the value": mod(func(b []byte) { binary.BigEndian.PutUint16(b[2:], 60000) }),
		"K above 256":              mod(func(b []byte) { binary.BigEndian.PutUint16(b[2:], 257) }),
		"K another KEK":            mod(func(b []byte) { b[4] ^= 1 }),
		"W zero":                   mod(func(b []byte) { binary.BigEndian.PutUint16(b[12:], 0) }),
		"W above 512":              mod(func(b []byte) { binary.BigEndian.PutUint16(b[12:], 513) }),
		"W 59":                     mod(func(b []byte) { binary.BigEndian.PutUint16(b[12:], 59) }),
		"W longer than the value":  mod(func(b []byte) { binary.BigEndian.PutUint16(b[12:], 400) }),
		"oversized":                append(append([]byte(nil), sealed...), make([]byte, maxSealSize+1)...),
		"only the header":          sealed[:14],
		"no secret":                sealed[:14+60+nonceLen],
	}
	for name, b := range cases {
		if _, err := s.Open(where, b); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: Open = %v, want ErrOpen", name, err)
		}
		if _, err := s.Rewrap(where, b); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: Rewrap = %v, want ErrOpen", name, err)
		}
	}
	for _, name := range []string{"K zero", "K too long for the value", "K above 256", "W zero", "W above 512", "oversized"} {
		if _, err := KEKVersion(cases[name]); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: KEKVersion = %v, want ErrOpen", name, err)
		}
	}
	// The largest secret seals and opens; one byte more is refused by Seal, and an oversized
	// value is refused before anything is decrypted.
	big, err := s.Seal(where, New(strings.Repeat("x", maxSealSize)))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Open(where, big); err != nil || len(got.Reveal()) != maxSealSize {
		t.Errorf("Open of the largest secret: %v", err)
	}
}

// fixedWrapper is a Wrapper of another kind, to check the interface and the AAD swap.
type fixedWrapper struct {
	kind  byte
	id    string
	calls *[]string
	down  error
}

func (w fixedWrapper) Kind() byte { return w.kind }
func (w fixedWrapper) ID() []byte { return []byte(w.id) }
func (w fixedWrapper) Wrap(_ context.Context, dk, aad []byte) ([]byte, error) {
	if w.down != nil {
		return nil, w.down
	}
	*w.calls = append(*w.calls, string(aad))
	return append([]byte("vault:v1:"), dk...), nil
}
func (w fixedWrapper) Unwrap(_ context.Context, wr, aad []byte) ([]byte, error) {
	if w.down != nil {
		return nil, w.down
	}
	if !bytes.HasPrefix(wr, []byte("vault:v1:")) || len(*w.calls) == 0 || (*w.calls)[len(*w.calls)-1] != string(aad) {
		return nil, ErrOpen
	}
	return wr[9:], nil
}

// TestWrapperInterface: Seal and Open go through the Wrapper with the secret's AAD, an error of
// the Wrapper that is not ErrOpen reaches the caller as it is, and rewrapping moves a value to
// the current Wrapper without touching the secret.
func TestWrapperInterface(t *testing.T) {
	var calls []string
	w := fixedWrapper{kind: KindTransit, id: "transit/rpmgr", calls: &calls}
	s, err := NewSealerWith(w)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal(where, New("tr"))
	if err != nil {
		t.Fatal(err)
	}
	if sealed[1] != KindTransit || binary.BigEndian.Uint16(sealed[2:]) != uint16(len("transit/rpmgr")) {
		t.Errorf("header % x", sealed[:20])
	}
	if v, _ := KEKVersion(sealed); v != "transit/rpmgr" {
		t.Errorf("KEKVersion = %q", v)
	}
	if got, err := s.Open(where, sealed); err != nil || got.Reveal() != "tr" {
		t.Errorf("Open = %q, %v", got.Reveal(), err)
	}
	if want := string(dataAD(formatV2, where)); calls[0] != want {
		t.Errorf("the wrapper got AAD %q, want %q", calls[0], want)
	}
	// The AAD swap: a value at another row gives the wrapper another AAD and does not open.
	if _, err := s.Open(Context{Table: where.Table, Column: where.Column, RowID: "other"}, sealed); !errors.Is(err, ErrOpen) {
		t.Errorf("Open at another row: %v", err)
	}
	// Down is not ErrOpen.
	errDown := errors.New("down")
	down, _ := NewSealerWith(fixedWrapper{kind: KindTransit, id: "transit/rpmgr", calls: &calls, down: errDown})
	if _, err := down.Open(where, sealed); !errors.Is(err, errDown) || errors.Is(err, ErrOpen) {
		t.Errorf("Open with the wrapper down: %v", err)
	}
	// Moving a Transit value to a local KEK keeps the encrypted secret.
	k := newKEK(t)
	both, _ := NewSealerWith(NewLocalWrapper(k), w)
	re, err := both.Rewrap(where, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := KEKVersion(re); v != k.Version() || !bytes.HasSuffix(re, sealed[len(sealed)-nonceLen-len("tr")-tagLen:]) {
		t.Errorf("Rewrap: version %s", v)
	}
	if got, err := newSealer(t, k).Open(where, re); err != nil || got.Reveal() != "tr" {
		t.Errorf("Open under the local KEK = %q, %v", got.Reveal(), err)
	}
	if _, err := NewSealerWith(nil); err == nil {
		t.Error("NewSealerWith accepted no wrapper")
	}
	if _, err := NewSealerWith(fixedWrapper{kind: 2, id: "", calls: &calls}); err == nil {
		t.Error("NewSealerWith accepted an empty identifier")
	}
}

// TestAADSwap: the local wrap is bound to the secret's AAD and the KEK identifier: a wrapped key
// cut from one value and put into another at another row does not open.
func TestAADSwap(t *testing.T) {
	k := newKEK(t)
	s := newSealer(t, k)
	other := Context{Table: where.Table, Column: where.Column, RowID: "cak_other"}
	a, _ := s.Seal(where, New("a"))
	b, _ := s.Seal(other, New("b"))
	// a's wrapped key with b's secret, and the reverse, each opened at its own row.
	const hdr = 14 + 60
	mixed := append(append([]byte(nil), a[:hdr]...), b[hdr:]...)
	if _, err := s.Open(where, mixed); !errors.Is(err, ErrOpen) {
		t.Errorf("a's key, b's secret at a: %v", err)
	}
	if _, err := s.Open(other, mixed); !errors.Is(err, ErrOpen) {
		t.Errorf("a's key, b's secret at b: %v", err)
	}
	// The wrapped key at another row does not unwrap.
	w := NewLocalWrapper(k)
	dk, err := w.Unwrap(context.Background(), a[14:hdr], dataAD(formatV2, where))
	if err != nil || len(dk) != keyLen {
		t.Fatalf("Unwrap at its own row: %v", err)
	}
	if _, err := w.Unwrap(context.Background(), a[14:hdr], dataAD(formatV2, other)); !errors.Is(err, ErrOpen) {
		t.Errorf("Unwrap at another row: %v", err)
	}
	// A version 1 wrapped key is not a version 2 one.
	if _, err := w.Unwrap(context.Background(), a[14:hdr], dataAD(formatV1, where)); !errors.Is(err, ErrOpen) {
		t.Errorf("Unwrap with the version 1 label: %v", err)
	}
}
