// SPDX-License-Identifier: Apache-2.0

package release_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func key(t *testing.T, text string) release.PublicKey {
	t.Helper()
	k, err := release.ParsePublicKey(text)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// during is a time at which the test vectors' statement is valid.
var during = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

// TestMinisignVectors: the chain made with minisign 0.12 itself (testdata, made with throwaway
// keys) verifies, and its artifact matches; its legacy (Ed) signature is refused.
func TestMinisignVectors(t *testing.T) {
	root := key(t, string(read(t, "root.pub")))
	m, err := release.Verify([]release.PublicKey{root}, read(t, "statement.json"), read(t, "statement.json.minisig"),
		read(t, "manifest.json"), read(t, "manifest.json.minisig"), during)
	if err != nil {
		t.Fatal(err)
	}
	if m.Seq != 87 || m.Version != "1.4.2" || m.Floor != "1.3.0" || m.Channel != release.Stable || len(m.Artifacts) != 1 {
		t.Fatalf("manifest %+v", m)
	}
	a, err := m.Artifact("linux", "amd64", "full")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Check(bytes.NewReader(read(t, "artifact.bin"))); err != nil {
		t.Fatal(err)
	}
	if root.String() != strings.Split(strings.TrimSpace(string(read(t, "root.pub"))), "\n")[1] || len(root.Fingerprint()) != 64 {
		t.Errorf("key forms %s %s", root.String(), root.Fingerprint())
	}
	if !strings.Contains(string(read(t, "root.pub")), "minisign public key "+root.IDString()) {
		t.Errorf("key ID %s is not the one minisign prints", root.IDString())
	}
	_, err = release.Verify([]release.PublicKey{root}, read(t, "statement.json"), read(t, "statement.json.minisig"),
		read(t, "manifest.json"), read(t, "manifest.json.legacy-minisig"), during)
	if !errors.Is(err, release.ErrSignature) || !strings.Contains(err.Error(), "prehashed") {
		t.Errorf("a legacy signature: %v", err)
	}
}

// TestVerifyRefuses: a changed file or comment, an unknown key, a statement outside its validity,
// one that is too long or malformed, and a build without roots are refused.
func TestVerifyRefuses(t *testing.T) {
	root := key(t, string(read(t, "root.pub")))
	roots := []release.PublicKey{root}
	st, stSig := read(t, "statement.json"), read(t, "statement.json.minisig")
	man, manSig := read(t, "manifest.json"), read(t, "manifest.json.minisig")
	flip := func(b []byte, old, new string) []byte {
		return bytes.Replace(bytes.Clone(b), []byte(old), []byte(new), 1)
	}
	other := key(t, releasetest.Key("other").Public())
	for name, tc := range map[string]struct {
		roots            []release.PublicKey
		st, stSig, m, mS []byte
		now              time.Time
	}{
		"a changed manifest":             {roots, st, stSig, flip(man, `"seq":87`, `"seq":88`), manSig, during},
		"a changed trusted comment":      {roots, st, stSig, man, flip(manSig, "rpmgr 1.4.2", "rpmgr 9.9.9"), during},
		"a changed statement":            {roots, flip(st, "2027-10-01", "2028-10-01"), stSig, man, manSig, during},
		"a statement of an unknown root": {[]release.PublicKey{other}, st, stSig, man, manSig, during},
		"a manifest of the root key":     {roots, st, stSig, man, stSig, during},
		"no root keys":                   {nil, st, stSig, man, manSig, during},
		"an expired statement":           {roots, st, stSig, man, manSig, time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)},
		"a statement not yet valid":      {roots, st, stSig, man, manSig, time.Date(2026, 9, 30, 23, 59, 59, 0, time.UTC)},
		"not a signature file":           {roots, st, []byte("untrusted comment: x\n"), man, manSig, during},
	} {
		if _, err := release.Verify(tc.roots, tc.st, tc.stSig, tc.m, tc.mS, tc.now); !errors.Is(err, release.ErrSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}

	r, s := releasetest.Key("root"), releasetest.Key("signing")
	rootKeys := []release.PublicKey{key(t, r.Public())}
	sign := func(statement string) error {
		_, err := release.Verify(rootKeys, []byte(statement), r.Sign([]byte(statement)), man, s.Sign(man), during)
		return err
	}
	good := `{"statement":1,"signer":"` + s.Public() + `","not_before":"2026-10-01T00:00:00Z","not_after":"2027-10-01T00:00:00Z"}`
	if err := sign(good); err != nil {
		t.Fatalf("a good statement: %v", err)
	}
	for name, text := range map[string]string{
		"13 months":       strings.Replace(good, "2027-10-01", "2027-11-01", 1),
		"no time":         strings.Replace(good, "2027-10-01", "2026-10-01", 1),
		"format 2":        strings.Replace(good, `"statement":1`, `"statement":2`, 1),
		"an unknown key":  strings.Replace(good, `"statement":1`, `"statement":1,"scope":"all"`, 1),
		"a bad key":       strings.Replace(good, s.Public(), "RWQ=", 1),
		"not JSON at all": "statement",
	} {
		if err := sign(text); err == nil {
			t.Errorf("a statement with %s was accepted", name)
		}
	}
}

// signed returns a manifest signed through a test chain, changed by edit.
func signed(t *testing.T, edit func(*release.Manifest)) (*release.Manifest, error) {
	t.Helper()
	r, s := releasetest.Key("root"), releasetest.Key("signing")
	st := []byte(`{"statement":1,"signer":"` + s.Public() + `","not_before":"2026-10-01T00:00:00Z","not_after":"2027-10-01T00:00:00Z"}`)
	m := release.Manifest{Seq: 5, Version: "1.4.2", Floor: "1.3.0", Channel: release.Stable, IssuedAt: during,
		Artifacts: []release.Artifact{{OS: "linux", Arch: "arm64", Variant: "full", SHA256: strings.Repeat("ab", 32), Size: 10}}}
	edit(&m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return release.Verify([]release.PublicKey{key(t, r.Public())}, st, r.Sign(st), b, s.Sign(b), during)
}

// TestManifestChecked: a signed manifest must still be well-formed.
func TestManifestChecked(t *testing.T) {
	if _, err := signed(t, func(*release.Manifest) {}); err != nil {
		t.Fatal(err)
	}
	if _, err := signed(t, func(m *release.Manifest) { m.Version, m.Channel = "1.5.0-rc.1", release.Prerelease }); err != nil {
		t.Errorf("a pre-release: %v", err)
	}
	for name, edit := range map[string]func(*release.Manifest){
		"seq 0":                    func(m *release.Manifest) { m.Seq = 0 },
		"no issue time":            func(m *release.Manifest) { m.IssuedAt = time.Time{} },
		"no artifacts":             func(m *release.Manifest) { m.Artifacts = nil },
		"a short version":          func(m *release.Manifest) { m.Version = "1.4" },
		"a v prefix":               func(m *release.Manifest) { m.Version = "v1.4.2" },
		"build metadata":           func(m *release.Manifest) { m.Version = "1.4.2+abc" },
		"a floor above it":         func(m *release.Manifest) { m.Floor = "1.4.3" },
		"an unknown channel":       func(m *release.Manifest) { m.Channel = "beta" },
		"a stable pre-release":     func(m *release.Manifest) { m.Version = "1.5.0-rc.1" },
		"an upper-case SHA-256":    func(m *release.Manifest) { m.Artifacts[0].SHA256 = strings.Repeat("AB", 32) },
		"a short SHA-256":          func(m *release.Manifest) { m.Artifacts[0].SHA256 = "ab" },
		"an empty artifact":        func(m *release.Manifest) { m.Artifacts[0].Size = 0 },
		"an artifact without OS":   func(m *release.Manifest) { m.Artifacts[0].OS = "" },
		"an artifact without arch": func(m *release.Manifest) { m.Artifacts[0].Arch = "" },
		"a path in the arch":       func(m *release.Manifest) { m.Artifacts[0].Arch = "../x" },
		"an upper-case variant":    func(m *release.Manifest) { m.Artifacts[0].Variant = "Full" },
	} {
		if _, err := signed(t, edit); err == nil {
			t.Errorf("a manifest with %s was accepted", name)
		}
	}
}

// TestAccept: the seq and floor rules of docs/04-security.md, "Release signing".
func TestAccept(t *testing.T) {
	m := func(seq uint64, version, floor, channel string) *release.Manifest {
		return &release.Manifest{Seq: seq, Version: version, Floor: floor, Channel: channel}
	}
	for _, tc := range []struct {
		name    string
		from    release.State
		m       *release.Manifest
		channel string
		want    release.State
		refused bool
	}{
		{"a new host", release.State{}, m(5, "1.4.2", "1.3.0", release.Stable), release.Stable, release.State{Seq: 5, Floor: "1.3.0"}, false},
		{"a newer release", release.State{Seq: 5, Floor: "1.3.0"}, m(6, "1.5.0", "1.4.0", release.Stable), release.Stable, release.State{Seq: 6, Floor: "1.4.0"}, false},
		{"a replay", release.State{Seq: 6, Floor: "1.4.0"}, m(5, "1.4.2", "1.3.0", release.Stable), release.Stable, release.State{Seq: 6, Floor: "1.4.0"}, true},
		{"the same manifest again", release.State{Seq: 6, Floor: "1.4.0"}, m(6, "1.5.0", "1.4.0", release.Stable), release.Stable, release.State{Seq: 6, Floor: "1.4.0"}, false},
		{"the same seq below the floor", release.State{Seq: 6, Floor: "1.5.0"}, m(6, "1.4.9", "1.4.0", release.Stable), release.Stable, release.State{Seq: 6, Floor: "1.5.0"}, true},
		{"the same seq never lowers the floor", release.State{Seq: 6, Floor: "1.5.0"}, m(6, "1.5.1", "1.4.0", release.Stable), release.Stable, release.State{Seq: 6, Floor: "1.5.0"}, false},
		{"a signed downgrade", release.State{Seq: 6, Floor: "1.5.0"}, m(7, "1.4.9", "1.4.0", release.Stable), release.Stable, release.State{Seq: 7, Floor: "1.4.0"}, false},
		{"a pre-release on a stable host", release.State{}, m(8, "1.6.0-rc.1", "1.5.0", release.Prerelease), release.Stable, release.State{}, true},
		{"a pre-release on a pre-release host", release.State{}, m(8, "1.6.0-rc.1", "1.5.0", release.Prerelease), release.Prerelease, release.State{Seq: 8, Floor: "1.5.0"}, false},
		{"a release on a pre-release host", release.State{Seq: 8, Floor: "1.5.0"}, m(9, "1.6.0", "1.5.0", release.Stable), release.Prerelease, release.State{Seq: 9, Floor: "1.5.0"}, false},
	} {
		got, err := tc.from.Accept(tc.m, tc.channel)
		if errors.Is(err, release.ErrRefused) != tc.refused || got != tc.want {
			t.Errorf("%s: %+v %v", tc.name, got, err)
		}
	}
}

// TestArtifactCheck: an artifact must have the manifest's size and SHA-256; a read error is
// reported; no more than one byte beyond the size is read.
func TestArtifactCheck(t *testing.T) {
	m, err := release.Verify([]release.PublicKey{key(t, string(read(t, "root.pub")))}, read(t, "statement.json"),
		read(t, "statement.json.minisig"), read(t, "manifest.json"), read(t, "manifest.json.minisig"), during)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Artifact("linux", "arm64", "full"); err == nil {
		t.Error("an artifact the manifest does not list")
	}
	a, _ := m.Artifact("linux", "amd64", "full")
	file := read(t, "artifact.bin")
	for name, r := range map[string]*bytes.Reader{
		"a short file":    bytes.NewReader(file[:len(file)-1]),
		"a long file":     bytes.NewReader(append(bytes.Clone(file), 'x')),
		"another content": bytes.NewReader(bytes.ToUpper(file)),
	} {
		if err := a.Check(r); err == nil {
			t.Errorf("%s matched", name)
		}
	}
	if err := a.Check(iotest.ErrReader(errors.New("disk"))); err == nil || !strings.Contains(err.Error(), "disk") {
		t.Errorf("a read error: %v", err)
	}
	endless := &countingReader{}
	_ = a.Check(endless)
	if endless.n > a.Size+1 {
		t.Errorf("read %d bytes of a %d-byte artifact", endless.n, a.Size)
	}
}

type countingReader struct{ n int64 }

func (c *countingReader) Read(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// TestRoots: release builds have no roots until the interim keys are added (D48); rpmgrtest
// builds have the two test roots, with which a test chain verifies (D60).
func TestRoots(t *testing.T) {
	roots := release.Roots()
	if !release.TestBuild {
		if len(roots) != 0 {
			t.Fatalf("roots %v", roots)
		}
		return
	}
	if len(roots) != 2 || roots[0].String() != releasetest.Key("root 1").Public() || roots[1].String() != releasetest.Key("root 2").Public() {
		t.Fatalf("test roots %v", roots)
	}
}

// TestParsePublicKey: only minisign Ed25519 public keys are read.
func TestParsePublicKey(t *testing.T) {
	good := releasetest.Key("k").Public()
	for _, text := range []string{good, "untrusted comment: minisign public key\n" + good + "\n"} {
		if _, err := release.ParsePublicKey(text); err != nil {
			t.Errorf("%q: %v", text, err)
		}
	}
	for _, text := range []string{"", "not base64!", good[:20], "untrusted comment: x\n" + good + "\n" + good, strings.Replace(good, "RW", "RU", 1)} {
		if _, err := release.ParsePublicKey(text); err == nil {
			t.Errorf("%q was read", text)
		}
	}
}
