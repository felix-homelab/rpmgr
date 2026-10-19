// SPDX-License-Identifier: Apache-2.0

package release_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/semver"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
)

func readF(f *testing.F, name string) []byte {
	f.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// FuzzVerifyChain: the minisign chain made with minisign 0.12 (testdata) verifies only as it was
// signed. Whatever the fuzzer changes in the statement, the manifest or their signature files, a
// chain that verifies has the very statement and manifest that were signed.
func FuzzVerifyChain(f *testing.F) {
	root, err := release.ParsePublicKey(string(readF(f, "root.pub")))
	if err != nil {
		f.Fatal(err)
	}
	st, stSig := readF(f, "statement.json"), readF(f, "statement.json.minisig")
	man, manSig := readF(f, "manifest.json"), readF(f, "manifest.json.minisig")
	f.Add(st, stSig, man, manSig)
	f.Add(st, stSig, man, readF(f, "manifest.json.legacy-minisig"))
	f.Add(st, stSig, man, stSig)
	f.Add(st, bytes.ReplaceAll(stSig, []byte("\n"), []byte("\r\n")), man, manSig)
	f.Fuzz(func(t *testing.T, st2, stSig2, man2, manSig2 []byte) {
		m, err := release.Verify([]release.PublicKey{root}, st2, stSig2, man2, manSig2, during)
		if err != nil {
			return
		}
		if !bytes.Equal(st2, st) || !bytes.Equal(man2, man) {
			t.Fatalf("a changed chain verified:\n%q\n%q", st2, man2)
		}
		if m.Check() != nil {
			t.Fatalf("Verify returned a manifest that Check refuses: %+v", m)
		}
	})
}

// FuzzManifest: a manifest that a valid chain signs is accepted only when it is well-formed
// (docs/04-security.md, "Release signing"), and then stays the same when written and read again.
// The signatures are made with test keys, so the fuzzer reaches the manifest's checks.
func FuzzManifest(f *testing.F) {
	r, s := releasetest.Key("root"), releasetest.Key("signing")
	roots := []release.PublicKey{mustKey(f, r.Public())}
	st := []byte(`{"statement":1,"signer":"` + s.Public() + `","not_before":"2026-10-01T00:00:00Z","not_after":"2027-10-01T00:00:00Z"}`)
	stSig := r.Sign(st)
	f.Add(readF(f, "manifest.json"))
	f.Add([]byte(`{"seq":3,"version":"1.5.0-rc.1","floor":"1.4.0","channel":"prerelease","issued_at":"2026-10-09T12:00:00Z","artifacts":[{"os":"linux","arch":"arm64","variant":"connector","sha256":"` + strings.Repeat("0a", 32) + `","size":1}],"later":true}`))
	f.Add([]byte(`{"seq":1,"version":"1.0.0","floor":"1.0.0","channel":"stable","issued_at":"2026-10-09T12:00:00Z","artifacts":[{"os":"../x","arch":"amd64","variant":"full","sha256":"` + strings.Repeat("A", 64) + `","size":-1}]}`))
	partRe := regexp.MustCompile(`^[a-z0-9]+$`)
	f.Fuzz(func(t *testing.T, man []byte) {
		m, err := release.Verify(roots, st, stSig, man, s.Sign(man), during)
		if err != nil {
			return
		}
		switch {
		case m.Seq == 0, m.IssuedAt.IsZero(), len(m.Artifacts) == 0:
			t.Fatalf("accepted without seq, issue time or artifacts: %q", man)
		case semver.Canonical("v"+m.Version) != "v"+m.Version, semver.Canonical("v"+m.Floor) != "v"+m.Floor,
			semver.Compare("v"+m.Floor, "v"+m.Version) > 0:
			t.Fatalf("accepted version %q with floor %q", m.Version, m.Floor)
		case m.Channel != release.Stable && m.Channel != release.Prerelease,
			m.Channel == release.Stable && semver.Prerelease("v"+m.Version) != "":
			t.Fatalf("accepted version %q on channel %q", m.Version, m.Channel)
		}
		for _, a := range m.Artifacts {
			sum, err := hex.DecodeString(a.SHA256)
			if !partRe.MatchString(a.OS) || !partRe.MatchString(a.Arch) || !partRe.MatchString(a.Variant) || a.Size <= 0 ||
				err != nil || len(sum) != 32 || hex.EncodeToString(sum) != a.SHA256 {
				t.Fatalf("accepted a bad artifact %+v", a)
			}
		}
		again, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		m2, err := release.Verify(roots, st, stSig, again, s.Sign(again), during)
		if err != nil {
			t.Fatalf("an accepted manifest, written again, is refused: %v\n%s", err, again)
		}
		if again2, _ := json.Marshal(m2); !bytes.Equal(again, again2) {
			t.Fatalf("an accepted manifest changed when written and read again:\n%s\n%s", again, again2)
		}
		// Accepting it never panics, whatever the state and channel.
		_, _ = release.State{Seq: m.Seq, Floor: m.Floor}.Accept(m, release.Stable)
		_, _ = release.State{}.Accept(m, release.Prerelease)
	})
}

// FuzzStatement: a signing-key statement signed by a root is accepted only in format 1, with a
// minisign key and a validity of at most 12 months that covers now; then the manifest must be
// signed by the key it names.
func FuzzStatement(f *testing.F) {
	r, s := releasetest.Key("root"), releasetest.Key("signing")
	roots := []release.PublicKey{mustKey(f, r.Public())}
	man := readF(f, "manifest.json")
	manSig := s.Sign(man)
	f.Add([]byte(`{"statement":1,"signer":"` + s.Public() + `","not_before":"2026-10-01T00:00:00Z","not_after":"2027-10-01T00:00:00Z"}`))
	f.Add([]byte(`{"statement":1,"signer":"` + s.Public() + `","not_before":"2026-10-01T00:00:00+14:00","not_after":"2027-10-01T00:00:00-12:00"}`))
	f.Add(readF(f, "statement.json"))
	f.Fuzz(func(t *testing.T, st []byte) {
		if _, err := release.Verify(roots, st, r.Sign(st), man, manSig, during); err != nil {
			return
		}
		var got release.Statement
		dec := json.NewDecoder(bytes.NewReader(st))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("accepted a statement that is not strict JSON: %v: %q", err, st)
		}
		k, err := release.ParsePublicKey(got.SigningKey)
		switch {
		case got.Statement != 1:
			t.Fatalf("accepted format %d", got.Statement)
		case err != nil || k.String() != s.Public():
			t.Fatalf("the manifest verified with a statement for key %q", got.SigningKey)
		case got.NotAfter.Sub(got.NotBefore) > release.StatementLifetime, !got.NotBefore.Before(got.NotAfter),
			during.Before(got.NotBefore), !during.Before(got.NotAfter):
			t.Fatalf("accepted a statement valid from %s to %s at %s", got.NotBefore, got.NotAfter, during.Format(time.RFC3339))
		}
	})
}

// FuzzParsePublicKey: a key that parses is an Ed25519 key that reads back from its own form.
func FuzzParsePublicKey(f *testing.F) {
	f.Add(string(readF(f, "root.pub")))
	f.Add(releasetest.Key("k").Public())
	f.Add("untrusted comment: x\nRWQ=\n")
	f.Fuzz(func(t *testing.T, text string) {
		k, err := release.ParsePublicKey(text)
		if err != nil {
			return
		}
		again, err := release.ParsePublicKey(k.String())
		if err != nil || again.ID != k.ID || !bytes.Equal(again.Key, k.Key) || len(k.Key) != 32 || len(k.Fingerprint()) != 64 {
			t.Fatalf("key %q reads back as %v, %v", text, again, err)
		}
	})
}

func mustKey(f *testing.F, text string) release.PublicKey {
	f.Helper()
	k, err := release.ParsePublicKey(text)
	if err != nil {
		f.Fatal(err)
	}
	return k
}
