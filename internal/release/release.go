// SPDX-License-Identifier: Apache-2.0

// Package release verifies signed releases (docs/04-security.md, "Release signing"): a root key
// compiled into the binary signs a signing-key statement, the signing key it names signs each
// release manifest, and the manifest lists every artifact with its size and SHA-256. It also holds
// the seq and version-floor rules that keep a replayed manifest from rolling a host back.
package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// StatementLifetime is the longest a signing-key statement may be valid: 12 months.
const StatementLifetime = 366 * 24 * time.Hour

// Statement is a root key's statement that a signing key signs releases from NotBefore to NotAfter.
type Statement struct {
	Statement  int       `json:"statement"`
	SigningKey string    `json:"signer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
}

// Manifest is a release manifest.
type Manifest struct {
	Seq       uint64     `json:"seq"`
	Version   string     `json:"version"`
	Floor     string     `json:"floor"`
	Channel   string     `json:"channel"`
	IssuedAt  time.Time  `json:"issued_at"`
	Artifacts []Artifact `json:"artifacts"`
}

// Artifact is a release file.
type Artifact struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Variant string `json:"variant"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// Channels.
const (
	Stable     = "stable"
	Prerelease = "prerelease"
)

// ErrRefused means a verified manifest may not be installed here: it is older than the newest
// seen, below the version floor, or of another channel.
var ErrRefused = errors.New("release: refused")

// Verify checks the chain root → statement → manifest at time now and returns the manifest:
// the statement is signed by one of roots and valid at now, and the manifest is signed by the
// statement's signing key and well-formed.
func Verify(roots []PublicKey, statement, statementSig, manifest, manifestSig []byte, now time.Time) (*Manifest, error) {
	if len(roots) == 0 {
		return nil, fmt.Errorf("%w: this build has no release root keys", ErrSignature)
	}
	if _, _, err := verify(roots, statement, statementSig); err != nil {
		return nil, fmt.Errorf("signing-key statement: %w", err)
	}
	var st Statement
	if err := strict(statement, &st); err != nil {
		return nil, fmt.Errorf("release: signing-key statement: %w", err)
	}
	key, err := ParsePublicKey(st.SigningKey)
	switch {
	case st.Statement != 1:
		return nil, fmt.Errorf("release: signing-key statement of format %d", st.Statement)
	case err != nil:
		return nil, err
	case !st.NotBefore.Before(st.NotAfter) || st.NotAfter.Sub(st.NotBefore) > StatementLifetime:
		return nil, errors.New("release: a signing-key statement is valid for at most 12 months")
	case now.Before(st.NotBefore) || !now.Before(st.NotAfter):
		return nil, fmt.Errorf("%w: the statement for signing key %s is valid from %s to %s", ErrSignature, key.IDString(),
			st.NotBefore.Format(time.RFC3339), st.NotAfter.Format(time.RFC3339))
	}
	if _, _, err := verify([]PublicKey{key}, manifest, manifestSig); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil { // later fields are ignored, for newer manifests
		return nil, fmt.Errorf("release: manifest: %w", err)
	}
	return &m, m.check()
}

func (m *Manifest) check() error {
	switch {
	case m.Seq == 0 || m.IssuedAt.IsZero() || len(m.Artifacts) == 0:
		return errors.New("release: manifest without seq, issue time or artifacts")
	case !valid(m.Version) || !valid(m.Floor) || semver.Compare("v"+m.Floor, "v"+m.Version) > 0:
		return fmt.Errorf("release: manifest of version %q with floor %q", m.Version, m.Floor)
	case m.Channel != Stable && m.Channel != Prerelease, m.Channel == Stable && semver.Prerelease("v"+m.Version) != "":
		return fmt.Errorf("release: version %s on channel %q", m.Version, m.Channel)
	}
	for _, a := range m.Artifacts {
		if a.OS == "" || a.Arch == "" || a.Variant == "" || a.Size <= 0 || len(a.SHA256) != 64 || strings.ToLower(a.SHA256) != a.SHA256 {
			return fmt.Errorf("release: manifest lists a bad artifact %+v", a)
		}
	}
	return nil
}

// valid reports whether v is a full semantic version without a "v" and without build metadata.
func valid(v string) bool {
	return semver.Canonical("v"+v) == "v"+v
}

// State is what a host has accepted: the highest seq and its version floor (docs/04-security.md,
// "Over-the-air updates").
type State struct {
	Seq   uint64
	Floor string
}

// Accept returns the state after installing m on a host of the given channel, or ErrRefused. A
// lower seq is a replay; with the same seq the floor only rises, and only a higher seq may lower
// it, which makes signed downgrades possible. A stable host takes stable releases only; a
// prerelease host takes both.
func (s State) Accept(m *Manifest, channel string) (State, error) {
	switch {
	case m.Channel == Prerelease && channel != Prerelease:
		return s, fmt.Errorf("%w: %s is a pre-release, and this host takes stable releases only", ErrRefused, m.Version)
	case m.Seq < s.Seq:
		return s, fmt.Errorf("%w: manifest %d is older than manifest %d, the newest accepted", ErrRefused, m.Seq, s.Seq)
	case m.Seq > s.Seq:
		return State{Seq: m.Seq, Floor: m.Floor}, nil
	case s.Floor != "" && semver.Compare("v"+m.Version, "v"+s.Floor) < 0:
		return s, fmt.Errorf("%w: %s is below the version floor %s", ErrRefused, m.Version, s.Floor)
	}
	if s.Floor == "" || semver.Compare("v"+m.Floor, "v"+s.Floor) > 0 {
		s.Floor = m.Floor
	}
	return s, nil
}

// Artifact returns the manifest's artifact for an OS, architecture and variant.
func (m *Manifest) Artifact(os, arch, variant string) (Artifact, error) {
	for _, a := range m.Artifacts {
		if a.OS == os && a.Arch == arch && a.Variant == variant {
			return a, nil
		}
	}
	return Artifact{}, fmt.Errorf("release: %s has no %s artifact for %s/%s", m.Version, variant, os, arch)
}

// Check reads a file and reports whether it is the artifact: the same size and SHA-256. It reads
// at most one byte more than the size.
func (a Artifact) Check(r io.Reader) error {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, a.Size+1))
	switch {
	case err != nil:
		return fmt.Errorf("release: artifact: %w", err)
	case n != a.Size:
		return fmt.Errorf("release: the artifact has %d bytes, not %d", n, a.Size)
	case hex.EncodeToString(h.Sum(nil)) != a.SHA256:
		return errors.New("release: the artifact's SHA-256 does not match the manifest")
	}
	return nil
}

// strict decodes JSON that has no keys v does not know.
func strict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
