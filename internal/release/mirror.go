// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// The files of a release besides its artifacts (docs/04-security.md, "Release signing"); the
// manifest comes last, so a mirrored version with a manifest is complete.
var metaFiles = []string{"signing-key.json", "signing-key.json.minisig", "manifest.json.minisig", "manifest.json"}

const maxMeta = 1 << 20

// ErrDevelopment means the binary is a development build, which mirrors and serves no release.
var ErrDevelopment = errors.New("release: a development build mirrors no release")

// Releasable reports whether version is a release version, as release builds set it.
func Releasable(version string) bool { return valid(version) }

// ArtifactName is an artifact's file name: rpmgr-<version>-<os>-<arch>, followed by -<variant>
// for variants other than full.
func ArtifactName(version string, a Artifact) string {
	name := "rpmgr-" + version + "-" + a.OS + "-" + a.Arch
	if a.Variant != "full" {
		name += "-" + a.Variant
	}
	return name
}

// A Source gives the files of a release by name.
type Source interface {
	Open(ctx context.Context, name string) (io.ReadCloser, error)
}

// Dir is a release in a local directory, as `rpmgr release import` reads it.
type Dir string

// Open opens a file of the release.
func (d Dir) Open(_ context.Context, name string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(string(d), name)) //nolint:gosec // G304: names are fixed or made from a verified manifest
}

// GitHub is the release source of D4: the release assets of a version on GitHub.
type GitHub struct {
	Base    string // https://github.com/felix-homelab/rpmgr/releases/download
	Version string
	Client  *http.Client
}

// Open downloads a file of the release.
func (g GitHub) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.Base+"/v"+g.Version+"/"+name, nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		if until, ok := rateLimited(resp, time.Now()); ok {
			return nil, &RateLimitedError{Until: until}
		}
		return nil, fmt.Errorf("release: %s: %s", req.URL, resp.Status)
	}
	return resp.Body, nil
}

// Mirror keeps verified releases in Dir/<version>/ and serves them under /dl/
// (docs/04-security.md, "Over-the-air updates"): the controller's own version Version, the
// target of each running or paused rollout, and the version the controller ran before (D119).
// Each kept version has every artifact its manifest names, both variants for every OS and
// architecture.
type Mirror struct {
	Dir     string
	Version string
	Roots   []PublicKey
	Now     func() time.Time

	// wrap, if set, wraps the writer of each file the mirror keeps; tests use it to fail a write
	// as a full disk does.
	wrap func(name string, w io.Writer) io.Writer
}

// Signed is a release's verified manifest with the signed files it was verified from.
type Signed struct {
	Manifest     *Manifest
	Statement    []byte // signing-key.json
	StatementSig []byte // signing-key.json.minisig
	ManifestJSON []byte // manifest.json
	ManifestSig  []byte // manifest.json.minisig
}

// meta are the signed files in the order of metaFiles.
func (s *Signed) meta() [][]byte {
	return [][]byte{s.Statement, s.StatementSig, s.ManifestSig, s.ManifestJSON}
}

// Fetch reads a release's signed files from src, without its artifacts, and verifies them.
func (m *Mirror) Fetch(ctx context.Context, src Source) (*Signed, error) {
	meta := make([][]byte, len(metaFiles))
	for i, name := range metaFiles {
		b, err := read(ctx, src, name, maxMeta)
		if err != nil {
			return nil, err
		}
		meta[i] = b
	}
	man, err := Verify(m.Roots, meta[0], meta[1], meta[3], meta[2], m.Now())
	if err != nil {
		return nil, err
	}
	return &Signed{Manifest: man, Statement: meta[0], StatementSig: meta[1], ManifestSig: meta[2], ManifestJSON: meta[3]}, nil
}

// Sync keeps the controller's own release, m.Version, from src (SyncVersion).
func (m *Mirror) Sync(ctx context.Context, src Source) (*Manifest, error) {
	s, err := m.SyncVersion(ctx, m.Version, src)
	if err != nil {
		return nil, err
	}
	return s.Manifest, nil
}

// SyncVersion fetches the release of version from src, verifies it and keeps it with every
// artifact its manifest names. Artifacts already kept unchanged are not fetched again. A file is
// kept only once it verifies, the manifest last, so a version with a manifest is complete; a
// failure keeps what was there. Other versions stay until Prune.
func (m *Mirror) SyncVersion(ctx context.Context, version string, src Source) (*Signed, error) {
	if !Releasable(m.Version) {
		return nil, ErrDevelopment
	}
	if !Releasable(version) {
		return nil, fmt.Errorf("release: %q is no release version", version)
	}
	s, err := m.Fetch(ctx, src)
	if err != nil {
		return nil, err
	}
	if s.Manifest.Version != version {
		return nil, fmt.Errorf("release: the source gave the manifest of %s, not of %s", s.Manifest.Version, version)
	}
	if err := os.MkdirAll(filepath.Join(m.Dir, version), 0o750); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Join(m.Dir, version))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	for _, a := range s.Manifest.Artifacts {
		if name := ArtifactName(version, a); !kept(root, name, a) {
			if err := m.keep(root, name, a, func() (io.ReadCloser, error) { return src.Open(ctx, name) }); err != nil {
				return nil, err
			}
		}
	}
	for i, b := range s.meta() {
		sum := sha256.Sum256(b)
		a := Artifact{Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])}
		if err := m.keep(root, metaFiles[i], a, func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func read(ctx context.Context, src Source, name string, limit int64) ([]byte, error) {
	rc, err := src.Open(ctx, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("release: %s is larger than %d bytes", name, limit)
	}
	return b, err
}

// kept reports whether the mirror has the artifact unchanged.
func kept(root *os.Root, name string, a Artifact) bool {
	f, err := root.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	return a.Check(f) == nil
}

// keep writes a file that must be the artifact a to a temporary name, checks and syncs it, and
// renames it into place. A failure, a full disk included, removes the temporary file.
func (m *Mirror) keep(root *os.Root, name string, a Artifact, open func() (io.ReadCloser, error)) error {
	rc, err := open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	tmp := "." + name + ".part"
	f, err := root.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	var w io.Writer = f
	if m.wrap != nil {
		w = m.wrap(name, f)
	}
	_, err = io.Copy(w, io.LimitReader(rc, a.Size+1))
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err == nil {
		err = a.Check(f)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("release: %s: %w", name, err)
	}
	return root.Rename(tmp, name)
}

// Prune removes the directories of the versions keep does not name, and returns those versions.
// The controller's own version is always kept; directories that are no version stay.
func (m *Mirror) Prune(keep ...string) ([]string, error) {
	entries, err := os.ReadDir(m.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kept := map[string]bool{m.Version: true}
	for _, v := range keep {
		kept[v] = true
	}
	var removed []string
	for _, e := range entries {
		if e.IsDir() && !kept[e.Name()] && Releasable(e.Name()) {
			if err := os.RemoveAll(filepath.Join(m.Dir, e.Name())); err != nil {
				return removed, err
			}
			removed = append(removed, e.Name())
		}
	}
	return removed, nil
}

// Complete reports whether the mirror holds version complete: its manifest is written last.
func (m *Mirror) Complete(version string) bool {
	_, err := m.manifest(version)
	return err == nil
}

// ownFile records the controller's own version and the version it ran before, in Dir.
const ownFile = ".own.json"

type own struct {
	Version  string `json:"version"`
	Previous string `json:"previous,omitempty"`
}

// RecordOwn records the controller's own version and returns the version it ran before its last
// upgrade, "" if none is known: a new own version moves the recorded one to previous. A
// development build records nothing.
func (m *Mirror) RecordOwn() (string, error) {
	if !Releasable(m.Version) {
		return "", nil
	}
	path := filepath.Join(m.Dir, ownFile)
	var o own
	b, err := os.ReadFile(path) //nolint:gosec // G304: the mirror's own file
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return "", err
	case json.Unmarshal(b, &o) != nil || (o.Version != "" && !Releasable(o.Version)) || (o.Previous != "" && !Releasable(o.Previous)):
		o = own{} // an unreadable record knows no previous version
	}
	if o.Version == m.Version {
		return o.Previous, nil
	}
	if o.Version != "" {
		o.Previous = o.Version
	}
	o.Version = m.Version
	if err := os.MkdirAll(m.Dir, 0o750); err != nil {
		return "", err
	}
	b, err = json.Marshal(o)
	if err != nil {
		return "", err
	}
	tmp := path + ".part"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	return o.Previous, os.Rename(tmp, path)
}

var fileRe = regexp.MustCompile(`^[0-9A-Za-z.+-]+$`)

// Handler serves GET /dl/<version>/<file>: the files of each complete mirrored version. Other
// paths, versions the mirror does not hold complete, and development builds get 404.
func (m *Mirror) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		version, name, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/dl/"), "/")
		if !Releasable(m.Version) {
			http.Error(w, "this development build serves no downloads", http.StatusNotFound)
			return
		}
		if !Releasable(version) || !fileRe.MatchString(name) || !m.serves(version, name) {
			http.NotFound(w, r)
			return
		}
		root, err := os.OpenRoot(filepath.Join(m.Dir, version))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer func() { _ = root.Close() }()
		f, err := root.Open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer func() { _ = f.Close() }()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, name, st.ModTime(), f)
	})
}

// manifest reads the manifest of a mirrored version; there is one only once the version is
// complete.
func (m *Mirror) manifest(version string) (*Manifest, error) {
	if !Releasable(version) {
		return nil, fmt.Errorf("release: %q is no release version", version)
	}
	b, err := os.ReadFile(filepath.Join(m.Dir, version, "manifest.json")) //nolint:gosec // G304: the mirror's own file of a checked version
	if err != nil {
		return nil, err
	}
	var man Manifest
	if err := json.Unmarshal(b, &man); err != nil {
		return nil, err
	}
	return &man, nil
}

// serves reports whether name is a file of a complete mirrored version.
func (m *Mirror) serves(version, name string) bool {
	man, err := m.manifest(version)
	if err != nil {
		return false
	}
	for _, f := range metaFiles {
		if name == f {
			return true
		}
	}
	for _, a := range man.Artifacts {
		if ArtifactName(version, a) == name {
			return true
		}
	}
	return false
}
