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

// mirrored reports whether the mirror keeps an artifact: Phase 1 mirrors the full Linux builds
// (D59).
func mirrored(a Artifact) bool { return a.OS == "linux" && a.Variant == "full" }

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
		return nil, fmt.Errorf("release: %s: %s", req.URL, resp.Status)
	}
	return resp.Body, nil
}

// Mirror keeps the verified release of one version in Dir/<version>/ and serves it under /dl/
// (docs/04-security.md, "Over-the-air updates").
type Mirror struct {
	Dir     string
	Version string
	Roots   []PublicKey
	Now     func() time.Time
}

// Sync fetches the release of m.Version from src, verifies it and keeps it. Artifacts already
// kept unchanged are not fetched again. A file is kept only once it verifies, the manifest last;
// other versions' directories go once a version is complete.
func (m *Mirror) Sync(ctx context.Context, src Source) (*Manifest, error) {
	if !Releasable(m.Version) {
		return nil, ErrDevelopment
	}
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
	if man.Version != m.Version {
		return nil, fmt.Errorf("release: the source gave the manifest of %s, not of %s", man.Version, m.Version)
	}
	if err := os.MkdirAll(filepath.Join(m.Dir, m.Version), 0o750); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Join(m.Dir, m.Version))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	for _, a := range man.Artifacts {
		if name := ArtifactName(m.Version, a); mirrored(a) && !kept(root, name, a) {
			if err := keep(root, name, a, func() (io.ReadCloser, error) { return src.Open(ctx, name) }); err != nil {
				return nil, err
			}
		}
	}
	for i, name := range metaFiles {
		sum := sha256.Sum256(meta[i])
		a := Artifact{Size: int64(len(meta[i])), SHA256: hex.EncodeToString(sum[:])}
		if err := keep(root, name, a, func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(meta[i])), nil }); err != nil {
			return nil, err
		}
	}
	return man, m.prune()
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
// renames it into place.
func keep(root *os.Root, name string, a Artifact, open func() (io.ReadCloser, error)) error {
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
	_, err = io.Copy(f, io.LimitReader(rc, a.Size+1))
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

// prune removes the directories of other versions.
func (m *Mirror) prune() error {
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != m.Version && Releasable(e.Name()) {
			if err := os.RemoveAll(filepath.Join(m.Dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

var fileRe = regexp.MustCompile(`^[0-9A-Za-z.+-]+$`)

// Handler serves GET /dl/<version>/<file>: the files of the mirrored version, once it is
// complete. Other paths, other versions and development builds get 404.
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
		if version != m.Version || !fileRe.MatchString(name) || !m.serves(name) {
			http.NotFound(w, r)
			return
		}
		root, err := os.OpenRoot(filepath.Join(m.Dir, m.Version))
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

// serves reports whether name is a file of the complete mirrored version.
func (m *Mirror) serves(name string) bool {
	b, err := os.ReadFile(filepath.Join(m.Dir, m.Version, "manifest.json")) //nolint:gosec // G304: the mirror's own file
	if err != nil {
		return false
	}
	var man Manifest
	if json.Unmarshal(b, &man) != nil {
		return false
	}
	for _, f := range metaFiles {
		if name == f {
			return true
		}
	}
	for _, a := range man.Artifacts {
		if mirrored(a) && ArtifactName(m.Version, a) == name {
			return true
		}
	}
	return false
}
