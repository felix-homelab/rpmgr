// SPDX-License-Identifier: Apache-2.0

package release_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
)

// fakeRelease is a release in memory, signed through a test chain, which counts the files it
// gives out.
type fakeRelease struct {
	files  map[string][]byte
	opened map[string]int
	fail   error
}

func (f *fakeRelease) Open(_ context.Context, name string) (io.ReadCloser, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	f.opened[name]++
	b, ok := f.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

var testRoot = releasetest.Key("mirror root")

// newRelease signs a release of version with artifacts for linux amd64 and arm64, darwin arm64
// and a linux connector variant, each holding its own name.
func newRelease(t *testing.T, version string, seq uint64) *fakeRelease {
	t.Helper()
	signing := releasetest.Key("mirror signing")
	st := []byte(`{"statement":1,"signer":"` + signing.Public() + `","not_before":"2026-10-01T00:00:00Z","not_after":"2027-10-01T00:00:00Z"}`)
	f := &fakeRelease{files: map[string][]byte{}, opened: map[string]int{}}
	m := release.Manifest{Seq: seq, Version: version, Floor: "1.0.0", Channel: release.Stable, IssuedAt: during}
	for _, a := range []release.Artifact{{OS: "linux", Arch: "amd64", Variant: "full"}, {OS: "linux", Arch: "arm64", Variant: "full"},
		{OS: "darwin", Arch: "arm64", Variant: "full"}, {OS: "linux", Arch: "amd64", Variant: "connector"}} {
		body := []byte("binary " + release.ArtifactName(version, a))
		sum := sha256.Sum256(body)
		a.Size, a.SHA256 = int64(len(body)), hex.EncodeToString(sum[:])
		m.Artifacts = append(m.Artifacts, a)
		f.files[release.ArtifactName(version, a)] = body
	}
	man, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	f.files["signing-key.json"], f.files["signing-key.json.minisig"] = st, testRoot.Sign(st)
	f.files["manifest.json"], f.files["manifest.json.minisig"] = man, signing.Sign(man)
	return f
}

func newMirror(t *testing.T, version string) *release.Mirror {
	return &release.Mirror{Dir: filepath.Join(t.TempDir(), "dl"), Version: version, Roots: []release.PublicKey{key(t, testRoot.Public())},
		Now: func() time.Time { return during }}
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

// TestMirrorSync: a verified release is kept and served under /dl/: its metadata and the full
// Linux artifacts only; a second sync fetches no artifact again.
func TestMirrorSync(t *testing.T) {
	src := newRelease(t, "1.4.2", 87)
	m := newMirror(t, "1.4.2")
	man, err := m.Sync(context.Background(), src)
	if err != nil || man.Seq != 87 {
		t.Fatalf("sync: %v %v", man, err)
	}
	h := m.Handler()
	for _, name := range []string{"rpmgr-1.4.2-linux-amd64", "rpmgr-1.4.2-linux-arm64", "manifest.json", "manifest.json.minisig",
		"signing-key.json", "signing-key.json.minisig"} {
		w := get(t, h, http.MethodGet, "/dl/1.4.2/"+name)
		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), src.files[name]) {
			t.Errorf("GET %s: %d %q", name, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
			t.Errorf("%s: Cache-Control %q", name, w.Header().Get("Cache-Control"))
		}
	}
	for _, path := range []string{"/dl/1.4.2/rpmgr-1.4.2-darwin-arm64", "/dl/1.4.2/rpmgr-1.4.2-linux-amd64-connector",
		"/dl/1.4.1/manifest.json", "/dl/1.4.2/.manifest.json.part", "/dl/1.4.2/../dl/1.4.2/manifest.json", "/dl/1.4.2/", "/dl/"} {
		if w := get(t, h, http.MethodGet, path); w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d", path, w.Code)
		}
	}
	if w := get(t, h, http.MethodHead, "/dl/1.4.2/manifest.json"); w.Code != http.StatusOK {
		t.Errorf("HEAD: %d", w.Code)
	}
	if w := get(t, h, http.MethodPost, "/dl/1.4.2/manifest.json"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
	if _, err := m.Sync(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	if src.opened["rpmgr-1.4.2-linux-amd64"] != 1 || src.opened["rpmgr-1.4.2-darwin-arm64"] != 0 {
		t.Errorf("fetched %v", src.opened)
	}
}

// TestMirrorRefuses: an artifact that does not match, a manifest of another version, an
// unverified manifest, oversized metadata and an unreachable source keep nothing new, and the
// version already kept stays served.
func TestMirrorRefuses(t *testing.T) {
	m := newMirror(t, "1.4.2")
	if _, err := m.Sync(context.Background(), newRelease(t, "1.4.2", 87)); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*fakeRelease){
		"a changed artifact":      func(f *fakeRelease) { f.files["rpmgr-1.4.2-linux-arm64"] = []byte("binary rpmgr-1.4.2-linux-arm65") },
		"a truncated artifact":    func(f *fakeRelease) { f.files["rpmgr-1.4.2-linux-arm64"] = []byte("binary") },
		"an unsigned manifest":    func(f *fakeRelease) { f.files["manifest.json"] = append(f.files["manifest.json"], ' ') },
		"huge metadata":           func(f *fakeRelease) { f.files["signing-key.json"] = make([]byte, 1<<20+1) },
		"an unreachable source":   func(f *fakeRelease) { f.fail = errors.New("dial tcp: no route to host") },
		"no manifest at all":      func(f *fakeRelease) { delete(f.files, "manifest.json") },
		"a missing artifact file": func(f *fakeRelease) { delete(f.files, "rpmgr-1.4.2-linux-arm64") },
	} {
		src := newRelease(t, "1.4.2", 88)
		// The arm64 artifact was kept unchanged; delete it so the changed one is fetched.
		_ = os.Remove(filepath.Join(m.Dir, "1.4.2", "rpmgr-1.4.2-linux-arm64"))
		change(src)
		if _, err := m.Sync(context.Background(), src); err == nil {
			t.Errorf("%s: kept", name)
		}
		b, _ := os.ReadFile(filepath.Join(m.Dir, "1.4.2", "manifest.json"))
		var kept release.Manifest
		if json.Unmarshal(b, &kept) != nil || kept.Seq != 87 {
			t.Errorf("%s: the kept manifest became %s", name, b)
		}
		entries, _ := os.ReadDir(filepath.Join(m.Dir, "1.4.2"))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".part") {
				t.Errorf("%s: left %s", name, e.Name())
			}
		}
		// Put the arm64 artifact back for the next case.
		if _, err := m.Sync(context.Background(), newRelease(t, "1.4.2", 87)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := newMirror(t, "1.4.3").Sync(context.Background(), newRelease(t, "1.4.2", 87)); err == nil ||
		!strings.Contains(err.Error(), "not of 1.4.3") {
		t.Errorf("another version's manifest: %v", err)
	}
}

// TestMirrorPrunes: a complete new version removes the directories of other versions, and
// nothing else.
func TestMirrorPrunes(t *testing.T) {
	m := newMirror(t, "1.4.2")
	if _, err := m.Sync(context.Background(), newRelease(t, "1.4.2", 87)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(m.Dir, "notes"), 0o750); err != nil {
		t.Fatal(err)
	}
	m.Version = "1.5.0"
	if _, err := m.Sync(context.Background(), newRelease(t, "1.5.0", 90)); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(m.Dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, " ") != "1.5.0 notes" {
		t.Errorf("left %v", names)
	}
}

// TestMirrorDevelopmentBuild: a development build syncs nothing and serves no download.
func TestMirrorDevelopmentBuild(t *testing.T) {
	m := newMirror(t, "dev")
	if _, err := m.Sync(context.Background(), newRelease(t, "1.4.2", 87)); !errors.Is(err, release.ErrDevelopment) {
		t.Errorf("sync: %v", err)
	}
	if w := get(t, m.Handler(), http.MethodGet, "/dl/dev/manifest.json"); w.Code != http.StatusNotFound ||
		!strings.Contains(w.Body.String(), "development build") {
		t.Errorf("GET: %d %q", w.Code, w.Body.String())
	}
}

// TestGitHub: the source asks for /v<version>/<file> and refuses answers other than 200.
func TestGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.4.2/manifest.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	g := release.GitHub{Base: srv.URL, Version: "1.4.2", Client: srv.Client()}
	rc, err := g.Open(context.Background(), "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "{}" {
		t.Errorf("read %q", b)
	}
	if _, err := g.Open(context.Background(), "signing-key.json"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("a missing file: %v", err)
	}
}
