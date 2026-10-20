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
	"syscall"
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
	// breakAfter, if set, makes each artifact's download break off after that many bytes.
	breakAfter int
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
	if f.breakAfter > 0 && strings.HasPrefix(name, "rpmgr-") {
		return io.NopCloser(io.MultiReader(bytes.NewReader(b[:f.breakAfter]), errReader{})), nil
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset by peer") }

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

// TestMirrorSync: a verified release is kept and served under /dl/: its metadata and every
// artifact its manifest names, both variants on every OS (D119); a second sync fetches no
// artifact again.
func TestMirrorSync(t *testing.T) {
	src := newRelease(t, "1.4.2", 87)
	m := newMirror(t, "1.4.2")
	man, err := m.Sync(context.Background(), src)
	if err != nil || man.Seq != 87 {
		t.Fatalf("sync: %v %v", man, err)
	}
	h := m.Handler()
	for _, name := range []string{"rpmgr-1.4.2-linux-amd64", "rpmgr-1.4.2-linux-arm64", "rpmgr-1.4.2-darwin-arm64",
		"rpmgr-1.4.2-linux-amd64-connector", "manifest.json", "manifest.json.minisig", "signing-key.json", "signing-key.json.minisig"} {
		w := get(t, h, http.MethodGet, "/dl/1.4.2/"+name)
		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), src.files[name]) {
			t.Errorf("GET %s: %d %q", name, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
			t.Errorf("%s: Cache-Control %q", name, w.Header().Get("Cache-Control"))
		}
	}
	for _, path := range []string{"/dl/1.4.2/rpmgr-1.4.2-windows-amd64-connector.exe", "/dl/1.4.2/rpmgr-1.4.1-linux-amd64",
		"/dl/1.4.1/manifest.json", "/dl/dev/manifest.json", "/dl/1.4.2/.manifest.json.part", "/dl/1.4.2/../dl/1.4.2/manifest.json", "/dl/1.4.2/", "/dl/"} {
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
	if src.opened["rpmgr-1.4.2-linux-amd64"] != 1 || src.opened["rpmgr-1.4.2-darwin-arm64"] != 1 ||
		src.opened["rpmgr-1.4.2-linux-amd64-connector"] != 1 {
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

// TestMirrorKeepsSeveralVersions: other versions are kept beside the controller's own and served
// once complete; Prune removes only the versions it is not told to keep, never the own version,
// nor directories that are no version.
func TestMirrorKeepsSeveralVersions(t *testing.T) {
	m := newMirror(t, "1.5.0")
	ctx := context.Background()
	for v, seq := range map[string]uint64{"1.5.0": 90, "1.4.2": 87, "1.6.0": 95} {
		if _, err := m.SyncVersion(ctx, v, newRelease(t, v, seq)); err != nil {
			t.Fatalf("sync %s: %v", v, err)
		}
	}
	h := m.Handler()
	for _, v := range []string{"1.5.0", "1.4.2", "1.6.0"} {
		if w := get(t, h, http.MethodGet, "/dl/"+v+"/rpmgr-"+v+"-linux-amd64"); w.Code != http.StatusOK || !m.Complete(v) {
			t.Errorf("%s: %d, complete %v", v, w.Code, m.Complete(v))
		}
	}
	if _, err := m.SyncVersion(ctx, "1.4.2", newRelease(t, "1.4.3", 88)); err == nil || !strings.Contains(err.Error(), "not of 1.4.2") {
		t.Errorf("another version's manifest: %v", err)
	}
	if _, err := m.SyncVersion(ctx, "../etc", newRelease(t, "1.4.2", 87)); err == nil {
		t.Error("a version that is no release version")
	}
	if err := os.Mkdir(filepath.Join(m.Dir, "notes"), 0o750); err != nil {
		t.Fatal(err)
	}
	// An incomplete version, as a sync that failed before its manifest leaves it.
	if err := os.Mkdir(filepath.Join(m.Dir, "1.3.0"), 0o750); err != nil {
		t.Fatal(err)
	}
	if w := get(t, h, http.MethodGet, "/dl/1.3.0/manifest.json"); w.Code != http.StatusNotFound || m.Complete("1.3.0") {
		t.Errorf("an incomplete version: %d", w.Code)
	}
	removed, err := m.Prune("1.6.0")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(removed, " ") != "1.3.0 1.4.2" {
		t.Errorf("removed %v", removed)
	}
	entries, _ := os.ReadDir(m.Dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, " ") != "1.5.0 1.6.0 notes" {
		t.Errorf("left %v", names)
	}
	if removed, err := newMirror(t, "1.5.0").Prune(); err != nil || len(removed) != 0 {
		t.Errorf("a mirror without a directory: %v %v", removed, err)
	}
}

// TestMirrorFullDiskAndBrokenDownload: a write that fails, as on a full disk, and a download that
// breaks off keep nothing new and leave no partial file; the version already kept stays served.
func TestMirrorFullDiskAndBrokenDownload(t *testing.T) {
	m := newMirror(t, "1.4.2")
	ctx := context.Background()
	if _, err := m.Sync(ctx, newRelease(t, "1.4.2", 87)); err != nil {
		t.Fatal(err)
	}
	release.WrapWrites(m, func(name string, w io.Writer) io.Writer {
		if strings.HasPrefix(name, "rpmgr-1.5.0") {
			return failingWriter{}
		}
		return w
	})
	if _, err := m.SyncVersion(ctx, "1.5.0", newRelease(t, "1.5.0", 90)); !errors.Is(err, syscall.ENOSPC) {
		t.Errorf("a full disk: %v", err)
	}
	release.WrapWrites(m, nil)
	broken := newRelease(t, "1.5.0", 90)
	broken.breakAfter = 3
	if _, err := m.SyncVersion(ctx, "1.5.0", broken); err == nil {
		t.Error("a download that broke off was kept")
	}
	entries, _ := os.ReadDir(filepath.Join(m.Dir, "1.5.0"))
	for _, e := range entries {
		t.Errorf("left %s", e.Name())
	}
	if m.Complete("1.5.0") || !m.Complete("1.4.2") {
		t.Errorf("complete: 1.5.0 %v, 1.4.2 %v", m.Complete("1.5.0"), m.Complete("1.4.2"))
	}
	if w := get(t, m.Handler(), http.MethodGet, "/dl/1.4.2/rpmgr-1.4.2-linux-amd64"); w.Code != http.StatusOK {
		t.Errorf("the kept version: %d", w.Code)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, syscall.ENOSPC }

// TestMirrorRecordOwn: the mirror remembers the controller's own version, and a new one makes the
// recorded one the previous version; an unreadable record and a development build know none.
func TestMirrorRecordOwn(t *testing.T) {
	m := newMirror(t, "1.4.2")
	for i, want := range []string{"", ""} {
		if prev, err := m.RecordOwn(); err != nil || prev != want {
			t.Errorf("run %d: %q %v", i, prev, err)
		}
	}
	m.Version = "1.5.0"
	if prev, err := m.RecordOwn(); err != nil || prev != "1.4.2" {
		t.Errorf("after the upgrade: %q %v", prev, err)
	}
	if prev, err := m.RecordOwn(); err != nil || prev != "1.4.2" {
		t.Errorf("a later start: %q %v", prev, err)
	}
	m.Version = "1.4.2" // a downgrade by hand
	if prev, err := m.RecordOwn(); err != nil || prev != "1.5.0" {
		t.Errorf("after the downgrade: %q %v", prev, err)
	}
	if err := os.WriteFile(filepath.Join(m.Dir, ".own.json"), []byte(`{"version":"../x","previous":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if prev, err := m.RecordOwn(); err != nil || prev != "" {
		t.Errorf("an unreadable record: %q %v", prev, err)
	}
	if prev, err := newMirror(t, "dev").RecordOwn(); err != nil || prev != "" {
		t.Errorf("a development build: %q %v", prev, err)
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
