// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
)

var (
	otaRoot    = releasetest.Key("agent ota root")
	otaSigning = releasetest.Key("agent ota signing")
	otaNow     = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
)

// otaRelease is a signed release with linux/amd64 artifacts, as the controller's /dl/ serves it.
type otaRelease struct {
	version string
	seq     uint64
	files   map[string][]byte
	base    string // the controller's public URL, whose /dl/ serves it
}

// newOTARelease signs a release of version with the given channel and variants.
func newOTARelease(t *testing.T, version string, seq uint64, channel string, variants ...string) *otaRelease {
	t.Helper()
	r := &otaRelease{version: version, seq: seq, files: map[string][]byte{}}
	m := release.Manifest{Seq: seq, Version: version, Floor: "0.1.0", Channel: channel, IssuedAt: otaNow}
	for _, v := range variants {
		body := []byte("rpmgr " + version + " " + v + " " + strings.Repeat("x", 64))
		sum := sha256.Sum256(body)
		a := release.Artifact{OS: "linux", Arch: "amd64", Variant: v, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
		m.Artifacts = append(m.Artifacts, a)
		r.files[release.ArtifactName(version, a)] = body
	}
	man, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	st := []byte(`{"statement":1,"signer":"` + otaSigning.Public() + `","not_before":"2026-10-01T00:00:00Z","not_after":"2027-10-01T00:00:00Z"}`)
	r.files[release.StatementFile] = st
	r.files[release.StatementSigFile] = otaRoot.Sign(st)
	r.files[release.ManifestFile] = man
	r.files[release.ManifestSigFile] = otaSigning.Sign(man)
	return r
}

// offer is the offer of the release, with every file and its size and SHA-256.
func (r *otaRelease) offer() *agentv1.ReleaseOffer {
	o := &agentv1.ReleaseOffer{Version: r.version, BaseUrl: r.base, Seq: r.seq}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for n := range r.files {
			if !yield(n) {
				return
			}
		}
	}) {
		sum := sha256.Sum256(r.files[name])
		o.Files = append(o.Files, &agentv1.ReleaseFile{Name: name, Size: uint64(len(r.files[name])), Sha256: sum[:]})
	}
	return o
}

func (r *otaRelease) artifact(variant string) string {
	name := "rpmgr-" + r.version + "-linux-amd64"
	if variant != "full" {
		name += "-" + variant
	}
	return name
}

// otaEnv is a controller's /dl/ over TLS, a staging directory and a stager that reports into
// states.
type otaEnv struct {
	t      *testing.T
	srv    *httptest.Server
	dir    string
	status string
	states chan *agentv1.UpdateState

	mu       sync.Mutex
	releases map[string]*otaRelease
	requests []string
	serve    func(w http.ResponseWriter, r *http.Request, name string, body []byte) bool // true: handled
	pol      *policy.Policy
	free     uint64
}

func newOTAEnv(t *testing.T, rels ...*otaRelease) *otaEnv {
	t.Helper()
	e := &otaEnv{t: t, dir: filepath.Join(t.TempDir(), "update"), status: filepath.Join(t.TempDir(), "status.json"),
		states: make(chan *agentv1.UpdateState, 64), releases: map[string]*otaRelease{}, pol: policy.Defaults(), free: 1 << 40}
	for _, r := range rels {
		e.releases[r.version] = r
	}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.requests = append(e.requests, r.URL.Path)
		serve := e.serve
		version, name, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/dl/"), "/")
		rel := e.releases[version]
		e.mu.Unlock()
		if rel == nil || rel.files[name] == nil {
			http.NotFound(w, r)
			return
		}
		if serve != nil && serve(w, r, name, rel.files[name]) {
			return
		}
		_, _ = w.Write(rel.files[name])
	}))
	t.Cleanup(e.srv.Close)
	for _, r := range e.releases {
		r.base = e.srv.URL
	}
	return e
}

// stager returns a running stager of a full linux/amd64 build at version 0.1.0.
func (e *otaEnv) stager(ctx context.Context, variant string) *agent.Stager {
	e.t.Helper()
	root, err := release.ParsePublicKey(otaRoot.Public())
	if err != nil {
		e.t.Fatal(err)
	}
	s := agent.NewStager(agent.UpdateOptions{Dir: e.dir, StatusFile: e.status, Variant: variant, Client: e.srv.Client(),
		Roots: []release.PublicKey{root}, OS: "linux", Arch: "amd64",
		Policy:    func() *policy.Policy { e.mu.Lock(); defer e.mu.Unlock(); return e.pol },
		FreeSpace: func(string) (uint64, error) { e.mu.Lock(); defer e.mu.Unlock(); return e.free, nil },
		Timeout:   5 * time.Second, Stall: 300 * time.Millisecond, Recheck: 20 * time.Millisecond,
		Retry: func(int) time.Duration { return 20 * time.Millisecond }},
		"0.1.0", func(st *agentv1.UpdateState) { e.states <- st }, func() time.Time { return otaNow }, nil)
	go s.Run(ctx)
	return s
}

// next waits for the next reported state.
func (e *otaEnv) next() *agentv1.UpdateState {
	e.t.Helper()
	select {
	case st := <-e.states:
		return st
	case <-time.After(10 * time.Second):
		e.t.Fatal("no update state reported")
		return nil
	}
}

// until waits for a state of the phase and returns it.
func (e *otaEnv) until(phase agentv1.UpdatePhase) *agentv1.UpdateState {
	e.t.Helper()
	for {
		if st := e.next(); st.GetPhase() == phase {
			return st
		}
	}
}

// quiet requires that no state is reported for a while.
func (e *otaEnv) quiet() {
	e.t.Helper()
	select {
	case st := <-e.states:
		e.t.Fatalf("unexpected update state %v", st)
	case <-time.After(150 * time.Millisecond):
	}
}

func (e *otaEnv) requested() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.requests)
}

func (e *otaEnv) set(f func(e *otaEnv)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f(e)
	for _, r := range e.releases {
		if r.base == "" {
			r.base = e.srv.URL
		}
	}
}

// staged returns the names in the staging directory.
func (e *otaEnv) staged() []string {
	e.t.Helper()
	entries, err := os.ReadDir(e.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		e.t.Fatal(err)
	}
	var names []string
	for _, en := range entries {
		names = append(names, en.Name())
	}
	return names
}

func run(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

// TestStager_StagesOffer: an offered release is downloaded from the controller's /dl/, verified
// and staged with the artifact of the host's variant, the manifest written only after the rest;
// the same offer again changes nothing, also after a restart.
func TestStager_StagesOffer(t *testing.T) {
	rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full", "connector")
	e := newOTAEnv(t, rel)
	var sawManifest bool
	e.serve = func(_ http.ResponseWriter, _ *http.Request, name string, _ []byte) bool {
		if name == rel.artifact("connector") {
			_, err := os.Stat(filepath.Join(e.dir, release.ManifestFile))
			sawManifest = err == nil
		}
		return false
	}
	ctx := run(t)
	s := e.stager(ctx, "connector")
	s.Offer(rel.offer())
	if st := e.next(); st.GetPhase() != agentv1.UpdatePhase_UPDATE_PHASE_DOWNLOADING || st.GetVersion() != "0.2.0" {
		t.Fatalf("first state %v, want downloading 0.2.0", st)
	}
	if st := e.next(); st.GetPhase() != agentv1.UpdatePhase_UPDATE_PHASE_STAGED {
		t.Fatalf("second state %v, want staged", st)
	}
	if sawManifest {
		t.Error("manifest.json was in the staging directory before the artifact was downloaded")
	}
	want := []string{release.ManifestFile, release.ManifestSigFile, rel.artifact("connector"), release.StatementFile, release.StatementSigFile}
	slices.Sort(want)
	if got := e.staged(); !slices.Equal(got, want) {
		t.Fatalf("staged %v, want %v", got, want)
	}
	for _, name := range want {
		b, err := os.ReadFile(filepath.Join(e.dir, name))
		if err != nil || string(b) != string(rel.files[name]) {
			t.Errorf("%s staged as %q, %v", name, b, err)
		}
	}
	if st := s.State(); st.GetPhase() != agentv1.UpdatePhase_UPDATE_PHASE_STAGED || st.GetUpdater() != nil {
		t.Errorf("State() = %v", st)
	}

	// The same offer twice, also as an equal copy, sends nothing and fetches nothing.
	n := len(e.requested())
	s.Offer(rel.offer())
	s.Offer(proto.CloneOf(rel.offer()))
	e.quiet()
	if len(e.requested()) != n {
		t.Errorf("the same offer again made requests %v", e.requested()[n:])
	}

	// After a restart the agent finds the release staged and downloads no artifact again.
	ctx2, cancel := context.WithCancel(context.Background())
	defer cancel()
	s2 := e.stager(ctx2, "connector")
	s2.Offer(rel.offer())
	e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED)
	for _, p := range e.requested()[n:] {
		if strings.HasSuffix(p, rel.artifact("connector")) {
			t.Errorf("a restarted agent downloaded the staged artifact again")
		}
	}
}

// TestStager_HostileOffer: the agent downloads only from its controller's /dl/<version>/ with
// names it makes itself: an offer whose version is a path is declined without a request, file
// names in the offer are never used, and a redirect is not followed.
func TestStager_HostileOffer(t *testing.T) {
	rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
	e := newOTAEnv(t, rel)
	ctx := run(t)
	s := e.stager(ctx, "full")
	for _, v := range []string{"../../etc", "0.2.0/../../x", "https://evil.example/0.2.0", "", "v0.2.0"} {
		o := rel.offer()
		o.Version = v
		s.Offer(o)
		if st := e.until(agentv1.UpdatePhase_UPDATE_PHASE_DECLINED); st.GetVersion() != v {
			t.Fatalf("declined %q, want %q", st.GetVersion(), v)
		}
	}
	if r := e.requested(); len(r) != 0 {
		t.Fatalf("hostile versions made requests %v", r)
	}

	// Hostile names in the offer play no part.
	o := rel.offer()
	o.Files = append(o.Files, &agentv1.ReleaseFile{Name: "../../../../tmp/owned", Size: 1, Sha256: make([]byte, 32)},
		&agentv1.ReleaseFile{Name: "https://evil.example/x", Size: 1})
	s.Offer(o)
	e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED)
	for _, p := range e.requested() {
		if !strings.HasPrefix(p, "/dl/0.2.0/") || strings.Contains(p, "..") || strings.Contains(p, "evil") {
			t.Errorf("request %q", p)
		}
	}

	// A redirect, here to another host, is a failure and is not followed.
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the redirect was followed to %s", r.URL)
	}))
	defer other.Close()
	rel2 := newOTARelease(t, "0.3.0", 8, release.Stable, "full")
	e.set(func(e *otaEnv) {
		e.releases["0.3.0"] = rel2
		e.serve = func(w http.ResponseWriter, _ *http.Request, name string, _ []byte) bool {
			if strings.HasPrefix(name, "rpmgr-") {
				w.Header().Set("Location", other.URL+"/dl/0.3.0/elsewhere")
				w.WriteHeader(http.StatusFound)
				return true
			}
			return false
		}
	})
	s.Offer(rel2.offer())
	if st := e.until(agentv1.UpdatePhase_UPDATE_PHASE_FAILED); !strings.Contains(st.GetDetail(), "302") {
		t.Errorf("a redirect: %v", st)
	}
}

// TestStager_BadDownloads: a truncated, an oversized and a stalled artifact, and one that does
// not match the signed manifest, fail and leave no file behind; the agent tries again and stages
// the release once the controller serves it correctly. A manifest that does not verify fails too.
func TestStager_BadDownloads(t *testing.T) {
	for name, serve := range map[string]func(w http.ResponseWriter, body []byte){
		"truncated": func(w http.ResponseWriter, body []byte) { _, _ = w.Write(body[:len(body)-10]) },
		"oversized": func(w http.ResponseWriter, body []byte) { _, _ = w.Write(append(body, "trailing bytes"...)) },
		"altered": func(w http.ResponseWriter, body []byte) {
			_, _ = w.Write(append([]byte("X"), body[1:]...))
		},
		"stalled": func(w http.ResponseWriter, body []byte) {
			_, _ = w.Write(body[:10])
			w.(http.Flusher).Flush()
			time.Sleep(time.Second)
			_, _ = w.Write(body[10:])
		},
	} {
		t.Run(name, func(t *testing.T) {
			rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
			e := newOTAEnv(t, rel)
			var bad atomic.Bool
			bad.Store(true)
			e.serve = func(w http.ResponseWriter, _ *http.Request, n string, body []byte) bool {
				if n != rel.artifact("full") || !bad.Load() {
					return false
				}
				serve(w, body)
				return true
			}
			ctx := run(t)
			e.stager(ctx, "full").Offer(rel.offer())
			e.until(agentv1.UpdatePhase_UPDATE_PHASE_FAILED)
			for _, n := range e.staged() {
				if n == rel.artifact("full") || strings.HasSuffix(n, ".part") || n == release.ManifestFile {
					t.Errorf("a failed download left %s", n)
				}
			}
			bad.Store(false)
			e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED)
		})
	}

	t.Run("bad signature", func(t *testing.T) {
		rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
		rel.files[release.ManifestSigFile] = releasetest.Key("someone else").Sign(rel.files[release.ManifestFile])
		e := newOTAEnv(t, rel)
		e.stager(run(t), "full").Offer(rel.offer())
		e.until(agentv1.UpdatePhase_UPDATE_PHASE_FAILED)
		if got := e.staged(); len(got) != 0 {
			t.Errorf("a manifest that does not verify staged %v", got)
		}
	})

	t.Run("other manifest", func(t *testing.T) {
		rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
		e := newOTAEnv(t, rel)
		o := rel.offer()
		o.Seq = 9 // the controller offers a seq its /dl/ does not serve
		e.stager(run(t), "full").Offer(o)
		if st := e.until(agentv1.UpdatePhase_UPDATE_PHASE_FAILED); !strings.Contains(st.GetDetail(), "manifest of 0.2.0 (7)") {
			t.Errorf("another manifest: %v", st)
		}
	})
}

// TestStager_FullDisk: without the artifact's size plus 64 MiB free the artifact is not
// downloaded; a write that fails as on a full disk leaves no partial file.
func TestStager_FullDisk(t *testing.T) {
	rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
	e := newOTAEnv(t, rel)
	size := uint64(len(rel.files[rel.artifact("full")]))
	e.free = size + 64<<20 - 1
	ctx := run(t)
	e.stager(ctx, "full").Offer(rel.offer())
	if st := e.until(agentv1.UpdatePhase_UPDATE_PHASE_FAILED); !strings.Contains(st.GetDetail(), "bytes free") {
		t.Fatalf("a full disk: %v", st)
	}
	for _, p := range e.requested() {
		if strings.HasSuffix(p, rel.artifact("full")) {
			t.Fatal("the artifact was downloaded without the space for it")
		}
	}
	e.set(func(e *otaEnv) { e.free = size + 64<<20 })
	e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED)

	// A staging directory the agent cannot write fails without a partial file.
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	rel2 := newOTARelease(t, "0.3.0", 8, release.Stable, "full")
	e.set(func(e *otaEnv) { e.releases["0.3.0"] = rel2 })
	if err := os.Chmod(e.dir, 0o500); err != nil { //nolint:gosec // G302: a directory, made unwritable
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.dir, 0o750) }) //nolint:gosec // G302: the directory's mode again
	e.stager(ctx, "full").Offer(rel2.offer())
	e.until(agentv1.UpdatePhase_UPDATE_PHASE_FAILED)
	for _, n := range e.staged() {
		if strings.Contains(n, "0.3.0") {
			t.Errorf("an unwritable directory got %s", n)
		}
	}
}

// TestStager_Policy: auto_update off and a policy that does not load decline the offer, notify
// reports it available, and neither downloads anything; a pre-release on a stable host and a
// release without the host's variant are declined after the signed files and before the
// artifact. Once the policy allows it, a declined offer is staged.
func TestStager_Policy(t *testing.T) {
	rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
	for name, c := range map[string]struct {
		pol   *policy.Policy
		phase agentv1.UpdatePhase
		want  string
	}{
		"off":     {&policy.Policy{AutoUpdate: policy.AutoUpdateOff, UpdateChannel: policy.ChannelStable}, agentv1.UpdatePhase_UPDATE_PHASE_DECLINED, "auto_update is off"},
		"invalid": {&policy.Policy{AutoUpdate: policy.AutoUpdateAuto, UpdateChannel: policy.ChannelStable, Invalid: errors.New("bad yaml")}, agentv1.UpdatePhase_UPDATE_PHASE_DECLINED, "does not load"},
		"notify":  {&policy.Policy{AutoUpdate: policy.AutoUpdateNotify, UpdateChannel: policy.ChannelStable}, agentv1.UpdatePhase_UPDATE_PHASE_AVAILABLE, ""},
	} {
		t.Run(name, func(t *testing.T) {
			e := newOTAEnv(t, rel)
			e.pol = c.pol
			e.stager(run(t), "full").Offer(rel.offer())
			if st := e.next(); st.GetPhase() != c.phase || !strings.Contains(st.GetDetail(), c.want) || st.GetVersion() != "0.2.0" {
				t.Fatalf("state %v, want %v with %q", st, c.phase, c.want)
			}
			e.quiet() // checked again with an unchanged policy: nothing new
			if r := e.requested(); len(r) != 0 {
				t.Fatalf("requests %v", r)
			}
			e.set(func(e *otaEnv) { e.pol = policy.Defaults() })
			e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED)
		})
	}

	t.Run("prerelease on stable", func(t *testing.T) {
		pre := newOTARelease(t, "0.2.0-rc.1", 7, release.Prerelease, "full")
		e := newOTAEnv(t, pre)
		e.stager(run(t), "full").Offer(pre.offer())
		if st := e.until(agentv1.UpdatePhase_UPDATE_PHASE_DECLINED); !strings.Contains(st.GetDetail(), "pre-release") {
			t.Fatalf("state %v", st)
		}
		for _, p := range e.requested() {
			if strings.HasSuffix(p, pre.artifact("full")) {
				t.Fatal("a refused pre-release was downloaded")
			}
		}
		e.set(func(e *otaEnv) {
			e.pol = &policy.Policy{AutoUpdate: policy.AutoUpdateAuto, UpdateChannel: policy.ChannelPrerelease}
		})
		e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED)
	})

	t.Run("no artifact for the variant", func(t *testing.T) {
		e := newOTAEnv(t, rel)
		e.stager(run(t), "connector").Offer(rel.offer())
		if st := e.until(agentv1.UpdatePhase_UPDATE_PHASE_DECLINED); !strings.Contains(st.GetDetail(), "no connector build") {
			t.Fatalf("state %v", st)
		}
	})

	t.Run("running version", func(t *testing.T) {
		cur := newOTARelease(t, "0.1.0", 6, release.Stable, "full")
		e := newOTAEnv(t, cur)
		e.stager(run(t), "full").Offer(cur.offer())
		if st := e.next(); st.GetPhase() != agentv1.UpdatePhase_UPDATE_PHASE_UNSPECIFIED || st.GetVersion() != "0.1.0" {
			t.Fatalf("state %v", st)
		}
		if r := e.requested(); len(r) != 0 {
			t.Fatalf("the running version made requests %v", r)
		}
	})
}

// TestStager_NewOfferReplacesDownload: a new offer ends the download of an earlier one, and no
// offer leaves the staged files alone.
func TestStager_NewOfferReplacesDownload(t *testing.T) {
	a, b := newOTARelease(t, "0.2.0", 7, release.Stable, "full"), newOTARelease(t, "0.3.0", 8, release.Stable, "full")
	e := newOTAEnv(t, a, b)
	release2 := make(chan struct{})
	e.serve = func(w http.ResponseWriter, r *http.Request, name string, body []byte) bool {
		if name != a.artifact("full") {
			return false
		}
		_, _ = w.Write(body[:5])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release2:
		}
		return true
	}
	defer close(release2)
	s := e.stager(run(t), "full")
	s.Offer(a.offer())
	e.until(agentv1.UpdatePhase_UPDATE_PHASE_DOWNLOADING)
	s.Offer(b.offer())
	if st := e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED); st.GetVersion() != "0.3.0" {
		t.Fatalf("staged %v", st)
	}
	s.Offer(nil)
	e.quiet()
	if !slices.Contains(e.staged(), b.artifact("full")) {
		t.Error("withdrawing the offer removed the staged release")
	}
}

// TestStager_UpdaterOutcome: the root updater's status file is reported with the state; a missing
// or corrupt file is no outcome.
func TestStager_UpdaterOutcome(t *testing.T) {
	e := newOTAEnv(t)
	s := e.stager(run(t), "full")
	if st := s.State(); st != nil {
		t.Fatalf("no offer and no status file: %v", st)
	}
	at := time.Date(2026, 10, 22, 11, 0, 0, 0, time.UTC)
	for state, want := range map[string]agentv1.UpdaterResult{
		"updated":         agentv1.UpdaterResult_UPDATER_RESULT_UPDATED,
		"rolled_back":     agentv1.UpdaterResult_UPDATER_RESULT_ROLLED_BACK,
		"rollback_failed": agentv1.UpdaterResult_UPDATER_RESULT_ROLLBACK_FAILED,
		"refused":         agentv1.UpdaterResult_UPDATER_RESULT_REFUSED,
	} {
		b, _ := json.Marshal(map[string]any{"state": state, "version": "0.2.0", "previous": "0.1.0", "reason": "not ready", "at": at})
		if err := os.WriteFile(e.status, b, 0o644); err != nil {
			t.Fatal(err)
		}
		u := s.State().GetUpdater()
		if u.GetResult() != want || u.GetVersion() != "0.2.0" || u.GetPrevious() != "0.1.0" || u.GetReason() != "not ready" ||
			!u.GetAt().AsTime().Equal(at) {
			t.Errorf("%s reported as %v", state, u)
		}
	}
	if err := os.WriteFile(e.status, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := s.State(); st != nil {
		t.Errorf("a corrupt status file: %v", st)
	}
	// An update of a controller or all-in-one under way (D158) is no outcome yet.
	if err := os.WriteFile(e.status, []byte(`{"state":"updating","step":"backing_up","version":"0.2.0","at":"2026-10-29T10:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := s.State(); st != nil {
		t.Errorf("an update under way: %v", st)
	}
}

// resign changes a release's manifest and signs it again.
func (r *otaRelease) resign(t *testing.T, edit func(m *release.Manifest)) {
	t.Helper()
	var m release.Manifest
	if err := json.Unmarshal(r.files[release.ManifestFile], &m); err != nil {
		t.Fatal(err)
	}
	edit(&m)
	man, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r.files[release.ManifestFile] = man
	r.files[release.ManifestSigFile] = otaSigning.Sign(man)
}

// TestStager_ReplacesStagedRelease: staging release B over a staged release A removes A's manifest
// before anything of B is written, so the updater never finds A's manifest next to B's files, and
// leaves only B's files.
func TestStager_ReplacesStagedRelease(t *testing.T) {
	a, b := newOTARelease(t, "0.2.0", 7, release.Stable, "full"), newOTARelease(t, "0.3.0", 8, release.Stable, "full")
	e := newOTAEnv(t, a, b)
	s := e.stager(run(t), "full")
	s.Offer(a.offer())
	e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED)
	var mu sync.Mutex
	var during []string
	var downloaded bool
	e.set(func(e *otaEnv) {
		e.serve = func(_ http.ResponseWriter, _ *http.Request, name string, _ []byte) bool {
			if name == b.artifact("full") {
				mu.Lock()
				during, downloaded = e.staged(), true
				mu.Unlock()
			}
			return false
		}
	})
	s.Offer(b.offer())
	e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED)
	mu.Lock()
	defer mu.Unlock()
	if !downloaded {
		t.Fatal("B's artifact was not downloaded")
	}
	for _, n := range during {
		if n == release.ManifestFile || n == release.ManifestSigFile || n == release.StatementFile || n == release.StatementSigFile {
			t.Errorf("A's %s was still staged while B downloaded (%v)", n, during)
		}
	}
	want := []string{release.ManifestFile, release.ManifestSigFile, b.artifact("full"), release.StatementFile, release.StatementSigFile}
	slices.Sort(want)
	if got := e.staged(); !slices.Equal(got, want) {
		t.Fatalf("staged %v, want %v", got, want)
	}
	if got, _ := os.ReadFile(filepath.Join(e.dir, release.ManifestFile)); string(got) != string(b.files[release.ManifestFile]) {
		t.Error("the staged manifest is not B's")
	}
}

// TestStager_ReportsLaterOutcome: while a release is staged, the updater's status file is read
// again, and an outcome written after staging, such as refused, which restarts nothing, is
// reported; an unchanged one is not reported again.
func TestStager_ReportsLaterOutcome(t *testing.T) {
	rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
	e := newOTAEnv(t, rel)
	old, _ := json.Marshal(map[string]any{"state": "updated", "version": "0.1.0", "at": otaNow.Add(-time.Hour)})
	if err := os.WriteFile(e.status, old, 0o644); err != nil {
		t.Fatal(err)
	}
	s := e.stager(run(t), "full")
	s.Offer(rel.offer())
	e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED)
	e.quiet() // the outcome from before staging is not news
	b, _ := json.Marshal(map[string]any{"state": "refused", "version": "0.2.0", "reason": "below the floor", "at": otaNow})
	if err := os.WriteFile(e.status, b, 0o644); err != nil {
		t.Fatal(err)
	}
	st := e.next()
	if st.GetPhase() != agentv1.UpdatePhase_UPDATE_PHASE_STAGED || st.GetUpdater().GetResult() != agentv1.UpdaterResult_UPDATER_RESULT_REFUSED ||
		st.GetUpdater().GetReason() != "below the floor" {
		t.Fatalf("a later outcome: %v", st)
	}
	e.quiet()
}

// TestStager_ArtifactAboveCapAndOfferMismatch: a signed manifest whose artifact is larger than the
// updater's cap is declined without downloading it, and an offer whose entry for the artifact
// differs from the signed manifest fails.
func TestStager_ArtifactAboveCapAndOfferMismatch(t *testing.T) {
	big := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
	big.resign(t, func(m *release.Manifest) { m.Artifacts[0].Size = 256<<20 + 1 })
	e := newOTAEnv(t, big)
	e.stager(run(t), "full").Offer(big.offer())
	if st := e.until(agentv1.UpdatePhase_UPDATE_PHASE_DECLINED); !strings.Contains(st.GetDetail(), "above the cap") {
		t.Fatalf("an artifact above the cap: %v", st)
	}
	for _, p := range e.requested() {
		if strings.HasSuffix(p, big.artifact("full")) {
			t.Fatal("an artifact above the cap was downloaded")
		}
	}

	rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
	e2 := newOTAEnv(t, rel)
	o := rel.offer()
	for _, f := range o.GetFiles() {
		if f.GetName() == rel.artifact("full") {
			f.Size++
		}
	}
	e2.stager(run(t), "full").Offer(o)
	if st := e2.until(agentv1.UpdatePhase_UPDATE_PHASE_FAILED); !strings.Contains(st.GetDetail(), "differs from the signed manifest") {
		t.Fatalf("an offer that differs: %v", st)
	}
}

// TestStager_OfferBaseURL (docs/04-security.md, "Over-the-air updates", step 3): the offer names
// the controller's public URL whose /dl/ the agent downloads from; a missing or non-https one is
// declined without a request, because a private controller may not be reachable at the control
// session's endpoint.
func TestStager_OfferBaseURL(t *testing.T) {
	for _, base := range []string{"", "http://controller.example", "controller.example", "https://",
		"https://user:pw@controller.example", "https://controller.example/dl", "https://controller.example?x=1"} {
		t.Run(base, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
			e := newOTAEnv(t, rel)
			s := e.stager(ctx, "full")
			o := rel.offer()
			o.BaseUrl = base
			s.Offer(o)
			st := e.until(agentv1.UpdatePhase_UPDATE_PHASE_DECLINED)
			if !strings.Contains(st.GetDetail(), "controller URL") {
				t.Errorf("declined %q, want the controller URL named", st.GetDetail())
			}
			if reqs := e.requested(); len(reqs) != 0 {
				t.Errorf("requests %v, want none", reqs)
			}
		})
	}
}

// filesSource serves a release's files from memory, as the mirror's directory does.
type filesSource map[string][]byte

func (f filesSource) Open(_ context.Context, name string) (io.ReadCloser, error) {
	b, ok := f[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// TestStageRelease: the controller stages a release of its own mirror for the root updater, which
// checks it as it does an agent's; a manifest of another version, one without a build for this
// host, a signature that does not verify and too little space are refused, and nothing is
// staged then (D158).
func TestStageRelease(t *testing.T) {
	root, err := release.ParsePublicKey(otaRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	opts := func(dir string) agent.UpdateOptions {
		return agent.UpdateOptions{Dir: dir, Variant: "full", Roots: []release.PublicKey{root}, OS: "linux", Arch: "amd64",
			FreeSpace: func(string) (uint64, error) { return 1 << 40, nil }}
	}
	r := newOTARelease(t, "0.2.0", 7, release.Stable, "full")
	t.Run("staged, the manifest with it", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "update")
		if err := agent.StageRelease(context.Background(), opts(dir), filesSource(r.files), "0.2.0"); err != nil {
			t.Fatal(err)
		}
		for name, want := range r.files {
			if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || !bytes.Equal(got, want) { //nolint:gosec // G304: under t.TempDir
				t.Errorf("%s staged as %q, %v", name, got, err)
			}
		}
	})
	t.Run("refused, and nothing staged", func(t *testing.T) {
		bad := maps.Clone(r.files)
		bad[release.ManifestSigFile] = otaRoot.Sign([]byte("another manifest"))
		noBuild := newOTARelease(t, "0.2.0", 7, release.Stable, "connector")
		for name, tc := range map[string]struct {
			src     filesSource
			version string
			free    uint64
		}{
			"another version":           {filesSource(r.files), "0.3.0", 1 << 40},
			"a signature that fails":    {filesSource(bad), "0.2.0", 1 << 40},
			"no build for this variant": {filesSource(noBuild.files), "0.2.0", 1 << 40},
			"nothing in the mirror":     {filesSource{}, "0.2.0", 1 << 40},
			"too little space":          {filesSource(r.files), "0.2.0", 10},
		} {
			dir := filepath.Join(t.TempDir(), "update")
			o := opts(dir)
			o.FreeSpace = func(string) (uint64, error) { return tc.free, nil }
			if err := agent.StageRelease(context.Background(), o, tc.src, tc.version); err == nil {
				t.Errorf("%s: staged", name)
			}
			if _, err := os.Stat(filepath.Join(dir, release.ManifestFile)); err == nil {
				t.Errorf("%s: a manifest was staged", name)
			}
		}
	})
}
