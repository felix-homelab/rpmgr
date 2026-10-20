// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	entrelease "github.com/felix-homelab/rpmgr/internal/store/ent/release"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// memRelease is a release in memory, which counts the files it gives out.
type memRelease struct {
	files  map[string][]byte
	opened map[string]int
	fail   error
}

func (m *memRelease) Open(_ context.Context, name string) (io.ReadCloser, error) {
	if m.fail != nil {
		return nil, m.fail
	}
	m.opened[name]++
	b, ok := m.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// signedRelease signs a release of version on channel with a full and a connector build for
// linux/amd64 and a connector build for windows/amd64.
func signedRelease(t *testing.T, version string, seq uint64, channel string) *memRelease {
	t.Helper()
	signing := releasetest.Key("controller test signing")
	st := []byte(`{"statement":1,"signer":"` + signing.Public() + `","not_before":"2026-10-01T00:00:00Z","not_after":"2027-10-01T00:00:00Z"}`)
	r := &memRelease{files: map[string][]byte{}, opened: map[string]int{}}
	m := release.Manifest{Seq: seq, Version: version, Floor: "1.0.0", Channel: channel, IssuedAt: relNow}
	for _, a := range []release.Artifact{{OS: "linux", Arch: "amd64", Variant: "full"}, {OS: "linux", Arch: "amd64", Variant: "connector"},
		{OS: "windows", Arch: "amd64", Variant: "connector"}} {
		body := []byte("binary " + release.ArtifactName(version, a))
		sum := sha256.Sum256(body)
		a.Size, a.SHA256 = int64(len(body)), hex.EncodeToString(sum[:])
		m.Artifacts = append(m.Artifacts, a)
		r.files[release.ArtifactName(version, a)] = body
	}
	man, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r.files["signing-key.json"], r.files["signing-key.json.minisig"] = st, relRoot.Sign(st)
	r.files["manifest.json"], r.files["manifest.json.minisig"] = man, signing.Sign(man)
	return r
}

type fixedLister struct {
	listed []release.Listed
	err    error
	asked  int
}

func (f *fixedLister) List(context.Context) ([]release.Listed, error) {
	f.asked++
	return f.listed, f.err
}

// mirrorEnv is a controller database and mirror with releases served from memory.
type mirrorEnv struct {
	db       *store.DB
	sys      context.Context
	o        controller.ReleaseCheckOptions
	releases map[string]*memRelease
	lister   *fixedLister
}

func newMirrorEnv(t *testing.T, own string) *mirrorEnv {
	t.Helper()
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	e := &mirrorEnv{db: db, sys: storetest.SystemCtx(t), releases: map[string]*memRelease{}, lister: &fixedLister{}}
	e.o = controller.ReleaseCheckOptions{DB: db, Mirror: relMirror(t, own), Lister: e.lister,
		Source: func(v string) release.Source {
			if r, ok := e.releases[v]; ok {
				return r
			}
			return &memRelease{fail: errors.New("dial tcp: no route to host")}
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return e
}

func (e *mirrorEnv) rows(t *testing.T) map[string]*ent.Release {
	t.Helper()
	rows, err := e.db.Client().Release.Query().All(e.sys)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*ent.Release{}
	for _, r := range rows {
		out[r.Version] = r
	}
	return out
}

func (e *mirrorEnv) dirs(t *testing.T) string {
	t.Helper()
	entries, _ := os.ReadDir(e.o.Mirror.Dir)
	var names []string
	for _, x := range entries {
		if x.IsDir() {
			names = append(names, x.Name())
		}
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}

func (e *mirrorEnv) channel(t *testing.T, c rpmgrv1.UpdateChannel) {
	t.Helper()
	if _, err := settings.UpdateInstance(e.sys, e.db, &rpmgrv1.InstanceSettings{UpdateChannel: c.Enum()},
		&fieldmaskpb.FieldMask{Paths: []string{"update_channel"}}, 0); err != nil {
		t.Fatal(err)
	}
}

// TestCheckRelease_KeepsWhatRolloutsNeed: the mirror keeps the controller's own version, the one
// it ran before and a running rollout's target, each with every artifact; the listing records the
// releases of the instance's channel newer than the oldest kept version without downloading them;
// a finished rollout's target goes, and a manifest with a higher seq replaces the recorded one.
func TestCheckRelease_KeepsWhatRolloutsNeed(t *testing.T) {
	e := newMirrorEnv(t, "1.4.2")
	for v, seq := range map[string]uint64{"1.4.2": 87, "1.5.0": 90, "1.3.0": 80, "1.6.0": 95, "1.2.0": 70} {
		e.releases[v] = signedRelease(t, v, seq, release.Stable)
	}
	e.releases["1.7.0-rc.1"] = signedRelease(t, "1.7.0-rc.1", 99, release.Prerelease)
	e.releases["1.6.1"] = signedRelease(t, "1.6.1", 96, release.Prerelease) // listed as stable, signed for prerelease
	e.lister.listed = []release.Listed{{Version: "1.7.0-rc.1", Prerelease: true}, {Version: "1.6.1"}, {Version: "1.6.0"},
		{Version: "1.5.0"}, {Version: "1.4.2"}, {Version: "1.2.0"}}
	// The controller ran 1.4.2 and was upgraded to 1.5.0.
	if err := controller.CheckRelease(e.sys, e.o); err != nil {
		t.Fatal(err)
	}
	e.o.Mirror.Version = "1.5.0"
	// An uploaded signed downgrade, the target of a running rollout.
	up := signedRelease(t, "1.3.0", 80, release.Stable).files
	rel, err := e.db.Client().Release.Create().SetVersion("1.3.0").SetChannel(entrelease.ChannelStable).SetManifestSeq(80).
		SetManifest(up["manifest.json"]).SetSignature(up["manifest.json.minisig"]).SetSigningKeyStatement(up["signing-key.json"]).
		SetStatementSignature(up["signing-key.json.minisig"]).SetSource(entrelease.SourceUpload).Save(e.sys)
	if err != nil {
		t.Fatal(err)
	}
	ro, err := e.db.Client().Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_admin").Save(e.sys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.o.Mirror.Dir, "1.1.0"), 0o750); err != nil { // a version nothing keeps
		t.Fatal(err)
	}

	if err := controller.CheckRelease(e.sys, e.o); err != nil {
		t.Fatal(err)
	}
	if got := e.dirs(t); got != "1.3.0 1.4.2 1.5.0" {
		t.Errorf("kept %s", got)
	}
	for _, v := range []string{"1.3.0", "1.4.2", "1.5.0"} {
		for _, name := range []string{"rpmgr-" + v + "-linux-amd64", "rpmgr-" + v + "-linux-amd64-connector", "rpmgr-" + v + "-windows-amd64-connector.exe"} {
			if _, err := os.Stat(filepath.Join(e.o.Mirror.Dir, v, name)); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
	rows := e.rows(t)
	for v, want := range map[string]string{"1.5.0": "check mirrored", "1.4.2": "check mirrored", "1.3.0": "upload mirrored", "1.6.0": "check listed"} {
		r, ok := rows[v]
		got := "missing"
		if ok {
			got = string(r.Source) + " listed"
			if r.MirroredAt != nil {
				got = string(r.Source) + " mirrored"
			}
		}
		if got != want {
			t.Errorf("%s: %s, want %s", v, got, want)
		}
	}
	for _, v := range []string{"1.7.0-rc.1", "1.6.1", "1.2.0"} {
		if _, ok := rows[v]; ok {
			t.Errorf("%s recorded on a stable instance or older than every kept version", v)
		}
	}
	if n := e.releases["1.6.0"].opened["rpmgr-1.6.0-linux-amd64"]; n != 0 {
		t.Errorf("a listed release downloaded its artifacts %d times", n)
	}

	// The rollout completes, a higher seq of the own version appears, and the instance moves to
	// the prerelease channel.
	if err := e.db.Client().Rollout.UpdateOneID(ro.ID).SetState(rollout.StateCompleted).Exec(e.sys); err != nil {
		t.Fatal(err)
	}
	e.releases["1.5.0"] = signedRelease(t, "1.5.0", 91, release.Stable)
	e.channel(t, rpmgrv1.UpdateChannel_UPDATE_CHANNEL_PRERELEASE)
	if err := controller.CheckRelease(e.sys, e.o); err != nil {
		t.Fatal(err)
	}
	if got := e.dirs(t); got != "1.4.2 1.5.0" {
		t.Errorf("kept %s after the rollout", got)
	}
	rows = e.rows(t)
	if rows["1.3.0"].MirroredAt != nil {
		t.Error("a removed version still counts as mirrored")
	}
	if rows["1.5.0"].ManifestSeq != 91 {
		t.Errorf("seq %d, want the higher 91", rows["1.5.0"].ManifestSeq)
	}
	for _, v := range []string{"1.7.0-rc.1", "1.6.1"} {
		if r, ok := rows[v]; !ok || r.MirroredAt != nil {
			t.Errorf("%s on a prerelease instance: %+v", v, r)
		}
	}
}

// TestCheckRelease_FailuresKeepWhatIsThere: an unreachable or rate-limited source fails the check
// and keeps every kept version; with the release check off nothing is asked, and versions nothing
// keeps still go.
func TestCheckRelease_FailuresKeepWhatIsThere(t *testing.T) {
	e := newMirrorEnv(t, "1.4.2")
	e.releases["1.4.2"] = signedRelease(t, "1.4.2", 87, release.Stable)
	if err := controller.CheckRelease(e.sys, e.o); err != nil {
		t.Fatal(err)
	}

	until := relNow.Add(40 * time.Minute)
	e.lister.err = &release.RateLimitedError{Until: until}
	e.releases["1.4.2"].fail = errors.New("dial tcp: no route to host")
	err := controller.CheckRelease(e.sys, e.o)
	var rl *release.RateLimitedError
	if !errors.As(err, &rl) || !strings.Contains(err.Error(), "no route to host") {
		t.Errorf("a failing source: %v", err)
	}
	if !e.o.Mirror.Complete("1.4.2") {
		t.Error("the own version was lost")
	}

	if err := os.MkdirAll(filepath.Join(e.o.Mirror.Dir, "1.0.0"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := settings.UpdateInstance(e.sys, e.db, &rpmgrv1.InstanceSettings{ReleaseCheck: new(false)},
		&fieldmaskpb.FieldMask{Paths: []string{"release_check"}}, 0); err != nil {
		t.Fatal(err)
	}
	asked := e.lister.asked
	if err := controller.CheckRelease(e.sys, e.o); err != nil {
		t.Errorf("switched off: %v", err)
	}
	if e.lister.asked != asked {
		t.Error("switched off, the check listed releases")
	}
	if got := e.dirs(t); got != "1.4.2" {
		t.Errorf("switched off, kept %s", got)
	}
}

// TestNextReleaseCheck: daily after a success; after failures 15 min, doubling up to a day; a rate
// limit is waited out, but never longer than a day.
func TestNextReleaseCheck(t *testing.T) {
	now := relNow
	fail := errors.New("dial tcp: no route to host")
	wait, retry := controller.NextReleaseCheck(nil, 0, now)
	if wait != 24*time.Hour || retry != 0 {
		t.Errorf("success: %v %v", wait, retry)
	}
	var waits []time.Duration
	for range 9 {
		wait, retry = controller.NextReleaseCheck(fail, retry, now)
		waits = append(waits, wait)
	}
	want := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour,
		24 * time.Hour, 24 * time.Hour}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("failures: %v", waits)
			break
		}
	}
	if wait, _ := controller.NextReleaseCheck(nil, retry, now); wait != 24*time.Hour {
		t.Errorf("a success after failures: %v", wait)
	}
	limited := errors.Join(fail, &release.RateLimitedError{Until: now.Add(3 * time.Hour)})
	if wait, _ := controller.NextReleaseCheck(limited, 0, now); wait != 3*time.Hour {
		t.Errorf("rate-limited: %v", wait)
	}
	if wait, _ := controller.NextReleaseCheck(&release.RateLimitedError{Until: now.Add(72 * time.Hour)}, 0, now); wait != 24*time.Hour {
		t.Errorf("rate-limited for days: %v", wait)
	}
}
