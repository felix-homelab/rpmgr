// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

var (
	relRoot = releasetest.Key("controller test root")
	relNow  = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
)

// releaseFiles are the files of a test release of version 1.4.2 with a linux/amd64 artifact.
func releaseFiles(t *testing.T) map[string][]byte {
	t.Helper()
	signing := releasetest.Key("controller test signing")
	st := []byte(`{"statement":1,"signer":"` + signing.Public() + `","not_before":"2026-10-01T00:00:00Z","not_after":"2027-10-01T00:00:00Z"}`)
	body := []byte("rpmgr 1.4.2 for linux/amd64")
	sum := sha256.Sum256(body)
	man, err := json.Marshal(release.Manifest{Seq: 87, Version: "1.4.2", Floor: "1.4.0", Channel: release.Stable, IssuedAt: relNow,
		Artifacts: []release.Artifact{{OS: "linux", Arch: "amd64", Variant: "full", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"signing-key.json": st, "signing-key.json.minisig": relRoot.Sign(st), "manifest.json": man,
		"manifest.json.minisig": signing.Sign(man), "rpmgr-1.4.2-linux-amd64": body}
}

func relMirror(t *testing.T, version string) *release.Mirror {
	k, err := release.ParsePublicKey(relRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	return &release.Mirror{Dir: filepath.Join(t.TempDir(), "dl"), Version: version, Roots: []release.PublicKey{k}, Now: func() time.Time { return relNow }}
}

// TestCheckRelease: with the release check on, as by default, the controller mirrors its own
// release from GitHub's address through the proxy the environment names (R44); switched off, it
// asks nothing; with the release source unreachable, the mirror keeps what it has.
func TestCheckRelease(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	files := releaseFiles(t)
	var mu sync.Mutex
	var asked []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.String()) // a proxy gets the absolute URL
		mu.Unlock()
		b, ok := files[strings.TrimPrefix(r.URL.Path, "/download/v1.4.2/")]
		if r.URL.Host != "releases.example" || !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	defer proxy.Close()
	purl, _ := url.Parse(proxy.URL)
	o := controller.ReleaseCheckOptions{DB: db, Mirror: relMirror(t, "1.4.2"), Base: "http://releases.example/download", Proxy: http.ProxyURL(purl),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	if err := controller.CheckRelease(sys, o); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 5 || asked[0] != "http://releases.example/download/v1.4.2/signing-key.json" {
		t.Errorf("asked %v", asked)
	}
	if b, err := os.ReadFile(filepath.Join(o.Mirror.Dir, "1.4.2", "rpmgr-1.4.2-linux-amd64")); err != nil || string(b) != "rpmgr 1.4.2 for linux/amd64" {
		t.Errorf("the mirrored artifact: %q %v", b, err)
	}

	proxy.Close()
	if err := controller.CheckRelease(sys, o); err == nil {
		t.Error("an unreachable source")
	}
	if _, err := os.Stat(filepath.Join(o.Mirror.Dir, "1.4.2", "manifest.json")); err != nil {
		t.Errorf("the mirror lost its release: %v", err)
	}

	if _, err := settings.UpdateInstance(sys, db, &rpmgrv1.InstanceSettings{ReleaseCheck: proto.Bool(false)},
		&fieldmaskpb.FieldMask{Paths: []string{"release_check"}}, 0); err != nil {
		t.Fatal(err)
	}
	asked = nil
	if err := controller.CheckRelease(sys, o); err != nil || len(asked) != 0 {
		t.Errorf("switched off: %v, asked %v", err, asked)
	}
}

// TestReleaseCheckOff: a development build, and a build without release root keys, check
// nothing and return at once.
func TestReleaseCheckOff(t *testing.T) {
	for _, m := range []*release.Mirror{relMirror(t, "dev"), {Dir: t.TempDir(), Version: "1.4.2"}} {
		done := make(chan struct{})
		go func() {
			controller.ReleaseCheck(context.Background(), controller.ReleaseCheckOptions{Mirror: m, Source: release.Dir("/nonexistent"),
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("version %s with %d roots: still checking", m.Version, len(m.Roots))
		}
	}
}

// TestImportRelease: `rpmgr release import` puts a verified release into the mirror of the
// controller whose boot file it reads; an unverified one, or a development build, is refused.
func TestImportRelease(t *testing.T) {
	dir := t.TempDir()
	for name, b := range releaseFiles(t) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := t.TempDir()
	ctx := context.Background()
	db, err := store.OpenSQLite(ctx, filepath.Join(state, "controller.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	migs, err := migrations.Dir(store.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Migrate(ctx, db, migs); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	boot := filepath.Join(state, "controller.yaml")
	if err := os.WriteFile(boot, []byte("version: 1\npublic_url: https://panel.example.com\ndatabase: {dsn: "+filepath.Join(state, "controller.db")+"}\n"+
		"kek: {source: file, path: "+filepath.Join(state, "kek")+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var cfg config.Controller
	if err := config.Load(boot, &cfg); err != nil {
		t.Fatal(err)
	}
	roots := relMirror(t, "1.4.2").Roots
	now := func() time.Time { return relNow }
	m, err := controller.ImportRelease(ctx, boot, dir, "1.4.2", roots, now)
	if err != nil || m.Seq != 87 {
		t.Fatalf("import: %v %v", m, err)
	}
	if _, err := os.Stat(filepath.Join(state, "dl", "1.4.2", "rpmgr-1.4.2-linux-amd64")); err != nil {
		t.Errorf("the imported artifact: %v", err)
	}
	if _, err := controller.ImportRelease(ctx, boot, dir, "dev", roots, now); err == nil {
		t.Error("a development build imported")
	}
	if _, err := controller.ImportRelease(ctx, boot, dir, "1.4.2", nil, now); err == nil {
		t.Error("imported without root keys")
	}
	if err := os.WriteFile(filepath.Join(dir, "rpmgr-1.4.2-linux-amd64"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(state, "dl", "1.4.2", "rpmgr-1.4.2-linux-amd64")); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ImportRelease(ctx, boot, dir, "1.4.2", roots, now); err == nil {
		t.Error("a changed artifact imported")
	}
}
