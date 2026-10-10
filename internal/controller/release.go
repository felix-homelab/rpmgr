// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// ReleaseCheckEvery is how often the controller checks for its own release: daily (D4).
const ReleaseCheckEvery = 24 * time.Hour

// releaseBase is where GitHub serves the release assets of felix-homelab/rpmgr.
const releaseBase = "https://github.com/felix-homelab/rpmgr/releases/download"

// ReleaseCheckOptions configure ReleaseCheck.
type ReleaseCheckOptions struct {
	DB     *store.DB
	Mirror *release.Mirror
	// Source is where releases come from; nil is GitHub, at Base through Proxy.
	Source release.Source
	Base   string // "" is felix-homelab/rpmgr's release downloads
	// Proxy chooses the proxy of the requests to GitHub; nil is http.ProxyFromEnvironment
	// (HTTPS_PROXY, ALL_PROXY, NO_PROXY; R44).
	Proxy  func(*http.Request) (*url.URL, error)
	Logger *slog.Logger
}

func (o *ReleaseCheckOptions) source() release.Source {
	if o.Source != nil {
		return o.Source
	}
	proxy := o.Proxy
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}
	base := o.Base
	if base == "" {
		base = releaseBase
	}
	return release.GitHub{Base: base, Version: o.Mirror.Version,
		Client: &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{Proxy: proxy, TLSHandshakeTimeout: 10 * time.Second}}}
}

// ReleaseCheck mirrors the controller's own release once at start and then daily, while the
// instance setting release_check is on (D4, D59). The mirror is local, so every controller runs
// its own check. A development build, or a build without release root keys, checks nothing.
func ReleaseCheck(ctx context.Context, o ReleaseCheckOptions) {
	if !release.Releasable(o.Mirror.Version) || len(o.Mirror.Roots) == 0 {
		o.Logger.Info("release check off: this build mirrors no release", "version", o.Mirror.Version, "root keys", len(o.Mirror.Roots))
		return
	}
	for {
		_ = CheckRelease(ctx, o)
		select {
		case <-ctx.Done():
			return
		case <-time.After(ReleaseCheckEvery):
		}
	}
}

// CheckRelease runs one release check and logs its outcome.
func CheckRelease(ctx context.Context, o ReleaseCheckOptions) error {
	set, _, err := settings.Instance(ctx, o.DB.ReadClient())
	if err != nil {
		o.Logger.Warn("release check: settings", "error", err)
		return err
	}
	if !set.GetReleaseCheck() {
		return nil
	}
	m, err := o.Mirror.Sync(ctx, o.source())
	if err != nil {
		o.Logger.Warn("release check failed; the mirror keeps what it has", "version", o.Mirror.Version, "error", err)
		return err
	}
	o.Logger.Info("release mirrored under /dl/", "version", m.Version, "seq", m.Seq)
	return nil
}

// ImportRelease is `rpmgr release import`: it verifies the release of version in dir, as the
// release check would one from GitHub, and puts it into the controller's mirror, for air-gapped
// installations (D59). It is local administration, audited as local-cli.
func ImportRelease(ctx context.Context, path, dir, version string, roots []release.PublicKey, now func() time.Time) (*release.Manifest, error) {
	cfg, err := loadController(path)
	if err != nil {
		return nil, err
	}
	if !release.Releasable(version) {
		return nil, release.ErrDevelopment
	}
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	if _, err := authz.System(ctx, "local-cli", "rpmgr release import "+version, audit.SystemScopes(db)); err != nil {
		return nil, err
	}
	state := filepath.Dir(cfg.Database.DSN)
	m := &release.Mirror{Dir: filepath.Join(state, "dl"), Version: version, Roots: roots, Now: now}
	man, err := m.Sync(ctx, release.Dir(dir))
	if err != nil {
		return nil, err
	}
	// Run as root, the import gives the mirror to the owner of the state directory, the service
	// user, which serves and later updates it.
	return man, ownLike(m.Dir, state)
}
