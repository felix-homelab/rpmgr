// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/mod/semver"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/proxyenv"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	entrelease "github.com/felix-homelab/rpmgr/internal/store/ent/release"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
)

// ReleaseCheckEvery is how often the controller checks for releases: daily (D4). A failed check
// is retried after ReleaseRetryFirst, the wait doubling up to ReleaseCheckEvery, and a
// rate-limited one when the release source accepts requests again (docs/03-connections.md,
// "Timeouts, keepalive and backoff").
const (
	ReleaseCheckEvery = 24 * time.Hour
	ReleaseRetryFirst = 15 * time.Minute
)

// ReleaseCheckGap is how long after a release check started an Instance Admin may ask for the
// next one (docs/03-connections.md, "Timeouts, keepalive and backoff").
const ReleaseCheckGap = time.Minute

// ReleaseChecks is the state of a controller's release check, which ReleaseCheck records and
// the API shows, and the requests to check at once: for a rollout or an upload (Wake, D125), and
// an Instance Admin's "Check now" (CheckNow). Its methods are safe on nil, which records nothing.
type ReleaseChecks struct {
	none bool // the build checks for no releases
	now  func() time.Time
	wake chan struct{}

	mu             sync.Mutex
	running, asked bool
	started, ended time.Time
	outcome        rpmgrv1.ReleaseCheckOutcome
	err            string
	limited        time.Time // the release source accepts requests again
}

// NewReleaseChecks is the state of the release check of the mirror m, before its first check.
func NewReleaseChecks(m *release.Mirror) *ReleaseChecks {
	now := m.Now
	if now == nil {
		now = time.Now
	}
	return &ReleaseChecks{none: !release.Releasable(m.Version) || len(m.Roots) == 0, now: now, wake: make(chan struct{}, 1)}
}

// Wakes is the channel of ReleaseCheckOptions.Wake.
func (c *ReleaseChecks) Wakes() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.wake
}

// Wake asks for a check at once, without waiting for it and without the gap of CheckNow (D125).
func (c *ReleaseChecks) Wake() {
	if c == nil {
		return
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// CheckNow asks for a check at once and returns the state: it joins a check that runs or was
// asked for. A positive wait refuses it until the gap after the last check's start, or the
// release source's rate limit, has passed. A build that checks for no releases returns
// release.ErrDevelopment.
func (c *ReleaseChecks) CheckNow() (*rpmgrv1.ReleaseCheck, time.Duration, error) {
	if c == nil || c.none {
		return nil, 0, release.ErrDevelopment
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running && !c.asked {
		now := c.now()
		if wait := max(c.started.Add(ReleaseCheckGap).Sub(now), c.limited.Sub(now)); wait > 0 {
			return c.statusLocked(), wait, nil
		}
		c.asked = true
		c.Wake()
	}
	return c.statusLocked(), 0, nil
}

// Status is the state of the release check.
func (c *ReleaseChecks) Status() *rpmgrv1.ReleaseCheck {
	if c == nil || c.none {
		return &rpmgrv1.ReleaseCheck{Outcome: rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_NONE}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.statusLocked()
}

func (c *ReleaseChecks) statusLocked() *rpmgrv1.ReleaseCheck {
	st := &rpmgrv1.ReleaseCheck{Running: c.running || c.asked, Outcome: c.outcome, Error: c.err}
	if !c.ended.IsZero() {
		st.CheckTime = timestamppb.New(c.ended)
	}
	return st
}

func (c *ReleaseChecks) begin() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running, c.asked, c.started = true, false, c.now()
}

// end records a check that ended with err, which listed releases if checked. A check that ctx
// ended records nothing.
func (c *ReleaseChecks) end(ctx context.Context, err error, checked bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	if ctx.Err() != nil {
		return
	}
	c.ended, c.err = c.now(), ""
	var rl *release.RateLimitedError
	switch {
	case errors.As(err, &rl):
		c.limited = rl.Until
		fallthrough
	case err != nil:
		c.outcome, c.err = rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_FAILED, err.Error()
	case checked:
		c.outcome = rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_OK
	default:
		c.outcome = rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_OFF
	}
}

// releaseBase is where GitHub serves the release assets of felix-homelab/rpmgr, and releaseAPI
// where its REST API lists them.
const (
	releaseBase = "https://github.com/felix-homelab/rpmgr/releases/download"
	releaseAPI  = "https://api.github.com/repos/felix-homelab/rpmgr/releases"
)

// ReleaseCheckOptions configure ReleaseCheck.
type ReleaseCheckOptions struct {
	DB     *store.DB
	Mirror *release.Mirror
	// Source gives the files of a version; nil is GitHub's release downloads at Base through Proxy.
	Source func(version string) release.Source
	// Lister lists the releases; nil is GitHub's API at API through Proxy.
	Lister release.Lister
	Base   string // "" is felix-homelab/rpmgr's release downloads
	API    string // "" is felix-homelab/rpmgr's release listing
	// Proxy chooses the proxy of the requests to GitHub; nil is proxyenv.FromEnvironment
	// (HTTPS_PROXY, else ALL_PROXY; NO_PROXY; R44, D93).
	Proxy func(*http.Request) (*url.URL, error)
	// Wake, if set, starts a check at once, as a new rollout or upload asks for one (D125).
	Wake <-chan struct{}
	// Checks, if set, records each check (ReleaseChecks.Wakes is the Wake of a controller).
	Checks *ReleaseChecks
	Logger *slog.Logger
}

func (o *ReleaseCheckOptions) client() *http.Client {
	proxy := o.Proxy
	if proxy == nil {
		proxy = proxyenv.FromEnvironment
	}
	return &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{Proxy: proxy, TLSHandshakeTimeout: 10 * time.Second}}
}

func (o *ReleaseCheckOptions) source(version string) release.Source {
	if o.Source != nil {
		return o.Source(version)
	}
	base := o.Base
	if base == "" {
		base = releaseBase
	}
	return release.GitHub{Base: base, Version: version, Client: o.client()}
}

func (o *ReleaseCheckOptions) lister() release.Lister {
	if o.Lister != nil {
		return o.Lister
	}
	api := o.API
	if api == "" {
		api = releaseAPI
	}
	return release.GitHubReleases{API: api, Client: o.client(), Now: o.Mirror.Now}
}

// ReleaseCheck checks for releases once at start and then daily, while the instance setting
// release_check is on (D4, D59, D119); a failed check is retried sooner. The mirror is local, so
// every controller runs its own check. A development build, or a build without release root keys,
// checks nothing.
func ReleaseCheck(ctx context.Context, o ReleaseCheckOptions) {
	if !release.Releasable(o.Mirror.Version) || len(o.Mirror.Roots) == 0 {
		o.Logger.Info("release check off: this build mirrors no release", "version", o.Mirror.Version, "root keys", len(o.Mirror.Roots))
		return
	}
	retry := time.Duration(0)
	for {
		var wait time.Duration
		wait, retry = nextReleaseCheck(CheckRelease(ctx, o), retry, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-o.Wake:
		}
	}
}

// nextReleaseCheck is the wait before the next release check after one that ended with err, and
// the retry wait to remember: daily after success; after a failure ReleaseRetryFirst, doubling up
// to a day, and for a rate limit at least until the source accepts requests again.
func nextReleaseCheck(err error, retry time.Duration, now time.Time) (wait, nextRetry time.Duration) {
	if err == nil {
		return ReleaseCheckEvery, 0
	}
	retry = min(max(2*retry, ReleaseRetryFirst), ReleaseCheckEvery)
	wait = retry
	var rl *release.RateLimitedError
	if errors.As(err, &rl) {
		wait = min(max(wait, rl.Until.Sub(now)), ReleaseCheckEvery)
	}
	return wait, retry
}

// CheckRelease runs one release check and logs its outcome; a check that ctx ends is no failure.
// With the release check on, it keeps the controller's own release and the version it ran before,
// and lists the releases of the instance's channel newer than the oldest kept version, verifying
// their manifests without their artifacts. Always, it keeps the target of each running or paused
// rollout, also one the mirror does not hold yet (D125), and removes the versions nothing keeps
// (docs/04-security.md, "Over-the-air updates").
func CheckRelease(ctx context.Context, o ReleaseCheckOptions) (err error) {
	checked := false
	o.Checks.begin()
	defer func() { o.Checks.end(ctx, err, checked) }()
	set, _, err := settings.Instance(ctx, o.DB.ReadClient())
	if err != nil {
		if ctx.Err() == nil {
			o.Logger.Warn("release check: settings", "error", err)
		}
		return err
	}
	previous, err := o.Mirror.RecordOwn()
	if err != nil {
		o.Logger.Warn("release check: the record of the controller's own version", "error", err)
	}
	keep, targets, err := keptVersions(ctx, o.DB.ReadClient(), o.Mirror.Version, previous)
	if err != nil {
		if ctx.Err() == nil {
			o.Logger.Warn("release check: the versions to keep", "error", err)
		}
		return err
	}
	var errs []error
	if checked = set.GetReleaseCheck(); checked {
		errs = append(errs, o.check(ctx, set.GetUpdateChannel() == rpmgrv1.UpdateChannel_UPDATE_CHANNEL_PRERELEASE, keep))
	} else {
		errs = append(errs, o.sync(ctx, targets))
	}
	removed, err := o.Mirror.Prune(keep...)
	errs = append(errs, err)
	if len(removed) > 0 {
		errs = append(errs, store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
			return tx.Release.Update().Where(entrelease.VersionIn(removed...)).ClearMirroredAt().Exec(ctx)
		}))
		o.Logger.Info("release mirror: removed versions nothing keeps", "versions", removed)
	}
	err = errors.Join(errs...)
	if err != nil && ctx.Err() == nil {
		o.Logger.Warn("release check failed; the mirror keeps what it has", "version", o.Mirror.Version, "error", err)
	}
	return err
}

// sync keeps every version of versions from the release source, with the signed files the
// controller recorded where their seq is higher than the source's (D125).
func (o *ReleaseCheckOptions) sync(ctx context.Context, versions []string) error {
	var errs []error
	for _, v := range versions {
		s, err := o.Mirror.SyncVersion(ctx, v, o.syncSource(ctx, v))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		now := o.Mirror.Now()
		errs = append(errs, recordRelease(ctx, o.DB, s, entrelease.SourceCheck, &now))
		o.Logger.Info("release mirrored under /dl/", "version", v, "seq", s.Manifest.Seq)
	}
	return errors.Join(errs...)
}

// syncSource is the source of a version to keep: the release source, with the signed files of an
// uploaded or imported manifest instead whose seq is higher than the source's, or when the source
// gives none, such as an uploaded signed downgrade re-signed with a higher seq (D125).
func (o *ReleaseCheckOptions) syncSource(ctx context.Context, v string) release.Source {
	src := o.source(v)
	row, err := o.DB.ReadClient().Release.Query().Where(entrelease.Version(v)).Only(ctx)
	if err != nil || row.Source == entrelease.SourceCheck {
		return src
	}
	if up, err := o.Mirror.Fetch(ctx, src); err == nil && up.Manifest.Seq >= uint64(row.ManifestSeq) { //nolint:gosec // G115: seq is positive
		return src
	}
	return release.WithSigned(src, &release.Signed{Statement: row.SigningKeyStatement, StatementSig: row.StatementSignature,
		ManifestJSON: row.Manifest, ManifestSig: row.Signature})
}

// check keeps every version of keep and lists the newer releases.
func (o *ReleaseCheckOptions) check(ctx context.Context, prerelease bool, keep []string) error {
	errs := []error{o.sync(ctx, keep)}
	listed, err := o.lister().List(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	oldest := oldestVersion(keep)
	known, err := o.DB.ReadClient().Release.Query().Select(entrelease.FieldVersion).Strings(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	have := map[string]bool{}
	for _, v := range known {
		have[v] = true
	}
	for _, l := range listed {
		pre := l.Prerelease || semver.Prerelease("v"+l.Version) != ""
		if have[l.Version] || (pre && !prerelease) || semver.Compare("v"+l.Version, "v"+oldest) <= 0 {
			continue
		}
		s, err := o.Mirror.Fetch(ctx, o.source(l.Version))
		if err == nil && s.Manifest.Version != l.Version {
			err = errors.New("release: the listed release " + l.Version + " has the manifest of " + s.Manifest.Version)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if s.Manifest.Channel == release.Prerelease && !prerelease {
			continue
		}
		errs = append(errs, recordRelease(ctx, o.DB, s, entrelease.SourceCheck, nil))
	}
	return errors.Join(errs...)
}

// keptVersions are the versions the mirror keeps: the controller's own, the one it ran before,
// and the target of each running or paused rollout (D119), and of them the rollout targets.
func keptVersions(ctx context.Context, c *ent.Client, own, previous string) (keep, targets []string, err error) {
	keep = []string{own}
	if release.Releasable(previous) && previous != own {
		keep = append(keep, previous)
	}
	active, err := c.Rollout.Query().Where(rollout.Active(true)).QueryRelease().Select(entrelease.FieldVersion).Strings(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, v := range active {
		if !release.Releasable(v) {
			continue
		}
		targets = append(targets, v)
		if !contains(keep, v) {
			keep = append(keep, v)
		}
	}
	return keep, targets, nil
}

func contains(vs []string, v string) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}

// oldestVersion is the lowest of versions.
func oldestVersion(versions []string) string {
	oldest := versions[0]
	for _, v := range versions[1:] {
		if semver.Compare("v"+v, "v"+oldest) < 0 {
			oldest = v
		}
	}
	return oldest
}

// recordRelease records a verified release in the releases table (store.RecordRelease).
func recordRelease(ctx context.Context, db *store.DB, s *release.Signed, source entrelease.Source, mirrored *time.Time) error {
	_, err := store.RecordRelease(ctx, db, s, source, mirrored)
	return err
}

// ImportRelease is `rpmgr release import`: it verifies the release of version in dir, as the
// release check would one from GitHub, puts it into the controller's mirror and records it, for
// air-gapped installations (D59). It is local administration, audited as local-cli.
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
	sys, err := authz.System(ctx, "local-cli", "rpmgr release import "+version, audit.SystemScopes(db))
	if err != nil {
		return nil, err
	}
	state := filepath.Dir(cfg.Database.DSN)
	m := &release.Mirror{Dir: filepath.Join(state, "dl"), Version: version, Roots: roots, Now: now}
	s, err := m.SyncVersion(ctx, version, release.Dir(dir))
	if err != nil {
		return nil, err
	}
	at := now()
	if err := recordRelease(sys, db, s, entrelease.SourceImport, &at); err != nil {
		return nil, err
	}
	// Run as root, the import gives the mirror to the owner of the state directory, the service
	// user, which serves and later updates it.
	return s.Manifest, ownLike(m.Dir, state)
}

// releaseSource gives src for every version, nil for GitHub.
func releaseSource(src release.Source) func(string) release.Source {
	if src == nil {
		return nil
	}
	return func(string) release.Source { return src }
}

// releaseLister lists nothing when a test's release source replaces GitHub, nil for GitHub.
func releaseLister(src release.Source) release.Lister {
	if src == nil {
		return nil
	}
	return listNothing{}
}

type listNothing struct{}

func (listNothing) List(context.Context) ([]release.Listed, error) { return nil, nil }
