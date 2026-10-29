// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/update"
)

// The limits of an OTA download (docs/03-connections.md, "Timeouts, keepalive and backoff"): the
// artifact is at most update.MaxArtifact and downloaded only with its size plus otaFreeMargin
// free; the whole download may take otaDownloadTimeout and a read may stall otaStallTimeout; a
// failed download is tried again after otaRetryFirst, the wait doubling up to otaRetryMax.
const (
	otaFreeMargin      = 64 << 20
	otaDownloadTimeout = 10 * time.Minute
	otaStallTimeout    = 60 * time.Second
	otaRetryFirst      = time.Minute
	otaRetryMax        = time.Hour
	// otaPolicyRecheck is how often an offer the local policy declined or only announced is
	// checked against the policy again, so that a changed policy takes it.
	otaPolicyRecheck = time.Minute
)

// UpdateOptions configure how an agent stages the releases its controller offers
// (docs/04-security.md, "Over-the-air updates", step 3).
type UpdateOptions struct {
	// Dir is the staging directory, which the service user writes and the root updater only
	// reads: /var/lib/rpmgr/update.
	Dir string
	// StatusFile is the root updater's status file; empty means update.StatusFile.
	StatusFile string
	// Policy returns the local policy, for auto_update and update_channel.
	Policy func() *policy.Policy
	// Variant is the build's variant, full or connector: the artifact the agent stages.
	Variant string
	// Client downloads from the controller; nil is a client with the system's roots and the proxy
	// of the environment. It never follows a redirect.
	Client *http.Client
	// Roots are the release root keys; nil means those compiled into the binary.
	Roots []release.PublicKey
	// OS and Arch default to the running binary's.
	OS, Arch string
	// FreeSpace returns the bytes the service user may still write on dir's filesystem; nil is
	// the filesystem's own count.
	FreeSpace func(dir string) (uint64, error)
	// Timeout, Stall and Recheck default to the limits of 03 and otaPolicyRecheck; tests shorten
	// them.
	Timeout, Stall, Recheck time.Duration
	// Retry returns the wait before the nth attempt after a failed one; nil doubles from 1 min to
	// 1 h.
	Retry func(n int) time.Duration
}

// errDeclined marks an offer the agent does not take; it is not tried again.
var errDeclined = errors.New("declined")

// Stager stages the releases a controller offers for the root updater: it downloads the signed
// files and the artifact for this host from the controller's /dl/<version>/, verifies them and
// writes them into the staging directory, the manifest last, so that the updater, which watches
// the manifest, starts only once the release is complete. It trusts the release's signatures, not
// the offer: the offer only says what to fetch, and the URL is always the controller's own.
type Stager struct {
	o       UpdateOptions
	version string                     // the running version
	send    func(*agentv1.UpdateState) // reports a state on the control session
	now     func() time.Time           // for signing-key statements
	logger  *slog.Logger

	mu      sync.Mutex
	offer   *agentv1.ReleaseOffer   // the offer of the last applied snapshot
	state   *agentv1.UpdateState    // the last state about the offer
	lastOut *agentv1.UpdaterOutcome // the updater's outcome last reported
	handled string                  // the offer whose outcome needs no further attempt
	byPol   string                  // the policy (policyKey) that declined or announced it
	cancel  context.CancelFunc      // ends the attempt that runs
	wake    chan struct{}
}

// newStager returns a stager; Control wires it.
func newStager(o UpdateOptions, version string, send func(*agentv1.UpdateState),
	now func() time.Time, logger *slog.Logger) *Stager {
	if o.StatusFile == "" {
		o.StatusFile = update.StatusFile
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if o.Policy == nil {
		o.Policy = policy.Defaults
	}
	if o.Client == nil {
		o.Client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}}
	}
	client := *o.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	o.Client = &client
	if o.Roots == nil {
		o.Roots = release.Roots()
	}
	if o.OS == "" {
		o.OS = runtime.GOOS
	}
	if o.Arch == "" {
		o.Arch = runtime.GOARCH
	}
	if o.FreeSpace == nil {
		o.FreeSpace = freeSpace
	}
	if o.Timeout == 0 {
		o.Timeout = otaDownloadTimeout
	}
	if o.Stall == 0 {
		o.Stall = otaStallTimeout
	}
	if o.Recheck == 0 {
		o.Recheck = otaPolicyRecheck
	}
	if o.Retry == nil {
		o.Retry = func(n int) time.Duration { return min(otaRetryFirst<<min(n-1, 6), otaRetryMax) }
	}
	return &Stager{o: o, version: version, send: send, now: now, logger: logger, wake: make(chan struct{}, 1)}
}

// Offer takes the offer of an applied snapshot, nil for none. A new offer ends an attempt for an
// earlier one; the same offer again changes nothing.
func (s *Stager) Offer(o *agentv1.ReleaseOffer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if proto.Equal(o, s.offer) {
		return
	}
	s.offer = o
	if s.cancel != nil {
		s.cancel()
	}
	if o == nil {
		s.state = nil
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// State returns the update state for the first Status of a session: the last state about the
// offer, with the root updater's last outcome from its status file. It is nil when there is
// neither.
func (s *Stager) State() *agentv1.UpdateState {
	out := s.outcome()
	s.mu.Lock()
	st := proto.CloneOf(s.state)
	s.lastOut = out
	s.mu.Unlock()
	if out == nil {
		return st
	}
	if st == nil {
		st = &agentv1.UpdateState{}
	}
	st.Updater = out
	return st
}

// outcome reads the root updater's status file; a missing file is no outcome.
func (s *Stager) outcome() *agentv1.UpdaterOutcome {
	st, err := update.ReadStatus(s.o.StatusFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		s.logger.Warn("cannot read the updater's status file", "file", s.o.StatusFile, "error", err)
		return nil
	}
	if st.State == update.Updating {
		return nil // under way: the outcome comes with its end
	}
	out := &agentv1.UpdaterOutcome{Version: st.Version, Previous: st.Previous, Reason: st.Reason}
	if !st.At.IsZero() {
		out.At = timestamppb.New(st.At)
	}
	switch st.State {
	case update.Updated:
		out.Result = agentv1.UpdaterResult_UPDATER_RESULT_UPDATED
	case update.RolledBack:
		out.Result = agentv1.UpdaterResult_UPDATER_RESULT_ROLLED_BACK
	case update.RollbackFailed:
		out.Result = agentv1.UpdaterResult_UPDATER_RESULT_ROLLBACK_FAILED
	case update.Refused:
		out.Result = agentv1.UpdaterResult_UPDATER_RESULT_REFUSED
	}
	return out
}

// Run stages the offers until ctx ends. A failed attempt is tried again after the retry wait; an
// offer the policy declined or only announced is checked again at the recheck interval, at which a
// staged release also has the updater's status file read again, so that an outcome without a
// restart, such as refused, is reported when it changes.
func (s *Stager) Run(ctx context.Context) {
	failures := 0
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	poll := time.NewTicker(s.o.Recheck)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			s.pollOutcome()
			continue
		case <-s.wake:
			failures = 0
		case <-timer.C:
		}
		timer.Stop()
		s.mu.Lock()
		offer, handled, byPol := s.offer, s.handled, s.byPol
		actx, cancel := context.WithCancel(ctx)
		s.cancel = cancel
		s.mu.Unlock()
		if offer == nil {
			cancel()
			continue
		}
		key := offerKey(offer)
		switch {
		case handled == key && byPol == "":
			cancel()
			continue
		case handled == key && s.policyKey() == byPol:
			cancel()
			timer.Reset(s.o.Recheck)
			continue
		}
		err := s.attempt(actx, offer)
		replaced := actx.Err() != nil && ctx.Err() == nil
		cancel()
		if replaced && !errors.Is(err, errDeclined) {
			continue // a newer offer ended it
		}
		switch {
		case err == nil, errors.Is(err, errDeclined):
			failures = 0
			if s.byPolicy() != "" {
				timer.Reset(s.o.Recheck)
			}
		default:
			failures++
			timer.Reset(s.o.Retry(failures))
		}
	}
}

// pollOutcome reports the updater's outcome with the state while a release is staged, if it
// changed since it was last reported.
func (s *Stager) pollOutcome() {
	s.mu.Lock()
	st, last := s.state, s.lastOut
	s.mu.Unlock()
	if st.GetPhase() != agentv1.UpdatePhase_UPDATE_PHASE_STAGED {
		return
	}
	out := s.outcome()
	if out == nil || proto.Equal(out, last) {
		return
	}
	s.mu.Lock()
	if s.state != st { // replaced meanwhile
		s.mu.Unlock()
		return
	}
	s.lastOut = out
	s.mu.Unlock()
	u := proto.CloneOf(st)
	u.Updater = out
	s.send(u)
}

// offerKey identifies an offer by its version and manifest seq.
func offerKey(o *agentv1.ReleaseOffer) string {
	return fmt.Sprintf("%s/%d", o.GetVersion(), o.GetSeq())
}

// autoUpdate is a local policy's auto_update, off for a policy that does not load (D120).
func autoUpdate(p *policy.Policy) string {
	if p.Invalid != nil {
		return policy.AutoUpdateOff
	}
	return p.AutoUpdate
}

// policyKey names what the local policy says about updates now: auto_update and update_channel.
func (s *Stager) policyKey() string {
	p := s.o.Policy()
	return autoUpdate(p) + "/" + p.UpdateChannel
}

func (s *Stager) byPolicy() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byPol
}

// report records and sends a state about offer; done marks the offer as needing no further
// attempt, and pol the auto_update value that decided it, if the policy did.
func (s *Stager) report(offer *agentv1.ReleaseOffer, st *agentv1.UpdateState, done bool, pol string) {
	s.mu.Lock()
	if !proto.Equal(offer, s.offer) { // replaced meanwhile: the state is about an old offer
		s.mu.Unlock()
		return
	}
	s.state = st
	s.handled, s.byPol = "", ""
	if done {
		s.handled, s.byPol = offerKey(offer), pol
	}
	s.mu.Unlock()
	s.send(proto.CloneOf(st))
}

// attempt handles one offer once. It returns nil once the release is staged or needs nothing,
// an error wrapping errDeclined when the agent does not take it, and another error when the
// attempt failed and should be tried again.
func (s *Stager) attempt(ctx context.Context, offer *agentv1.ReleaseOffer) error {
	v := offer.GetVersion()
	state := func(phase agentv1.UpdatePhase, detail string) *agentv1.UpdateState {
		return &agentv1.UpdateState{Version: v, Phase: phase, Detail: detail}
	}
	decline := func(pol, format string, args ...any) error {
		detail := fmt.Sprintf(format, args...)
		s.report(offer, state(agentv1.UpdatePhase_UPDATE_PHASE_DECLINED, detail), true, pol)
		s.logger.Info("not staging the offered release", "version", v, "reason", detail)
		return fmt.Errorf("%w: %s", errDeclined, detail)
	}
	fail := func(err error) error {
		s.report(offer, state(agentv1.UpdatePhase_UPDATE_PHASE_FAILED, err.Error()), false, "")
		s.logger.Warn("cannot stage the offered release; trying again later", "version", v, "error", err)
		return err
	}
	if !release.Releasable(v) {
		return decline("", "the offer names no release version: %q", v)
	}
	if v == s.version {
		s.report(offer, state(agentv1.UpdatePhase_UPDATE_PHASE_UNSPECIFIED, ""), true, "")
		return nil
	}
	pol := s.o.Policy()
	key := autoUpdate(pol) + "/" + pol.UpdateChannel
	switch auto := autoUpdate(pol); {
	case pol.Invalid != nil:
		return decline(key, "the local policy does not load, so updates are off: %v", pol.Invalid)
	case auto == policy.AutoUpdateOff:
		return decline(key, "auto_update is off in the local policy")
	case auto == policy.AutoUpdateNotify:
		s.report(offer, state(agentv1.UpdatePhase_UPDATE_PHASE_AVAILABLE, ""), true, key)
		return nil
	}
	s.report(offer, state(agentv1.UpdatePhase_UPDATE_PHASE_DOWNLOADING, ""), false, "")
	base := offer.GetBaseUrl()
	if u, err := url.Parse(base); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return decline("", "the offer's controller URL %q is not an https origin", base)
	}
	ctx, cancel := context.WithTimeout(ctx, s.o.Timeout)
	defer cancel()
	src := &dlSource{client: s.o.Client, base: base, version: v, stall: s.o.Stall}
	signed, err := (&release.Mirror{Roots: s.o.Roots, Now: s.now}).Fetch(ctx, src)
	if err != nil {
		return fail(err)
	}
	m := signed.Manifest
	switch {
	case m.Version != v || m.Seq != offer.GetSeq():
		return fail(fmt.Errorf("the controller offered %s (manifest %d) and serves the manifest of %s (%d)", v, offer.GetSeq(), m.Version, m.Seq))
	case m.Channel == release.Prerelease && pol.UpdateChannel != policy.ChannelPrerelease:
		return decline(key, "%s is a pre-release, and the local policy's update_channel is %s", v, pol.UpdateChannel)
	}
	a, err := m.Artifact(s.o.OS, s.o.Arch, s.o.Variant)
	if err != nil {
		return decline("", "the release has no %s build for %s/%s", s.o.Variant, s.o.OS, s.o.Arch)
	}
	name := release.ArtifactName(v, a)
	if a.Size > update.MaxArtifact {
		return decline("", "its artifact has %d bytes, above the cap of %d", a.Size, update.MaxArtifact)
	}
	if err := offered(offer, name, a); err != nil {
		return fail(err)
	}
	before := s.outcome()
	if err := s.write(ctx, src, signed, name, a); err != nil {
		return fail(err)
	}
	s.mu.Lock()
	s.lastOut = before
	s.mu.Unlock()
	s.report(offer, state(agentv1.UpdatePhase_UPDATE_PHASE_STAGED, ""), true, "")
	s.logger.Info("staged the offered release for the updater", "version", v, "seq", m.Seq, "dir", s.o.Dir)
	return nil
}

// offered checks the offer's entry for the artifact, if it has one, against the signed manifest.
func offered(o *agentv1.ReleaseOffer, name string, a release.Artifact) error {
	for _, f := range o.GetFiles() {
		if f.GetName() == name && (f.GetSize() != uint64(a.Size) || hex.EncodeToString(f.GetSha256()) != a.SHA256) { //nolint:gosec // G115: Size is checked against the cap
			return fmt.Errorf("the offer's %s differs from the signed manifest", name)
		}
	}
	return nil
}

// write stages a verified release: it removes what earlier releases left, downloads the artifact
// with the free-space check, and writes the signed files, the manifest last. A release staged
// already, the same manifest with its artifact, is left as it is.
func (s *Stager) write(ctx context.Context, src *dlSource, signed *release.Signed, name string, a release.Artifact) error {
	if err := os.MkdirAll(s.o.Dir, 0o750); err != nil {
		return err
	}
	root, err := os.OpenRoot(s.o.Dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if b, err := readRegular(root, release.ManifestFile); err == nil && string(b) == string(signed.ManifestJSON) && kept(root, name, a) {
		return nil
	}
	// An earlier release's manifest goes first, so that the updater never finds it next to this
	// release's files.
	if err := root.Remove(release.ManifestFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := clean(root, name); err != nil {
		return err
	}
	if !kept(root, name, a) {
		free, err := s.o.FreeSpace(s.o.Dir)
		if err != nil {
			return fmt.Errorf("cannot tell the free space in %s: %w", s.o.Dir, err)
		}
		if need := uint64(a.Size) + otaFreeMargin; free < need { //nolint:gosec // G115: Size is checked against the cap
			return fmt.Errorf("%s needs %d bytes free for the download and has %d", s.o.Dir, need, free)
		}
		if err := keep(root, name, a, func() (io.ReadCloser, error) { return src.Open(ctx, name) }); err != nil {
			return err
		}
	}
	files := map[string][]byte{release.StatementFile: signed.Statement, release.StatementSigFile: signed.StatementSig,
		release.ManifestSigFile: signed.ManifestSig, release.ManifestFile: signed.ManifestJSON}
	for _, f := range release.MetaFiles {
		sum := sha256.Sum256(files[f])
		meta := release.Artifact{Size: int64(len(files[f])), SHA256: hex.EncodeToString(sum[:])}
		if err := keep(root, f, meta, func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(files[f]))), nil }); err != nil {
			return err
		}
	}
	return syncRoot(root)
}

// clean removes the files of the staging directory but the release's artifact: earlier artifacts,
// earlier signed files and interrupted downloads. Directories stay; the updater refuses them
// anyway.
func clean(root *os.Root, artifact string) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == artifact {
			continue
		}
		if err := root.Remove(e.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// readRegular reads a small regular file of the staging directory.
func readRegular(root *os.Root, name string) ([]byte, error) {
	st, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, fmt.Errorf("%s is no small regular file", name)
	}
	return root.ReadFile(name)
}

// kept reports whether the staging directory has the file a as a regular file.
func kept(root *os.Root, name string, a release.Artifact) bool {
	st, err := root.Lstat(name)
	if err != nil || !st.Mode().IsRegular() || st.Size() != a.Size {
		return false
	}
	f, err := root.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	return a.Check(f) == nil
}

// keep writes a file that must be a to a temporary name, checks and syncs it, and renames it into
// place; a failure, a full disk included, removes the temporary file.
func keep(root *os.Root, name string, a release.Artifact, open func() (io.ReadCloser, error)) error {
	rc, err := open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	tmp := "." + name + ".part"
	_ = root.Remove(tmp) // a link planted there is removed, never followed
	f, err := root.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o640)
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
		return fmt.Errorf("%s: %w", name, err)
	}
	return root.Rename(tmp, name)
}

// syncRoot syncs the staging directory, so that the renames survive a crash.
func syncRoot(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// dlSource is a release under the controller's /dl/<version>/: names are the fixed signed files
// or made from the verified manifest, never taken from the offer.
type dlSource struct {
	client  *http.Client
	base    string // https://host[:port]
	version string
	stall   time.Duration
}

// Open downloads a file. A response other than 200, a redirect included, is an error, and a read
// that stalls longer than the stall limit ends the download.
func (d *dlSource) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	u, err := url.Parse(d.base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the controller endpoint %q is no https URL", d.base)
	}
	u.Path, u.RawQuery, u.Fragment = "/dl/"+d.version+"/"+name, "", ""
	ctx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		cancel()
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	return &stallReader{rc: resp.Body, cancel: cancel, timer: time.AfterFunc(d.stall, cancel), stall: d.stall}, nil
}

// stallReader ends a download whose reads make no progress for the stall limit.
type stallReader struct {
	rc     io.ReadCloser
	cancel context.CancelFunc
	timer  *time.Timer
	stall  time.Duration
}

func (r *stallReader) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	if n > 0 {
		r.timer.Reset(r.stall)
	}
	return n, err
}

func (r *stallReader) Close() error {
	r.timer.Stop()
	r.cancel()
	return r.rc.Close()
}
