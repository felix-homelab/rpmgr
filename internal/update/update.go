// SPDX-License-Identifier: Apache-2.0

// Package update is the root-owned updater (docs/04-security.md, "Over-the-air updates"). It copies
// a release that the agent staged in a directory the service user writes, verifies the copy and
// hands it on to be installed. It trusts nothing the agent decided: it reads the local policy,
// the installation record and its own state itself.
package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"golang.org/x/mod/semver"

	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/release"
)

// MaxArtifact is the updater's hard cap on a staged artifact (docs/03-connections.md, "Timeouts,
// keepalive and backoff"), whatever the manifest says.
const MaxArtifact = 256 << 20

// maxMeta caps each of the release's signed files and the updater's own JSON files.
const maxMeta = 1 << 20

// The files a staged release consists of besides its artifact (docs/04-security.md, "Release
// signing").
const (
	statementFile    = "signing-key.json"
	statementSigFile = "signing-key.json.minisig"
	manifestFile     = "manifest.json"
	manifestSigFile  = "manifest.json.minisig"
)

// Files in the updater's state directory.
const (
	installFile = "install.json"
	stateFile   = "state.json"
	stagingDir  = "staging"
)

var (
	// ErrRefused means the staged release may not be installed on this host; the error says why.
	ErrRefused = errors.New("update: refused")
	// ErrHostile means the staging directory holds something other than plain files within the
	// caps: a symbolic link, a FIFO, a device, or a file too large.
	ErrHostile = errors.New("update: unsafe staging")
)

// Install is how rpmgr was installed on this host (/var/lib/rpmgr-update/install.json).
type Install struct {
	Method  string   `json:"method"`
	Path    string   `json:"path"`
	Variant string   `json:"variant"`
	Roles   []string `json:"roles,omitempty"`
	// Role is the single role install scripts of v0.1.0 recorded; Roles replaces it.
	Role string `json:"role,omitempty"`
}

// roles returns the recorded roles, the single role of v0.1.0 included.
func (in Install) roles() []string {
	if len(in.Roles) == 0 && in.Role != "" {
		return []string{in.Role}
	}
	return in.Roles
}

// State is the updater's persisted state (/var/lib/rpmgr-update/state.json): the highest manifest
// seq accepted, the version floor, and the version that was last rolled back (D120).
type State struct {
	Seq    uint64  `json:"seq"`
	Floor  string  `json:"floor"`
	Failed *Failed `json:"failed,omitempty"`
}

// Failed is a version that was rolled back on this host, with the seq of the manifest that
// offered it. It is not installed again until a manifest with a higher seq offers it.
type Failed struct {
	Version string `json:"version"`
	Seq     uint64 `json:"seq"`
}

// Staged is a verified release in the updater's root-only staging directory.
type Staged struct {
	Manifest *release.Manifest
	Artifact release.Artifact
	// Path is the verified copy of the artifact, which only root can write.
	Path string
	// Next is the state to persist once the release is installed and ready, never before.
	Next State
}

// Updater copies and verifies staged releases.
type Updater struct {
	// Staged is the directory the agent writes (/var/lib/rpmgr/update).
	Staged string
	// State is the updater's own directory (/var/lib/rpmgr-update), owned by root.
	State string
	// Policy is the local policy file (/etc/rpmgr/policy.yaml).
	Policy string
	// Roots are the release root keys; nil means those compiled into the binary.
	Roots []release.PublicKey
	// Now is the clock for signing-key statements; nil means time.Now.
	Now func() time.Time
	// OS and Arch default to the running binary's.
	OS, Arch string
}

// Stage copies the staged release into the root-only staging directory and verifies the copy:
// the signature chain, the manifest's seq and floor against the persisted state, its channel
// against the policy, the artifact for this host's OS, architecture and variant, and its size and
// SHA-256. It returns the verified copy. Nothing is persisted; the installer does that after
// success.
func (u *Updater) Stage() (*Staged, error) {
	in, err := u.install()
	if err != nil {
		return nil, err
	}
	channel, err := u.channel()
	if err != nil {
		return nil, err
	}
	st, err := ReadState(u.State)
	if err != nil {
		return nil, err
	}
	src, err := openStaged(u.Staged)
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()
	meta := make(map[string][]byte, 4)
	for _, name := range []string{statementFile, statementSigFile, manifestFile, manifestSigFile} {
		if meta[name], err = src.read(name, maxMeta); err != nil {
			return nil, err
		}
	}
	m, err := u.verify(meta, in, channel, st)
	if err != nil {
		return nil, err
	}
	a, err := m.Artifact(u.os(), u.arch(), in.Variant)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if a.Size > MaxArtifact {
		return nil, fmt.Errorf("%w: the manifest's artifact has %d bytes, above the cap of %d", ErrHostile, a.Size, MaxArtifact)
	}
	dst, err := u.copyArtifact(src, release.ArtifactName(m.Version, a), a)
	if err != nil {
		return nil, err
	}
	next, _ := release.State{Seq: st.Seq, Floor: st.Floor}.Accept(m, channel)
	return &Staged{Manifest: m, Artifact: a, Path: dst, Next: State{Seq: next.Seq, Floor: next.Floor}}, nil
}

// afterCopy, if set, runs after the artifact is copied and before the copy is verified; tests use
// it to change the staged file once it was copied.
var afterCopy func()

// copyArtifact copies the staged artifact into a new file of the root-only staging directory,
// verifies that copy and gives it its final name. Copies of earlier runs are removed first, and a
// copy that fails is removed, so the directory never grows.
func (u *Updater) copyArtifact(src *staged, name string, a release.Artifact) (string, error) {
	dir := filepath.Join(u.State, stagingDir)
	if err := prepareStaging(dir); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".copy-*") // O_CREAT|O_EXCL, 0600: never an existing file or link
	if err != nil {
		return "", fmt.Errorf("update: %w", err)
	}
	done := false
	defer func() {
		if !done {
			_ = os.Remove(tmp.Name())
		}
	}()
	err = src.copy(name, tmp, a.Size)
	if cerr := tmp.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("update: %w", cerr)
	}
	if err != nil {
		return "", err
	}
	if afterCopy != nil {
		afterCopy()
	}
	if err := checkCopy(tmp.Name(), a); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, name)
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", fmt.Errorf("update: %w", err)
	}
	done = true
	return dst, nil
}

// verify checks the signed files and decides whether the manifest may be installed here.
func (u *Updater) verify(meta map[string][]byte, in Install, channel string, st State) (*release.Manifest, error) {
	roots := u.Roots
	if roots == nil {
		roots = release.Roots()
	}
	now := time.Now
	if u.Now != nil {
		now = u.Now
	}
	m, err := release.Verify(roots, meta[statementFile], meta[statementSigFile], meta[manifestFile], meta[manifestSigFile], now())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if _, err := (release.State{Seq: st.Seq, Floor: st.Floor}).Accept(m, channel); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if f := st.Failed; f != nil && f.Version == m.Version && m.Seq <= f.Seq {
		return nil, fmt.Errorf("%w: %s was rolled back on this host; only a manifest newer than %d offers it again",
			ErrRefused, m.Version, f.Seq)
	}
	return m, nil
}

// StateDir is the updater's own directory: install.json, state.json and staging/
// (docs/10-operations.md, "Filesystem layout").
const StateDir = "/var/lib/rpmgr-update"

// PathEnabled is the link by which systemd starts rpmgr-update.path at boot: systemctl enable
// writes it into this directory wherever the unit file is, and the service user can read it.
const PathEnabled = "/etc/systemd/system/multi-user.target.wants/rpmgr-update.path"

// UpdaterInstalled reports whether the root updater is installed on this host: a Linux host with the
// updater's directory and its unit rpmgr-update.path enabled, as rpmgr setup and the install
// scripts leave it. An agent elsewhere, such as in the container image, or on a host whose updater
// has no units, as the v0.1.0 install script and rpmgr setup --no-unit leave it, stages nothing and
// announces no capability ota, so that a rollout skips it instead of waiting for an updater that
// never runs. The service user cannot read the directory, but it can tell that it is there.
func UpdaterInstalled() bool { return runtime.GOOS == "linux" && installedAt(StateDir, PathEnabled) }

// installedAt reports whether dir is a directory and enabled, the link that enables the updater's
// path unit, leads to a regular file.
func installedAt(dir, enabled string) bool {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return false
	}
	unit, err := os.Stat(enabled)
	return err == nil && unit.Mode().IsRegular()
}

// ReadInstall reads the installation record of the updater's directory as the updater trusts it:
// a regular file that only the updater's user owns and writes.
func ReadInstall(dir string) (Install, error) {
	b, err := readOwn(filepath.Join(dir, installFile))
	if err != nil {
		return Install{}, err
	}
	var in Install
	if err := strictJSON(b, &in); err != nil {
		return Install{}, fmt.Errorf("update: %s: %w", installFile, err)
	}
	return in, nil
}

// install reads the installation record. A host whose roles include a controller or an
// all-in-one is updated too (D158): the Applier backs it up first.
func (u *Updater) install() (Install, error) {
	in, err := ReadInstall(u.State)
	if err != nil {
		return Install{}, err
	}
	roles := in.roles()
	switch {
	case in.Variant == "" || in.Path == "" || len(roles) == 0:
		return Install{}, fmt.Errorf("update: %s names no variant, path or role", installFile)
	case in.Variant == "connector" && controlRole(roles) != "":
		return Install{}, fmt.Errorf("%w: %s records the connector build, which has no controller", ErrRefused, installFile)
	case slices.Contains(roles, "controller") && slices.Contains(roles, "all-in-one"):
		return Install{}, fmt.Errorf("%w: %s names a controller and an all-in-one on one host", ErrRefused, installFile)
	}
	for _, r := range roles {
		if !updatable(r) {
			return Install{}, fmt.Errorf("%w: %s names the role %q; the updater replaces the roles of rpmgr only", ErrRefused, installFile, r)
		}
	}
	slices.Sort(roles)
	in.Roles, in.Role = slices.Compact(roles), ""
	return in, nil
}

// channel reads the local policy itself and returns its update channel. A policy that is missing
// takes the defaults; one that does not parse, or that others may write, counts as auto_update
// off (D120), as does auto_update notify or off.
func (u *Updater) channel() (string, error) {
	p, err := u.policy()
	switch {
	case err != nil:
		return "", fmt.Errorf("%w: the local policy cannot be trusted, so updates are off: %w", ErrRefused, err)
	case p.AutoUpdate != policy.AutoUpdateAuto:
		return "", fmt.Errorf("%w: the local policy sets auto_update: %s", ErrRefused, p.AutoUpdate)
	}
	return p.UpdateChannel, nil
}

func (u *Updater) os() string {
	if u.OS != "" {
		return u.OS
	}
	return runtime.GOOS
}

func (u *Updater) arch() string {
	if u.Arch != "" {
		return u.Arch
	}
	return runtime.GOARCH
}

// ReadState reads the updater's state. A missing, unreadable or malformed state.json is an error:
// the updater never guesses a floor.
func ReadState(dir string) (State, error) {
	b, err := readOwn(filepath.Join(dir, stateFile))
	if err != nil {
		return State{}, err
	}
	var st State
	if err := strictJSON(b, &st); err != nil {
		return State{}, fmt.Errorf("update: %s: %w", stateFile, err)
	}
	if !full(st.Floor) || (st.Failed != nil && !full(st.Failed.Version)) {
		return State{}, fmt.Errorf("update: %s holds a malformed version", stateFile)
	}
	return st, nil
}

// WriteState replaces the updater's state atomically: a new file, synced, renamed over the old
// one, and the directory synced, so a crash leaves the old state or the new one.
func WriteState(dir string, st State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("update: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("update: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("update: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, stateFile)); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	d, err := os.Open(dir) //nolint:gosec // G304: the updater's own state directory
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	return nil
}

// policy reads the local policy as the updater trusts it: a missing file is the defaults; the
// file is read through readOwn, so a symbolic link, a file another user owns or one its group or
// other users may write counts as untrusted, then parsed as the connector parses it.
func (u *Updater) policy() (*policy.Policy, error) {
	b, err := readOwn(u.Policy)
	if errors.Is(err, fs.ErrNotExist) {
		return policy.Defaults(), nil
	}
	if err != nil {
		return nil, err
	}
	return policy.Parse(b)
}

// checkCopy verifies the root-only copy against the manifest's artifact.
func checkCopy(path string, a release.Artifact) error {
	f, err := os.Open(path) //nolint:gosec // G304: the updater's own staging directory
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := a.Check(f); err != nil {
		return fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return nil
}

// full reports whether v is a full semantic version without a "v", as manifests write them.
func full(v string) bool {
	return semver.Canonical("v"+v) == "v"+v
}

// strictJSON decodes JSON without unknown keys or trailing data.
func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
