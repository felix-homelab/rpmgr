// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/mod/semver"

	"github.com/felix-homelab/rpmgr/internal/units"
)

// Roles are the roles an installation record may name; the updater replaces the binary of every
// one of them (D158).
var Roles = []string{"controller", "gateway", "connector", "all-in-one"}

// Installed is what an installer records for the updater (docs/10-operations.md, "Who installs the
// updater"): `rpmgr setup` and both install scripts, through `rpmgr updater install`.
type Installed struct {
	// Install is the installation: its method, the binary's path, the variant, and the roles it
	// adds to those recorded.
	Install
	// Seq and Floor are the seq of the release's verified manifest and the release's version, which
	// initialise or raise the state. With Seq 0, as for `rpmgr setup`, which knows no manifest,
	// Floor is the binary's own version: it initialises a missing state with seq 0, which takes no
	// manifest below the floor (release.State.Accept), and leaves an existing one as it is; a
	// version that is no release (a development build) leaves the state missing.
	Seq   uint64
	Floor string
}

// Record writes the installation record and the state into the updater's directory dir, which it
// creates as a directory of mode 0700 that only the updater's user, root, owns. The record keeps
// the variant it names, refusing another one, and the roles it names, the single role of v0.1.0
// included, and adds the new roles. The state is initialised from Seq and Floor, or raised to
// them: neither is ever lowered, and a version rolled back stays recorded. It returns the record
// and the state as written; the state is the zero State when there is none.
func Record(dir string, in Installed) (Install, State, error) {
	if err := ownDir(dir); err != nil {
		return Install{}, State{}, err
	}
	// The state is read and checked first, so that a refusal writes no file.
	st, write, err := raise(dir, in.Seq, in.Floor)
	if err != nil {
		return Install{}, State{}, err
	}
	rec, err := recordInstall(dir, in.Install)
	if err != nil {
		return Install{}, State{}, err
	}
	if write {
		err = WriteState(dir, st)
	}
	return rec, st, err
}

func recordInstall(dir string, in Install) (Install, error) {
	if !filepath.IsAbs(in.Path) || filepath.Clean(in.Path) != in.Path {
		return Install{}, fmt.Errorf("update: the binary path %q is no clean absolute path", in.Path)
	}
	if in.Variant != "full" && in.Variant != "connector" {
		return Install{}, fmt.Errorf("update: no variant %q: full or connector", in.Variant)
	}
	roles := in.roles()
	old, err := ReadInstall(dir)
	switch {
	case err == nil:
		if old.Variant != "" && old.Variant != in.Variant {
			return Install{}, fmt.Errorf("update: %s records the %s build, not the %s build; remove rpmgr first to change it",
				installFile, old.Variant, in.Variant)
		}
		if in.Method == "" {
			in.Method = old.Method
		}
		roles = append(roles, old.roles()...)
	case !errors.Is(err, fs.ErrNotExist):
		return Install{}, err
	}
	if in.Method == "" {
		return Install{}, errors.New("update: the installation names no method")
	}
	for _, r := range roles {
		if !slices.Contains(Roles, r) {
			return Install{}, fmt.Errorf("update: no role %q", r)
		}
	}
	slices.Sort(roles)
	rec := Install{Method: in.Method, Path: in.Path, Variant: in.Variant, Roles: slices.Compact(roles)}
	b, err := json.Marshal(rec)
	if err != nil {
		return Install{}, err
	}
	return rec, writeAtomic(dir, installFile, b, 0o600)
}

// raise returns the state raised to seq and floor, and whether it changed and must be written.
func raise(dir string, seq uint64, floor string) (State, bool, error) {
	old, err := ReadState(dir)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// A state that cannot be read may hide a higher seq: it is never replaced silently.
		return State{}, false, fmt.Errorf("%w; remove it to initialise the state from this release", err)
	}
	if seq == 0 {
		if exists || !full(floor) {
			return old, false, nil
		}
		return State{Floor: floor}, true, nil
	}
	if !full(floor) {
		return State{}, false, fmt.Errorf("update: the floor %q is no full semantic version", floor)
	}
	if !exists {
		return State{Seq: seq, Floor: floor}, true, nil
	}
	st := old
	st.Seq = max(st.Seq, seq)
	if semver.Compare("v"+floor, "v"+st.Floor) > 0 {
		st.Floor = floor
	}
	return st, st.Seq != old.Seq || st.Floor != old.Floor, nil
}

// ownDir creates the updater's directory, or checks the one there: a directory, not a symbolic
// link, owned by the updater's user. A wider mode is narrowed to 0700.
func ownDir(dir string) error {
	if err := mkdirMode(filepath.Dir(dir), 0o755); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("update: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if !fi.IsDir() || !ownedByMe(fi) {
		return fmt.Errorf("update: %s must be a directory that only the updater's user owns", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		return os.Chmod(dir, 0o700) //nolint:gosec // G302: a directory, 0700
	}
	return nil
}

// WriteUnits writes the updater's pair of units, rpmgr-update.path and rpmgr-update.service, into
// the unit directory dir, with bin, the path install.json records, in ExecStart. It returns the
// files it wrote.
func WriteUnits(dir, bin string) ([]string, error) {
	b, err := units.RenderUpdater(bin)
	if err != nil {
		return nil, err
	}
	if err := mkdirMode(dir, 0o755); err != nil { // minimal systems may lack it
		return nil, fmt.Errorf("update: %w", err)
	}
	// Each unit starts at the comment line that names its file, which stays in it.
	const header = "# /etc/systemd/system/"
	var names []string
	files := map[string][]byte{}
	for line := range bytes.Lines(b) {
		if name, ok := bytes.CutPrefix(line, []byte(header)); ok {
			names = append(names, string(bytes.TrimSpace(name)))
		} else if len(names) == 0 {
			return nil, errors.New("update: the updater units do not name their files")
		}
		files[names[len(names)-1]] = append(files[names[len(names)-1]], line...)
	}
	var written []string
	for _, name := range names {
		if filepath.Base(name) != name {
			return written, fmt.Errorf("update: the unit file %q", name)
		}
		if err := writeAtomic(dir, name, bytes.TrimSuffix(files[name], []byte("\n")), 0o644); err != nil {
			return written, err
		}
		written = append(written, filepath.Join(dir, name))
	}
	return written, nil
}

// mkdirMode creates dir and its missing parents with mode perm whatever the umask, which an
// install script sets to 077; a directory that exists keeps its mode.
func mkdirMode(dir string, perm os.FileMode) error {
	if fi, err := os.Stat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s exists and is no directory", dir)
		}
		return nil
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := mkdirMode(parent, perm); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, perm); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return os.Chmod(dir, perm)
}
