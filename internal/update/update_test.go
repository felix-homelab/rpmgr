// SPDX-License-Identifier: Apache-2.0

//go:build linux

package update_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
	"github.com/felix-homelab/rpmgr/internal/update"
)

var (
	testRoot    = releasetest.Key("update root")
	testSigning = releasetest.Key("update signing")
	now         = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
)

// host is a host's updater with its directories: the agent's staging directory, the updater's
// state directory and the policy file.
type host struct {
	t *testing.T
	u *update.Updater
}

// hostOpts describe a host: its installation record, state and policy.
type hostOpts struct {
	install string // install.json; default a script install of a full connector
	state   string // state.json; default seq 5, floor 1.0.0
	policy  string // policy.yaml; "" means no file (the defaults); "-" too
}

func newHost(t *testing.T, o hostOpts) *host {
	t.Helper()
	base := t.TempDir()
	staged, state := filepath.Join(base, "update"), filepath.Join(base, "rpmgr-update")
	mustMkdir(t, staged, 0o750)
	mustMkdir(t, state, 0o700)
	if o.install == "" {
		o.install = `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","roles":["connector"]}`
	}
	if o.state == "" {
		o.state = `{"seq":5,"floor":"1.0.0"}`
	}
	mustWrite(t, filepath.Join(state, "install.json"), o.install, 0o600)
	mustWrite(t, filepath.Join(state, "state.json"), o.state, 0o600)
	pol := filepath.Join(base, "policy.yaml")
	if o.policy != "" && o.policy != "-" {
		mustWrite(t, pol, o.policy, 0o644)
	}
	root, err := release.ParsePublicKey(testRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	return &host{t: t, u: &update.Updater{Staged: staged, State: state, Policy: pol, Roots: []release.PublicKey{root},
		Now: func() time.Time { return now }, OS: "linux", Arch: "amd64"}}
}

// rel is a release to stage.
type rel struct {
	version, floor, channel string
	seq                     uint64
	variants                []string // artifacts for linux/amd64; default full and connector
}

// binary is the content of an artifact.
func binary(version, variant string) []byte { return []byte("rpmgr " + version + " " + variant) }

// stage writes a signed release into the agent's staging directory, as the agent does, the
// manifest last, and returns its manifest.
func (h *host) stage(r rel) release.Manifest {
	h.t.Helper()
	if r.floor == "" {
		r.floor = "1.0.0"
	}
	if r.channel == "" {
		r.channel = release.Stable
	}
	if r.variants == nil {
		r.variants = []string{"full", "connector"}
	}
	m := release.Manifest{Seq: r.seq, Version: r.version, Floor: r.floor, Channel: r.channel, IssuedAt: now}
	for _, v := range r.variants {
		a := release.Artifact{OS: "linux", Arch: "amd64", Variant: v}
		body := binary(r.version, v)
		sum := sha256.Sum256(body)
		a.Size, a.SHA256 = int64(len(body)), hex.EncodeToString(sum[:])
		m.Artifacts = append(m.Artifacts, a)
		mustWrite(h.t, filepath.Join(h.u.Staged, release.ArtifactName(r.version, a)), string(body), 0o640)
	}
	man, err := json.Marshal(m)
	if err != nil {
		h.t.Fatal(err)
	}
	st := []byte(`{"statement":1,"signer":"` + testSigning.Public() + `","not_before":"2026-10-01T00:00:00Z","not_after":"2027-10-01T00:00:00Z"}`)
	mustWrite(h.t, filepath.Join(h.u.Staged, "signing-key.json"), string(st), 0o640)
	mustWrite(h.t, filepath.Join(h.u.Staged, "signing-key.json.minisig"), string(testRoot.Sign(st)), 0o640)
	mustWrite(h.t, filepath.Join(h.u.Staged, "manifest.json.minisig"), string(testSigning.Sign(man)), 0o640)
	mustWrite(h.t, filepath.Join(h.u.Staged, "manifest.json"), string(man), 0o640)
	return m
}

// artifact is the path of a staged artifact.
func (h *host) artifact(version, variant string) string {
	name := "rpmgr-" + version + "-linux-amd64"
	if variant != "full" {
		name += "-" + variant
	}
	return filepath.Join(h.u.Staged, name)
}

// refused runs Stage and requires the error it wraps, and that nothing reached the root-only
// staging directory.
func (h *host) refused(want error) {
	h.t.Helper()
	s, err := h.u.Stage()
	if !errors.Is(err, want) {
		h.t.Fatalf("Stage = %v, %v; want %v", s, err, want)
	}
	entries, _ := os.ReadDir(filepath.Join(h.u.State, "staging"))
	if len(entries) > 0 {
		h.t.Errorf("a refused release left %d files in the root-only staging directory", len(entries))
	}
}

func (h *host) staged() *update.Staged {
	h.t.Helper()
	s, err := h.u.Stage()
	if err != nil {
		h.t.Fatalf("Stage: %v", err)
	}
	return s
}

func TestStage_VerifiesTheCopy(t *testing.T) {
	h := newHost(t, hostOpts{})
	h.stage(rel{version: "1.2.0", seq: 6})
	s := h.staged()
	if got, err := os.ReadFile(s.Path); err != nil || !bytes.Equal(got, binary("1.2.0", "full")) {
		t.Fatalf("copy %s = %q, %v", s.Path, got, err)
	}
	if !strings.HasPrefix(s.Path, filepath.Join(h.u.State, "staging")+"/") {
		t.Errorf("the copy %s is outside the root-only staging directory", s.Path)
	}
	if fi, err := os.Stat(s.Path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("copy mode %v, %v; want 0600", fi.Mode(), err)
	}
	if s.Next != (update.State{Seq: 6, Floor: "1.0.0"}) {
		t.Errorf("next state %+v", s.Next)
	}
	if st, err := update.ReadState(h.u.State); err != nil || st.Seq != 5 {
		t.Errorf("Stage persisted state %+v, %v; it must not before the install", st, err)
	}
}

// TestOTA_ReplayedOldManifestRejected (seq clause; docs/12): a genuinely signed manifest with a
// lower seq is refused; the floor is lowered only by a higher seq. The clause that the service
// user cannot write the binary or the updater's state runs in test/ota (slice 2.11).
func TestOTA_ReplayedOldManifestRejected(t *testing.T) {
	t.Run("lower seq", func(t *testing.T) {
		h := newHost(t, hostOpts{state: `{"seq":9,"floor":"1.3.0"}`})
		h.stage(rel{version: "1.4.0", seq: 8})
		h.refused(update.ErrRefused)
	})
	t.Run("same seq below the floor", func(t *testing.T) {
		h := newHost(t, hostOpts{state: `{"seq":9,"floor":"1.3.0"}`})
		h.stage(rel{version: "1.2.0", seq: 9})
		h.refused(update.ErrRefused)
	})
	t.Run("higher seq lowers the floor", func(t *testing.T) {
		h := newHost(t, hostOpts{state: `{"seq":9,"floor":"1.3.0"}`})
		h.stage(rel{version: "1.2.0", floor: "1.1.0", seq: 10})
		if s := h.staged(); s.Next != (update.State{Seq: 10, Floor: "1.1.0"}) {
			t.Errorf("next state %+v; want seq 10, floor 1.1.0", s.Next)
		}
	})
	t.Run("forged manifest", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		man := filepath.Join(h.u.Staged, "manifest.json")
		b, _ := os.ReadFile(man)
		mustWrite(t, man, strings.Replace(string(b), `"seq":6`, `"seq":60`, 1), 0o640)
		h.refused(update.ErrRefused)
	})
}

// TestOTA_StagedFileSwapTOCTOU (as root; docs/12): the service user replaces the staged artifact
// or plants a symbolic link while the updater runs. The updater reads through the file it
// opened, verifies its root-only copy and returns only that copy, or aborts.
func TestOTA_StagedFileSwapTOCTOU(t *testing.T) {
	t.Run("file renamed over the staged one after the open", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		evil := filepath.Join(h.u.Staged, "evil")
		mustWrite(t, evil, "rpmgr 1.2.0 evil", 0o640)
		update.OnOpen(t, func(name string) {
			if strings.HasPrefix(name, "rpmgr-") {
				if err := os.Rename(evil, h.artifact("1.2.0", "full")); err != nil {
					t.Error(err)
				}
			}
		})
		s := h.staged()
		if got, _ := os.ReadFile(s.Path); !bytes.Equal(got, binary("1.2.0", "full")) {
			t.Fatalf("the verified copy holds %q", got)
		}
	})
	t.Run("symbolic link planted after the open", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		// A file of the same size that a reader following the path would copy instead.
		evil := filepath.Join(t.TempDir(), "evil")
		mustWrite(t, evil, "rpmgr 1.2.0 EVIL", 0o644)
		update.OnOpen(t, func(name string) {
			if strings.HasPrefix(name, "rpmgr-") {
				p := h.artifact("1.2.0", "full")
				_ = os.Remove(p)
				if err := os.Symlink(evil, p); err != nil {
					t.Error(err)
				}
			}
		})
		s := h.staged()
		if got, _ := os.ReadFile(s.Path); !bytes.Equal(got, binary("1.2.0", "full")) {
			t.Fatalf("the verified copy holds %q", got)
		}
	})
	t.Run("content changed in place during the copy", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		update.OnOpen(t, func(name string) {
			if strings.HasPrefix(name, "rpmgr-") {
				mustWrite(t, h.artifact("1.2.0", "full"), "rpmgr 1.2.0 FULL", 0o640) // same size, other bytes
			}
		})
		h.refused(update.ErrRefused)
	})
	t.Run("artifact changed after it was copied", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		// The hash is taken from the copy: a staged file changed now cannot fail it, nor pass.
		update.AfterCopy(t, func() { mustWrite(t, h.artifact("1.2.0", "full"), "rpmgr 1.2.0 EVIL", 0o640) })
		s := h.staged()
		if got, _ := os.ReadFile(s.Path); !bytes.Equal(got, binary("1.2.0", "full")) {
			t.Fatalf("the verified copy holds %q", got)
		}
	})
	t.Run("manifest swapped after it was read", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		update.OnOpen(t, func(name string) {
			if strings.HasPrefix(name, "rpmgr-") {
				mustWrite(t, filepath.Join(h.u.Staged, "manifest.json"), "{}", 0o640)
			}
		})
		if s := h.staged(); s.Manifest.Version != "1.2.0" {
			t.Errorf("staged %s", s.Manifest.Version)
		}
	})
}

// TestOTA_HostileStagingRefused (docs/12): a symbolic-linked staging directory, a FIFO, a device
// file, or a file larger than the manifest's size or the updater's cap is refused without hanging
// or filling the disk.
func TestOTA_HostileStagingRefused(t *testing.T) {
	t.Run("symbolic-linked staging directory", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		link := h.u.Staged + "-link"
		if err := os.Symlink(h.u.Staged, link); err != nil {
			t.Fatal(err)
		}
		h.u.Staged = link
		h.refused(update.ErrHostile)
	})
	for _, name := range []string{"rpmgr-1.2.0-linux-amd64", "manifest.json", "signing-key.json.minisig"} {
		t.Run("symbolic link as "+name, func(t *testing.T) {
			h := newHost(t, hostOpts{})
			h.stage(rel{version: "1.2.0", seq: 6})
			p := filepath.Join(h.u.Staged, name)
			real := filepath.Join(t.TempDir(), "real")
			b, _ := os.ReadFile(p)
			mustWrite(t, real, string(b), 0o644)
			_ = os.Remove(p)
			if err := os.Symlink(real, p); err != nil {
				t.Fatal(err)
			}
			h.refused(update.ErrHostile)
		})
	}
	t.Run("FIFO", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		p := h.artifact("1.2.0", "full")
		_ = os.Remove(p)
		if err := syscall.Mkfifo(p, 0o640); err != nil {
			t.Fatal(err)
		}
		var err error
		within(t, func() { _, err = h.u.Stage() })
		if !errors.Is(err, update.ErrHostile) {
			t.Fatalf("Stage with a FIFO: %v", err)
		}
	})
	t.Run("device", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("making a device file needs root")
		}
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		p := h.artifact("1.2.0", "full")
		_ = os.Remove(p)
		if err := syscall.Mknod(p, syscall.S_IFCHR|0o640, 1<<8|5); err != nil { // /dev/zero's numbers
			t.Fatal(err)
		}
		var err error
		within(t, func() { _, err = h.u.Stage() })
		if !errors.Is(err, update.ErrHostile) {
			t.Fatalf("Stage with a device: %v", err)
		}
	})
	t.Run("larger than the manifest says", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		mustWrite(t, h.artifact("1.2.0", "full"), string(binary("1.2.0", "full"))+strings.Repeat("x", 1<<20), 0o640)
		read := false
		update.OnOpen(t, func(name string) { read = read || strings.HasPrefix(name, "rpmgr-") })
		h.refused(update.ErrHostile)
		if read {
			t.Error("a static file above the manifest's size was opened for reading; its size alone must refuse it")
		}
	})
	t.Run("signed file growing while read", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		update.OnOpen(t, func(name string) {
			if name == "manifest.json" {
				f, err := os.OpenFile(filepath.Join(h.u.Staged, name), os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = f.WriteString(strings.Repeat(" ", 2<<20))
				_ = f.Close()
			}
		})
		h.refused(update.ErrHostile)
	})
	t.Run("growing while copied", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		update.OnOpen(t, func(name string) {
			if strings.HasPrefix(name, "rpmgr-") {
				f, err := os.OpenFile(h.artifact("1.2.0", "full"), os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = f.WriteString(strings.Repeat("x", 4096))
				_ = f.Close()
			}
		})
		h.refused(update.ErrHostile)
	})
	t.Run("manifest above the cap", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		m := h.stage(rel{version: "1.2.0", seq: 6})
		m.Artifacts[0].Size = update.MaxArtifact + 1
		man, _ := json.Marshal(m)
		mustWrite(t, filepath.Join(h.u.Staged, "manifest.json.minisig"), string(testSigning.Sign(man)), 0o640)
		mustWrite(t, filepath.Join(h.u.Staged, "manifest.json"), string(man), 0o640)
		h.refused(update.ErrHostile)
	})
	t.Run("oversized signed file", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		mustWrite(t, filepath.Join(h.u.Staged, "manifest.json"), strings.Repeat(" ", 2<<20), 0o640)
		h.refused(update.ErrHostile)
	})
	t.Run("staged file missing", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		_ = os.Remove(h.artifact("1.2.0", "full"))
		if _, err := h.u.Stage(); err == nil {
			t.Fatal("a release without its artifact was staged")
		}
	})
}

// TestOTA_ChannelAndVariantEnforced (docs/12): a stable host refuses a pre-release; a connector
// install refuses a full artifact and a full install a connector artifact, even when both are
// genuinely signed.
func TestOTA_ChannelAndVariantEnforced(t *testing.T) {
	t.Run("pre-release on a stable host", func(t *testing.T) {
		h := newHost(t, hostOpts{policy: "version: 1\nauto_update: auto\nupdate_channel: stable\n"})
		h.stage(rel{version: "1.2.0-rc.1", seq: 6, channel: release.Prerelease})
		h.refused(update.ErrRefused)
	})
	t.Run("pre-release on a pre-release host", func(t *testing.T) {
		h := newHost(t, hostOpts{policy: "version: 1\nauto_update: auto\nupdate_channel: prerelease\n"})
		h.stage(rel{version: "1.2.0-rc.1", seq: 6, channel: release.Prerelease})
		h.staged()
	})
	t.Run("connector install takes the connector artifact", func(t *testing.T) {
		h := newHost(t, hostOpts{install: `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"connector","roles":["connector"]}`})
		h.stage(rel{version: "1.2.0", seq: 6})
		if got, _ := os.ReadFile(h.staged().Path); !bytes.Equal(got, binary("1.2.0", "connector")) {
			t.Fatalf("staged %q", got)
		}
	})
	t.Run("connector install, release without a connector artifact", func(t *testing.T) {
		h := newHost(t, hostOpts{install: `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"connector","roles":["connector"]}`})
		h.stage(rel{version: "1.2.0", seq: 6, variants: []string{"full"}})
		h.refused(update.ErrRefused)
	})
	t.Run("connector install, full build staged under the connector name", func(t *testing.T) {
		h := newHost(t, hostOpts{install: `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"connector","roles":["connector"]}`})
		h.stage(rel{version: "1.2.0", seq: 6})
		mustWrite(t, h.artifact("1.2.0", "connector"), string(binary("1.2.0", "full")), 0o640)
		h.refused(update.ErrRefused)
	})
	t.Run("full install, connector build staged under the full name", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.stage(rel{version: "1.2.0", seq: 6})
		mustWrite(t, h.artifact("1.2.0", "full"), string(binary("1.2.0", "connector")), 0o640)
		h.refused(update.ErrHostile) // longer than the full artifact: refused before it is copied
	})
	t.Run("another architecture", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		h.u.Arch = "riscv64"
		h.stage(rel{version: "1.2.0", seq: 6})
		h.refused(update.ErrRefused)
	})
}

func TestStage_Policy(t *testing.T) {
	for name, tc := range map[string]struct {
		policy string
		mode   os.FileMode
		ok     bool
	}{
		"no file: the defaults":   {policy: "-", ok: true},
		"auto":                    {policy: "version: 1\nauto_update: auto\nupdate_channel: stable\n", mode: 0o644, ok: true},
		"notify":                  {policy: "version: 1\nauto_update: notify\nupdate_channel: stable\n", mode: 0o644},
		"off":                     {policy: "version: 1\nauto_update: off\nupdate_channel: stable\n", mode: 0o644},
		"does not parse":          {policy: "version: 1\nauto_update: [\n", mode: 0o644},
		"unknown key":             {policy: "version: 1\nauto_update: auto\nupdates: always\n", mode: 0o644},
		"writable by others":      {policy: "version: 1\nauto_update: auto\nupdate_channel: stable\n", mode: 0o666},
		"writable by the group":   {policy: "version: 1\nauto_update: auto\nupdate_channel: stable\n", mode: 0o664},
		"unknown update channel":  {policy: "version: 1\nauto_update: auto\nupdate_channel: nightly\n", mode: 0o644},
		"unknown auto_update key": {policy: "version: 1\nauto_update: sometimes\nupdate_channel: stable\n", mode: 0o644},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, hostOpts{policy: tc.policy})
			if tc.mode != 0 {
				if err := os.Chmod(h.u.Policy, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			h.stage(rel{version: "1.2.0", seq: 6})
			if tc.ok {
				h.staged()
				return
			}
			h.refused(update.ErrRefused)
		})
	}
}

func TestStage_Install(t *testing.T) {
	for name, tc := range map[string]struct {
		install string
		fails   bool  // Stage fails
		want    error // and wraps want, if set
	}{
		"several agent roles":       {install: `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","roles":["gateway","connector"]}`},
		"single role of v0.1.0":     {install: `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","role":"connector"}`},
		"controller host":           {install: `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","roles":["controller","connector"]}`, fails: true, want: update.ErrRefused},
		"all-in-one host of v0.1.0": {install: `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","role":"all-in-one"}`, fails: true, want: update.ErrRefused},
		"no variant":                {install: `{"method":"script","path":"/usr/local/bin/rpmgr","roles":["connector"]}`, fails: true},
		"unknown key":               {install: `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","roles":["connector"],"x":1}`, fails: true},
		"no role":                   {install: `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full"}`, fails: true},
		"not JSON":                  {install: `method=script`, fails: true},
		"two documents":             {install: `{"method":"script","path":"/p","variant":"full","roles":["connector"]}{}`, fails: true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, hostOpts{install: tc.install})
			h.stage(rel{version: "1.2.0", seq: 6})
			_, err := h.u.Stage()
			switch {
			case !tc.fails && err != nil:
				t.Fatalf("Stage: %v", err)
			case tc.fails && err == nil, tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("Stage: %v; want an error wrapping %v", err, tc.want)
			}
		})
	}
}

func TestStage_RootOnlyStagingDirectory(t *testing.T) {
	t.Run("copies of earlier runs removed", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		dir := filepath.Join(h.u.State, "staging")
		mustMkdir(t, dir, 0o700)
		mustWrite(t, filepath.Join(dir, ".copy-left"), "old", 0o600)
		mustWrite(t, filepath.Join(dir, "rpmgr-1.1.0-linux-amd64"), "old", 0o600)
		h.stage(rel{version: "1.2.0", seq: 6})
		s := h.staged()
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 || entries[0].Name() != filepath.Base(s.Path) {
			t.Errorf("staging holds %v; want only the new copy", entries)
		}
	})
	t.Run("open to others", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		mustMkdir(t, filepath.Join(h.u.State, "staging"), 0o755)
		if err := os.Chmod(filepath.Join(h.u.State, "staging"), 0o755); err != nil { //nolint:gosec // G302: the mode under test
			t.Fatal(err)
		}
		h.stage(rel{version: "1.2.0", seq: 6})
		if _, err := h.u.Stage(); !errors.Is(err, update.ErrHostile) {
			t.Fatalf("Stage with a staging directory of mode 0755: %v", err)
		}
	})
	t.Run("symbolic link", func(t *testing.T) {
		h := newHost(t, hostOpts{})
		if err := os.Symlink(t.TempDir(), filepath.Join(h.u.State, "staging")); err != nil {
			t.Fatal(err)
		}
		h.stage(rel{version: "1.2.0", seq: 6})
		if _, err := h.u.Stage(); !errors.Is(err, update.ErrHostile) {
			t.Fatalf("Stage with a symbolic-linked staging directory: %v", err)
		}
	})
}

// TestStage_OwnFilesNoSymlinks: install.json, state.json and the policy file are never read
// through a symbolic link, which another user could point at a file of their own.
func TestStage_OwnFilesNoSymlinks(t *testing.T) {
	for _, name := range []string{"install.json", "state.json", "policy"} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, hostOpts{policy: "version: 1\nauto_update: auto\nupdate_channel: stable\n"})
			p := filepath.Join(h.u.State, name)
			if name == "policy" {
				p = h.u.Policy
			}
			b, _ := os.ReadFile(p)
			real := filepath.Join(t.TempDir(), "real")
			mustWrite(t, real, string(b), 0o600)
			_ = os.Remove(p)
			if err := os.Symlink(real, p); err != nil {
				t.Fatal(err)
			}
			h.stage(rel{version: "1.2.0", seq: 6})
			if _, err := h.u.Stage(); err == nil {
				t.Fatalf("Stage read %s through a symbolic link", name)
			}
		})
	}
}

func TestStage_RolledBackVersion(t *testing.T) {
	const state = `{"seq":7,"floor":"1.1.0","failed":{"version":"1.2.0","seq":7}}`
	t.Run("same manifest again", func(t *testing.T) {
		h := newHost(t, hostOpts{state: state})
		h.stage(rel{version: "1.2.0", seq: 7})
		h.refused(update.ErrRefused)
	})
	t.Run("a newer manifest offers it again", func(t *testing.T) {
		h := newHost(t, hostOpts{state: state})
		h.stage(rel{version: "1.2.0", seq: 8})
		h.staged()
	})
	t.Run("another version", func(t *testing.T) {
		h := newHost(t, hostOpts{state: state})
		h.stage(rel{version: "1.2.1", seq: 7})
		h.staged()
	})
}

func TestReadState(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		mode os.FileMode
		ok   bool
	}{
		"valid":               {body: `{"seq":3,"floor":"1.0.0"}`, mode: 0o600, ok: true},
		"with a failed one":   {body: `{"seq":3,"floor":"1.0.0","failed":{"version":"1.1.0","seq":3}}`, mode: 0o600, ok: true},
		"not JSON":            {body: `seq=3`, mode: 0o600},
		"truncated":           {body: `{"seq":3,"fl`, mode: 0o600},
		"unknown key":         {body: `{"seq":3,"floor":"1.0.0","ceiling":"9.9.9"}`, mode: 0o600},
		"floor not a version": {body: `{"seq":3,"floor":"latest"}`, mode: 0o600},
		"floor with a v":      {body: `{"seq":3,"floor":"v1.0.0"}`, mode: 0o600},
		"no floor":            {body: `{"seq":3}`, mode: 0o600},
		"negative seq":        {body: `{"seq":-1,"floor":"1.0.0"}`, mode: 0o600},
		"bad failed version":  {body: `{"seq":3,"floor":"1.0.0","failed":{"version":"x","seq":3}}`, mode: 0o600},
		"writable by others":  {body: `{"seq":3,"floor":"1.0.0"}`, mode: 0o602},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, "state.json"), tc.body, tc.mode)
			st, err := update.ReadState(dir)
			if tc.ok != (err == nil) {
				t.Fatalf("ReadState = %+v, %v", st, err)
			}
		})
	}
	if _, err := update.ReadState(t.TempDir()); err == nil {
		t.Error("a missing state.json was read")
	}
}

func TestWriteState(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "state.json"), `{"seq":1,"floor":"1.0.0"}`, 0o600)
	want := update.State{Seq: 9, Floor: "1.3.0", Failed: &update.Failed{Version: "1.4.0", Seq: 9}}
	if err := update.WriteState(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := update.ReadState(dir)
	if err != nil || got.Seq != want.Seq || got.Floor != want.Floor || *got.Failed != *want.Failed {
		t.Fatalf("ReadState after WriteState = %+v, %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("%d files in the state directory; a temporary file was left", len(entries))
	}
	if fi, _ := os.Stat(filepath.Join(dir, "state.json")); fi.Mode().Perm() != 0o600 {
		t.Errorf("state.json mode %v", fi.Mode())
	}
	if err := update.WriteState(filepath.Join(dir, "missing"), want); err == nil {
		t.Error("WriteState into a missing directory succeeded")
	}
}

// within fails the test if f does not return within 5 s: the updater must never block on a
// FIFO or a device.
func within(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the updater blocked")
	}
}

func mustMkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(dir, mode); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil { //nolint:gosec // G703: paths under t.TempDir
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // WriteFile keeps an existing file's mode
		t.Fatal(err)
	}
}
