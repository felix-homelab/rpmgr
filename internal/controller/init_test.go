// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// host is a controller host in a temporary directory: the boot file names a database and, for
// the file source, a KEK inside it.
type host struct {
	dir, cfg, db, kek, credstore string
}

func newHost(t *testing.T) host {
	t.Helper()
	d := t.TempDir()
	return host{dir: d, cfg: filepath.Join(d, "controller.yaml"), db: filepath.Join(d, "lib", "controller.db"),
		kek: filepath.Join(d, "kek"), credstore: filepath.Join(d, "credstore")}
}

func (h host) writeBoot(t *testing.T, kek string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(h.db), 0o750); err != nil {
		t.Fatal(err)
	}
	boot := "version: 1\npublic_url: https://panel.example.com\ndatabase: {dsn: " + h.db + "}\n" + kek
	if err := os.WriteFile(h.cfg, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (h host) fileKEK() string { return "kek: {source: file, path: " + h.kek + "}\n" }

func (h host) opts() controller.InitOptions {
	return controller.InitOptions{ConfigPath: h.cfg, CredentialsDir: h.credstore,
		Getenv: func(string) string { return "" },
		Encrypt: func(context.Context, string, string, []byte) error {
			return errors.New("systemd-creds is not used in this test")
		}}
}

// check opens the initialised database and verifies what init created: the instance, a CA that
// opens with kek, an audit chain with the grant, the init and the first-user link, and the link.
func (h host) check(t *testing.T, kek secret.KEK, r controller.InitResult) {
	t.Helper()
	ctx := context.Background()
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sys := storetest.SystemCtx(t)
	inst := db.Client().Instance.GetX(sys, 1)
	if inst.TrustDomain != r.TrustDomain || !pki.ValidTrustDomain(r.TrustDomain) {
		t.Errorf("trust domain %s, reported %s", inst.TrustDomain, r.TrustDomain)
	}
	s, err := secret.NewSealer(kek)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadCA(sys, db, s, time.Now)
	if err != nil {
		t.Fatalf("the CA does not open with the KEK: %v", err)
	}
	if ca.TrustDomain() != r.TrustDomain || pki.RootPin(ca.Root()) != r.RootPin {
		t.Error("the reported pin or trust domain is not the CA's")
	}
	head, err := audit.Verify(sys, db, "")
	if err != nil || head.Seq != 3 {
		t.Errorf("instance audit chain: %d entries, %v; want the grant, the init and the first-user link", head.Seq, err)
	}
	if !strings.HasPrefix(r.FirstUserLink, "https://panel.example.com/setup#rpmgr_prs_") {
		t.Errorf("the first-user link %q", r.FirstUserLink)
	}
}

func TestInit_FileKEK(t *testing.T) {
	h := newHost(t)
	o := h.opts()
	o.PublicURL = "https://panel.example.com"
	h.writeBoot(t, h.fileKEK())
	r, err := controller.Init(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(h.kek)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("KEK file: %v, %v; want mode 0600", st, err)
	}
	kek, err := secret.LoadKEKFile(h.kek)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.KEK, "new file") {
		t.Errorf("reported KEK %q", r.KEK)
	}
	h.check(t, kek, r)

	before, _ := os.ReadFile(h.kek)
	boot, _ := os.ReadFile(h.cfg)
	if _, err := controller.Init(context.Background(), o); !errors.Is(err, controller.ErrInitialised) {
		t.Fatalf("second init: %v, want ErrInitialised", err)
	}
	after, _ := os.ReadFile(h.kek)
	boot2, _ := os.ReadFile(h.cfg)
	if !bytes.Equal(before, after) || !bytes.Equal(boot, boot2) {
		t.Error("a second init changed the KEK or the boot file")
	}
}

// TestInit_WritesBootFile: without a boot file, init writes one from the flags; with one, a
// different --public-url is refused.
func TestInit_WritesBootFile(t *testing.T) {
	h := newHost(t)
	o := h.opts()
	o.PublicURL, o.KEKSource, o.KEKPath = "https://panel.example.com", config.KEKFile, h.kek
	o.ConfigPath = filepath.Join(h.dir, "new.yaml")
	// The written file names the default database in /var/lib/rpmgr. Init must then fail, because
	// the directory does not exist; the file is what this test checks.
	if _, err := os.Stat("/var/lib/rpmgr"); err == nil {
		t.Skip("/var/lib/rpmgr exists on this host")
	}
	if _, err := controller.Init(context.Background(), o); err == nil {
		t.Fatal("init used /var/lib/rpmgr")
	}
	var c config.Controller
	if err := config.Load(o.ConfigPath, &c); err != nil {
		t.Fatalf("written boot file: %v", err)
	}
	if c.PublicURL != o.PublicURL || c.KEK.Source != config.KEKFile || c.KEK.Path != h.kek {
		t.Errorf("written boot file: %+v", c)
	}
	if st, err := os.Stat(o.ConfigPath); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("boot file mode: %v, %v", st, err)
	}
	o.PublicURL = "https://other.example.com"
	if _, err := controller.Init(context.Background(), o); err == nil || !strings.Contains(err.Error(), "public_url") {
		t.Errorf("another --public-url than the boot file's: %v", err)
	}
}

// TestInit_KEKSourceBySystemdVersion: without --kek-source, a new boot file takes the systemd
// credential from systemd 250, which has encrypted credentials, and a KEK file below it or
// without systemd (docs/10-operations.md, "Supported platforms").
func TestInit_KEKSourceBySystemdVersion(t *testing.T) {
	if _, err := os.Stat("/var/lib/rpmgr"); err == nil {
		t.Skip("/var/lib/rpmgr exists on this host")
	}
	for version, want := range map[int]string{0: config.KEKFile, 249: config.KEKFile, 250: config.KEKSystemdCredential, 257: config.KEKSystemdCredential} {
		h := newHost(t)
		o := h.opts()
		o.PublicURL, o.ConfigPath = "https://panel.example.com", filepath.Join(h.dir, "new.yaml")
		o.SystemdVersion = func() int { return version }
		_, _ = controller.Init(context.Background(), o) // fails on the default paths; the boot file is what counts
		var c config.Controller
		if err := config.Load(o.ConfigPath, &c); err != nil {
			t.Fatalf("systemd %d: %v", version, err)
		}
		if c.KEK.Source != want {
			t.Errorf("systemd %d: KEK source %s, want %s", version, c.KEK.Source, want)
		}
	}
}

func TestInit_Refusals(t *testing.T) {
	cases := map[string]func(t *testing.T, h host, o *controller.InitOptions){
		"no boot file and no URL": func(_ *testing.T, h host, o *controller.InitOptions) {
			o.ConfigPath = filepath.Join(h.dir, "missing.yaml")
		},
		"invalid URL": func(_ *testing.T, h host, o *controller.InitOptions) {
			o.ConfigPath, o.PublicURL = filepath.Join(h.dir, "missing.yaml"), "http://panel.example.com"
		},
		"unknown KEK source": func(_ *testing.T, h host, o *controller.InitOptions) {
			o.ConfigPath, o.PublicURL, o.KEKSource = filepath.Join(h.dir, "missing.yaml"), "https://p.example", "env"
		},
		"boot file with an unknown key": func(t *testing.T, h host, _ *controller.InitOptions) {
			h.writeBoot(t, h.fileKEK()+"kek_source: file\n")
		},
		"KEK file open to other users": func(t *testing.T, h host, _ *controller.InitOptions) {
			h.writeBoot(t, h.fileKEK())
			if err := os.WriteFile(h.kek, []byte(strings.Repeat("A", 43)+"=\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"KEK file that is no KEK": func(t *testing.T, h host, _ *controller.InitOptions) {
			h.writeBoot(t, h.fileKEK())
			if err := os.WriteFile(h.kek, []byte("not base64\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"encrypted credential that is not loaded": func(t *testing.T, h host, _ *controller.InitOptions) {
			h.writeBoot(t, "")
			if err := os.MkdirAll(h.credstore, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(h.credstore, "rpmgr-kek"), []byte("sealed"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"systemd-creds fails": func(t *testing.T, h host, _ *controller.InitOptions) {
			h.writeBoot(t, "")
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHost(t)
			o := h.opts()
			setup(t, h, &o)
			kekBefore, _ := os.ReadFile(h.kek)
			_, err := controller.Init(context.Background(), o)
			if err == nil {
				t.Fatal("init succeeded")
			}
			t.Logf("refused: %v", err)
			if kekAfter, _ := os.ReadFile(h.kek); !bytes.Equal(kekBefore, kekAfter) {
				t.Error("a refused init changed the KEK file")
			}
			if _, err := os.Stat(h.db); err == nil {
				db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = db.Close() }()
				if n, _ := db.Client().Instance.Query().Count(storetest.SystemCtx(t)); n != 0 {
					t.Error("a refused init initialised the database")
				}
			}
		})
	}
}

// TestInit_ExistingKEKIsUsed: init reads a KEK that already exists instead of replacing it, so it
// can run again after a failure.
func TestInit_ExistingKEKIsUsed(t *testing.T) {
	h := newHost(t)
	h.writeBoot(t, h.fileKEK())
	enc := []byte("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n")
	if err := os.WriteFile(h.kek, enc, 0o600); err != nil {
		t.Fatal(err)
	}
	kek, err := secret.LoadKEKFile(h.kek)
	if err != nil {
		t.Fatal(err)
	}
	r, err := controller.Init(context.Background(), h.opts())
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(h.kek); !bytes.Equal(got, enc) || !strings.HasPrefix(r.KEK, "existing file") {
		t.Errorf("the existing KEK was replaced, or reported as %q", r.KEK)
	}
	h.check(t, kek, r)
}

// TestInit_SystemdCredential: a new KEK is encrypted into the credential store with systemd-creds;
// a credential that systemd loaded is used as it is.
func TestInit_SystemdCredential(t *testing.T) {
	h := newHost(t)
	h.writeBoot(t, "")
	o := h.opts()
	var gotName, gotPath string
	var plain []byte
	o.Encrypt = func(_ context.Context, name, path string, b []byte) error {
		gotName, gotPath, plain = name, path, bytes.Clone(b)
		return os.WriteFile(path, []byte("sealed by systemd"), 0o600)
	}
	r, err := controller.Init(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if gotName != "rpmgr-kek" || gotPath != filepath.Join(h.credstore, "rpmgr-kek") {
		t.Errorf("systemd-creds encrypt --name=%s - %s", gotName, gotPath)
	}
	loaded := filepath.Join(h.dir, "loaded")
	if err := os.MkdirAll(loaded, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(loaded, "rpmgr-kek"), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	kek, err := secret.LoadSystemdCredential("rpmgr-kek", func(k string) string {
		return map[string]string{"CREDENTIALS_DIRECTORY": loaded}[k]
	})
	if err != nil {
		t.Fatalf("the encrypted plaintext is not a KEK: %v", err)
	}
	h.check(t, kek, r)

	// Under systemd-run with the credential loaded, a fresh database initialises with it.
	h2 := newHost(t)
	h2.writeBoot(t, "")
	o2 := h2.opts()
	o2.Getenv = func(k string) string { return map[string]string{"CREDENTIALS_DIRECTORY": loaded}[k] }
	r2, err := controller.Init(context.Background(), o2)
	if err != nil || !strings.HasPrefix(r2.KEK, "loaded systemd credential") {
		t.Fatalf("init with a loaded credential: %+v, %v", r2, err)
	}
	h2.check(t, kek, r2)
}

func TestInit_RunningControllerRefused(t *testing.T) {
	h := newHost(t)
	h.writeBoot(t, h.fileKEK())
	running, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = running.Close() }()
	if _, err := controller.Init(context.Background(), h.opts()); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("init next to a running controller: %v, want ErrLocked", err)
	}
	if _, err := os.Stat(h.kek); !errors.Is(err, os.ErrNotExist) {
		t.Error("init created a KEK although the database was in use")
	}
}

// TestInit_PasswordHashProfile: a host with less than 1 GiB of memory gets the low-memory
// password-hash profile; 1 GiB or more, or an unknown amount, keeps the default.
func TestInit_PasswordHashProfile(t *testing.T) {
	for _, c := range []struct {
		mem   uint64
		known bool
		want  rpmgrv1.PasswordHashProfile
	}{
		{1<<30 - 1, true, rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_LOW_MEMORY},
		{512 << 20, true, rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_LOW_MEMORY},
		{1 << 30, true, rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_DEFAULT},
		{0, false, rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_DEFAULT},
	} {
		h := newHost(t)
		h.writeBoot(t, h.fileKEK())
		o := h.opts()
		o.Memory = func() (uint64, bool) { return c.mem, c.known }
		if _, err := controller.Init(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		inst, _, err := settings.Instance(storetest.SystemCtx(t), db.Client())
		_ = db.Close()
		if err != nil || inst.GetPasswordHashProfile() != c.want {
			t.Errorf("%d bytes (%v): %v %v", c.mem, c.known, inst.GetPasswordHashProfile(), err)
		}
	}
}
