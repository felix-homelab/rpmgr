// SPDX-License-Identifier: Apache-2.0

// Package controller runs the controller role.
package controller

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"go.yaml.in/yaml/v3"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
)

// InitOptions are the inputs of `rpmgr controller init` (docs/16-cli.md).
type InitOptions struct {
	ConfigPath string // the boot file; written if it does not exist
	PublicURL  string // required unless the boot file exists; must match it if both are given
	KEKSource  string // for a new boot file: systemd-credential (default) or file
	KEKPath    string // for a new boot file with the file source; default /etc/rpmgr/kek
	// AllInOne reads and writes an all-in-one boot file (config.AllInOne) instead of a
	// controller's.
	AllInOne bool

	// Set by tests; the zero values are the real ones.
	CredentialsDir string                                                       // /etc/rpmgr/credstore
	Getenv         func(string) string                                          // os.Getenv
	Encrypt        func(ctx context.Context, name, path string, b []byte) error // systemd-creds encrypt
	Now            func() time.Time                                             // time.Now
	Memory         func() (uint64, bool)                                        // the host's memory in bytes, if known
}

// lowMemory is the host memory below which init picks the low-memory password-hash profile
// (docs/04-security.md, "Human authentication and sessions").
const lowMemory = 1 << 30

// InitResult is what init reports to the operator.
type InitResult struct {
	TrustDomain string
	RootPin     string
	Root        *x509.Certificate
	KEK         string // where the KEK is, and whether init created it
	// FirstUserLink is the one-time link that creates the first user.
	FirstUserLink string
}

// ErrInitialised is returned when the database already holds an installation.
var ErrInitialised = store.ErrInitialised

// Init initialises a controller (docs/10-operations.md, "Install"): the boot file, the KEK, the
// database and its migrations, and in one transaction the instance with its trust domain and
// epoch, the CA and its signing keys, and the audit entry. It never overwrites a boot file or a
// KEK: an existing file is read and used, so init can run again after a failure.
func Init(ctx context.Context, o InitOptions) (InitResult, error) {
	o.setDefaults()
	var cfg config.Controller
	if err := bootFile(o, &cfg); err != nil {
		return InitResult{}, err
	}
	// The database's directory must exist: the installer creates /var/lib/rpmgr with its owner.
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{Lock: true})
	if err != nil {
		return InitResult{}, err
	}
	defer func() { _ = db.Close() }()
	dir, err := migrations.Dir(db.Dialect)
	if err != nil {
		return InitResult{}, err
	}
	if _, err := store.Migrate(ctx, db, dir); err != nil {
		return InitResult{}, err
	}
	ctx, err = authz.System(ctx, "local-cli", "rpmgr controller init", audit.SystemScopes(db))
	if err != nil {
		return InitResult{}, err
	}
	done, err := db.ReadClient().Instance.Query().Exist(ctx)
	if err != nil {
		return InitResult{}, err
	}
	if done {
		return InitResult{}, ErrInitialised
	}
	kek, where, err := obtainKEK(ctx, o, cfg)
	if err != nil {
		return InitResult{}, err
	}
	sealer, err := secret.NewSealer(kek)
	if err != nil {
		return InitResult{}, err
	}
	td, err := pki.NewTrustDomain()
	if err != nil {
		return InitResult{}, err
	}
	err = store.WriteTx(ctx, db, func(tx *ent.Tx) error {
		if _, err := store.InitInstanceTx(ctx, tx, td); err != nil {
			return err
		}
		if err := pki.InitCA(ctx, tx, sealer, td, o.Now()); err != nil {
			return err
		}
		if mem, ok := o.Memory(); ok && mem < lowMemory {
			low := rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_LOW_MEMORY
			if err := settings.InitInstanceTx(ctx, tx, &rpmgrv1.InstanceSettings{PasswordHashProfile: &low}); err != nil {
				return err
			}
		}
		_, err := audit.Append(ctx, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli",
			Action: "instance.init", TargetType: "instance", TargetID: td, Result: audit.Success,
			Reason: "public URL " + cfg.PublicURL})
		return err
	})
	if err != nil {
		return InitResult{}, err
	}
	ca, err := pki.LoadCA(ctx, db, sealer, o.Now)
	if err != nil {
		return InitResult{}, err
	}
	tok, err := accounts.New(db, ctx, o.Now).FirstUserLink("local-cli")
	if err != nil {
		return InitResult{}, fmt.Errorf("controller: initialised, but no first-user link (run `rpmgr user reset-password`): %w", err)
	}
	return InitResult{TrustDomain: td, RootPin: pki.RootPin(ca.Root()), Root: ca.Root(), KEK: where,
		FirstUserLink: accounts.SetupURL(cfg.PublicURL, tok)}, nil
}

func (o *InitOptions) setDefaults() {
	if o.CredentialsDir == "" {
		o.CredentialsDir = "/etc/rpmgr/credstore"
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Encrypt == nil {
		o.Encrypt = systemdCredsEncrypt
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Memory == nil {
		o.Memory = hostMemory
	}
}

// bootFile reads the boot file, or writes it from the options if it does not exist.
func bootFile(o InitOptions, cfg *config.Controller) error {
	load := func(parse func(config.File) error) error {
		if !o.AllInOne {
			return parse(cfg)
		}
		var a config.AllInOne
		if err := parse(&a); err != nil {
			return err
		}
		*cfg = a.Controller()
		return nil
	}
	err := load(func(f config.File) error { return config.Load(o.ConfigPath, f) })
	switch {
	case err == nil:
		if o.PublicURL != "" && o.PublicURL != cfg.PublicURL {
			return fmt.Errorf("%s has public_url %s, not %s", o.ConfigPath, cfg.PublicURL, o.PublicURL)
		}
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return err
	case o.PublicURL == "":
		return fmt.Errorf("%s does not exist; --public-url is needed to write it", o.ConfigPath)
	}
	doc := map[string]any{"version": config.Version, "public_url": o.PublicURL}
	switch o.KEKSource {
	case "", config.KEKSystemdCredential:
	case config.KEKFile:
		path := o.KEKPath
		if path == "" {
			path = "/etc/rpmgr/kek"
		}
		doc["kek"] = map[string]string{"source": config.KEKFile, "path": path}
	default:
		return fmt.Errorf("--kek-source %q: want systemd-credential or file", o.KEKSource)
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := load(func(f config.File) error { return config.Parse(data, f) }); err != nil {
		return err
	}
	return writeNew(o.ConfigPath, data, 0o644)
}

// obtainKEK reads the configured KEK if it exists, and creates it otherwise; it never overwrites
// one. A systemd credential is readable only where systemd loaded it ($CREDENTIALS_DIRECTORY), so
// an encrypted credential that exists but is not loaded is refused.
func obtainKEK(ctx context.Context, o InitOptions, cfg config.Controller) (secret.KEK, string, error) {
	switch cfg.KEK.Source {
	case config.KEKFile:
		k, err := secret.LoadKEKFile(cfg.KEK.Path)
		if err == nil {
			return k, "existing file " + cfg.KEK.Path, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return secret.KEK{}, "", err
		}
		k, enc, err := newKEK()
		if err != nil {
			return secret.KEK{}, "", err
		}
		if err := writeNew(cfg.KEK.Path, enc, 0o600); err != nil {
			return secret.KEK{}, "", err
		}
		return k, "new file " + cfg.KEK.Path, nil
	case config.KEKSystemdCredential:
		if k, err := secret.LoadSystemdCredential(cfg.KEK.Name, o.Getenv); err == nil {
			return k, "loaded systemd credential " + cfg.KEK.Name, nil
		}
		path := filepath.Join(o.CredentialsDir, cfg.KEK.Name)
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return secret.KEK{}, "", fmt.Errorf("the encrypted credential %s exists but is not loaded: run init under "+
				"systemd-run --pipe --wait --property=LoadCredentialEncrypted=%s:%s, or remove it (err: %v)",
				path, cfg.KEK.Name, path, err)
		}
		k, enc, err := newKEK()
		if err != nil {
			return secret.KEK{}, "", err
		}
		if err := os.MkdirAll(o.CredentialsDir, 0o700); err != nil {
			return secret.KEK{}, "", err
		}
		if err := o.Encrypt(ctx, cfg.KEK.Name, path, enc); err != nil {
			return secret.KEK{}, "", fmt.Errorf("systemd-creds encrypt: %w", err)
		}
		return k, "new systemd credential " + path, nil
	}
	return secret.KEK{}, "", fmt.Errorf("kek.source %q", cfg.KEK.Source)
}

// newKEK returns a new KEK and its encoding: base64 of 32 random bytes and a newline.
func newKEK() (secret.KEK, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return secret.KEK{}, nil, err
	}
	defer clear(raw)
	k, err := secret.NewKEK(raw)
	if err != nil {
		return secret.KEK{}, nil, err
	}
	return k, []byte(base64.StdEncoding.EncodeToString(raw) + "\n"), nil
}

// writeNew writes a file that must not exist yet.
func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // G304: the operator's paths
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// systemdCredsEncrypt encrypts b into the credential file path with systemd-creds (systemd ≥ 250),
// which binds it to the host key and, where available, the TPM.
func systemdCredsEncrypt(ctx context.Context, name, path string, b []byte) error {
	cmd := exec.CommandContext(ctx, "systemd-creds", "encrypt", "--name="+name, "-", path) //nolint:gosec // G204: a validated credential name and path, no shell
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out := &limitedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return err
	}
	_, werr := stdin.Write(b)
	cerr := stdin.Close()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return errors.Join(werr, cerr)
}

// limitedBuffer keeps the first 4 KiB of a command's output for an error message.
type limitedBuffer struct{ b []byte }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := 4096 - len(l.b); room > 0 {
		l.b = append(l.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return string(l.b) }
