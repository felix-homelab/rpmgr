// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestSetACME: `rpmgr setup` sets the instance's ACME directory and e-mail address on an
// initialised host, audited as local-cli; an empty value keeps the setting, and an invalid one or
// a host without a database is refused.
func TestSetACME(t *testing.T) {
	ctx := context.Background()
	if err := controller.SetACME(ctx, filepath.Join(t.TempDir(), "none.yaml"), "", ""); err != nil {
		t.Errorf("nothing to set: %v", err)
	}
	if err := controller.SetACME(ctx, filepath.Join(t.TempDir(), "none.yaml"), "", "ops"); err == nil || !strings.Contains(err.Error(), "ACME settings") {
		t.Errorf("an invalid e-mail address: %v", err)
	}
	if err := controller.SetACME(ctx, filepath.Join(t.TempDir(), "none.yaml"), "", "ops@example.com"); err == nil {
		t.Error("set without a boot file")
	}

	h, _ := initHost(t)
	staging := "https://acme-staging-v02.api.letsencrypt.org/directory"
	if err := controller.SetACME(ctx, h.cfg, staging, ""); err != nil {
		t.Fatal(err)
	}
	if err := controller.SetACME(ctx, h.cfg, "", "ops@example.com"); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	inst, _, err := settings.Instance(storetest.SystemCtx(t), db.ReadClient())
	if err != nil || inst.GetAcmeDirectoryUrl() != staging || inst.GetAcmeEmail() != "ops@example.com" {
		t.Fatalf("instance settings %v %v", inst, err)
	}
	if n := len(slices.DeleteFunc(localActions(t, h), func(a string) bool { return !strings.HasPrefix(a, "instance.settings_update") })); n != 2 {
		t.Errorf("%d settings updates audited, want 2", n)
	}
}

// TestSelfSignedPEM: the certificate setup writes for a public name is a valid pair for that name,
// which no public CA signed.
func TestSelfSignedPEM(t *testing.T) {
	cert, key, err := controller.SelfSignedPEM("panel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || c.VerifyHostname("panel.example.com") != nil || c.VerifyHostname("other.example.com") == nil {
		t.Fatalf("certificate %v: %v", c.DNSNames, err)
	}
	if b, _ := pem.Decode(key); b == nil || b.Type != "PRIVATE KEY" {
		t.Errorf("key block %v", b)
	}
}

// TestKEKSourceFor: a new boot file takes the systemd credential from systemd 250, else a file.
func TestKEKSourceFor(t *testing.T) {
	for v, want := range map[int]string{0: config.KEKFile, 249: config.KEKFile, 250: config.KEKSystemdCredential, 257: config.KEKSystemdCredential} {
		if got := controller.KEKSourceFor(v); got != want {
			t.Errorf("systemd %d: %s, want %s", v, got, want)
		}
	}
}
