// SPDX-License-Identifier: Apache-2.0

//go:build unix

package setup_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/setup"
)

// TestPlan_StrictUmask (#456): setup started by install.sh ran under its umask 077, wrote the boot
// file and the unit with mode 0600, and the service, which runs as rpmgr, could not read its boot
// file. What setup writes for the service has its mode whatever the umask.
func TestPlan_StrictUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	f := &fakeHost{}
	h := newHost(t, f)
	p, err := setup.New(setup.Values{Role: setup.AllInOne, PublicURL: "https://panel.example.com", KEKSource: config.KEKFile,
		TLS: setup.TLSSelfSigned, ListenAdmin: "127.0.0.1:17381"}, h)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := p.Run(context.Background(), func(string) {}); err != nil {
		t.Fatalf("run: %v (wrote %v)", err, r.Written)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Join(h.Paths.Etc, "all-in-one.yaml"):              0o644,
		filepath.Join(h.Paths.Units, "rpmgr-all-in-one.service"):   0o644,
		filepath.Join(h.Paths.Etc, "tls", "panel.example.com.crt"): 0o644,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: mode %04o, want %04o", path, fi.Mode().Perm(), want)
		}
	}
}
