// SPDX-License-Identifier: Apache-2.0

//go:build unix

package setup_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/setup"
)

// umask sets the process's umask for the test.
func umask(t *testing.T, mask int) {
	t.Helper()
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

// modes checks the permission bits of paths.
func modes(t *testing.T, want map[string]os.FileMode) {
	t.Helper()
	for path, w := range want {
		fi, err := os.Stat(path)
		if err != nil {
			t.Error(err)
			continue
		}
		if fi.Mode().Perm() != w {
			t.Errorf("%s: mode %04o, want %04o", path, fi.Mode().Perm(), w)
		}
	}
}

// selfSignedAIO is an all-in-one with a self-signed certificate of a public name, whose files setup
// writes into a directory of its own.
func selfSignedAIO() setup.Values {
	return setup.Values{Role: setup.AllInOne, PublicURL: "https://panel.example.com", KEKSource: config.KEKFile,
		TLS: setup.TLSSelfSigned, ListenAdmin: "127.0.0.1:17381"}
}

// TestPlan_StrictUmask (#456, #458): setup started by install.sh ran under its umask 077, wrote the
// boot file and the unit with mode 0600, and the service, which runs as rpmgr, could not read its
// boot file. Then setup under a strict umask made /etc/rpmgr/tls 0700, or 0750 under umask 027 of
// many hardened hosts, and the service could not reach its certificate. What setup writes for the
// service, and the directories it creates, have their modes whatever the umask.
func TestPlan_StrictUmask(t *testing.T) {
	for _, mask := range []int{0o077, 0o027} {
		t.Run(fmt.Sprintf("%04o", mask), func(t *testing.T) {
			umask(t, mask)
			h := newHost(t, &fakeHost{})
			p, err := setup.New(selfSignedAIO(), h)
			if err != nil {
				t.Fatal(err)
			}
			if r, err := p.Run(context.Background(), func(string) {}); err != nil {
				t.Fatalf("run: %v (wrote %v)", err, r.Written)
			}
			modes(t, map[string]os.FileMode{
				h.Paths.Etc:                       0o755,
				h.Paths.Lib:                       0o750,
				h.Paths.Units:                     0o755,
				filepath.Join(h.Paths.Etc, "tls"): 0o755,
				filepath.Join(h.Paths.Etc, "all-in-one.yaml"):              0o644,
				filepath.Join(h.Paths.Units, "rpmgr-all-in-one.service"):   0o644,
				filepath.Join(h.Paths.Etc, "tls", "panel.example.com.crt"): 0o644,
				filepath.Join(h.Paths.Etc, "tls", "panel.example.com.key"): 0o600,
			})
		})
	}
}

// TestPlan_StrictUmask_Connector (#458): a connector's directories and files too: its proxy drop-in
// and its connector-local policy.
func TestPlan_StrictUmask_Connector(t *testing.T) {
	umask(t, 0o077)
	h := newHost(t, &fakeHost{})
	p, err := setup.New(setup.Values{Role: setup.Connector, ControllerURL: "https://panel.example.com", Pin: pin(t), Token: newToken(t),
		AllowTargets: []string{"10.0.0.5:8080"}, Proxy: "http://proxy.lan:3128"}, h)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := p.Run(context.Background(), nil); err != nil {
		t.Fatalf("run: %v (wrote %v)", err, r.Written)
	}
	dropIn := filepath.Join(h.Paths.Units, "rpmgr-connector.service.d")
	modes(t, map[string]os.FileMode{
		h.Paths.Etc: 0o755, h.Paths.Lib: 0o750, dropIn: 0o755,
		filepath.Join(dropIn, "proxy.conf"):          0o644,
		filepath.Join(h.Paths.Etc, "connector.yaml"): 0o644,
		filepath.Join(h.Paths.Etc, "policy.yaml"):    0o644,
	})
}

// TestPlan_KeepsDirectoryModes: a directory that exists keeps the mode the operator gave it; setup
// sets the modes of the directories it creates only.
func TestPlan_KeepsDirectoryModes(t *testing.T) {
	umask(t, 0o022)
	h := newHost(t, &fakeHost{})
	for dir, mode := range map[string]os.FileMode{h.Paths.Etc: 0o711, h.Paths.Lib: 0o700} {
		if err := os.Mkdir(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
	}
	p, err := setup.New(selfSignedAIO(), h)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := p.Run(context.Background(), nil); err != nil {
		t.Fatalf("run: %v (wrote %v)", err, r.Written)
	}
	modes(t, map[string]os.FileMode{h.Paths.Etc: 0o711, h.Paths.Lib: 0o700, filepath.Join(h.Paths.Etc, "tls"): 0o755})
}

// TestPlan_DirectoryIsAFile: where setup needs a directory, a file stops it with the path, and
// setup names what it had written.
func TestPlan_DirectoryIsAFile(t *testing.T) {
	h := newHost(t, &fakeHost{})
	if err := os.Mkdir(h.Paths.Etc, 0o755); err != nil {
		t.Fatal(err)
	}
	tls := filepath.Join(h.Paths.Etc, "tls")
	write(t, tls, "not a directory")
	p, err := setup.New(selfSignedAIO(), h)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Run(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), tls+" exists and is no directory") {
		t.Fatalf("run: %v, want the file %s named", err, tls)
	}
	if exists := func(p string) bool { _, err := os.Stat(p); return err == nil }; exists(filepath.Join(h.Paths.Etc, "all-in-one.yaml")) {
		t.Errorf("setup went on after the failure: %v", r.Written)
	}
}
