// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/controller"
)

// ServiceUser is the system user the roles run as (docs/10-operations.md, "Filesystem layout").
const ServiceUser = "rpmgr"

// Paths are where setup writes; tests move them into a temporary directory.
type Paths struct {
	Etc   string // the boot files, the policy and the KEK: /etc/rpmgr
	Lib   string // the state: /var/lib/rpmgr
	Units string // the systemd units: /etc/systemd/system
	Bin   string // the installed binary: /usr/local/bin/rpmgr
}

// DefaultPaths are the paths of docs/10-operations.md.
func DefaultPaths() Paths {
	return Paths{Etc: "/etc/rpmgr", Lib: "/var/lib/rpmgr", Units: "/etc/systemd/system", Bin: "/usr/local/bin/rpmgr"}
}

// Host is what setup does to the host; tests replace any of it. Zero fields are the real ones.
type Host struct {
	Paths Paths
	// Run runs a host command: useradd, systemctl.
	Run func(ctx context.Context, name string, args ...string) error
	// UserExists reports whether the service user exists.
	UserExists func() bool
	// GiveTo gives a file, or a directory and everything in it, to the service user.
	GiveTo func(path string) error
	// IsRoot reports whether setup runs as root.
	IsRoot func() bool
	// SystemdVersion is systemctl's version; 0 without systemd.
	SystemdVersion func() int
	// Encrypt is `systemd-creds encrypt`, for a KEK in a systemd credential.
	Encrypt func(ctx context.Context, name, path string, b []byte) error
	// Enroll enrolls a gateway or connector (agent.Enroll).
	Enroll func(ctx context.Context, o agent.EnrollOptions) (agent.Identity, error)
	// Ready waits until the admin listener at addr reports ready.
	Ready func(ctx context.Context, addr string) error
	// PortFree reports whether a TCP address can be listened on.
	PortFree func(addr string) bool
	Getenv   func(string) string
	Now      func() time.Time
}

func (h *Host) defaults() {
	if h.Paths == (Paths{}) {
		h.Paths = DefaultPaths()
	}
	if h.Run == nil {
		h.Run = func(ctx context.Context, name string, args ...string) error {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: setup's own commands
			if err != nil {
				return fmt.Errorf("%s: %w: %s", name, err, out)
			}
			return nil
		}
	}
	if h.UserExists == nil {
		h.UserExists = func() bool { _, err := user.Lookup(ServiceUser); return err == nil }
	}
	if h.GiveTo == nil {
		h.GiveTo = giveTree
	}
	if h.IsRoot == nil {
		h.IsRoot = func() bool { return os.Geteuid() == 0 }
	}
	if h.SystemdVersion == nil {
		h.SystemdVersion = controller.SystemdVersion
	}
	if h.Enroll == nil {
		h.Enroll = agent.Enroll
	}
	if h.Ready == nil {
		h.Ready = ready
	}
	if h.PortFree == nil {
		h.PortFree = func(addr string) bool {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return false
			}
			_ = ln.Close()
			return true
		}
	}
	if h.Getenv == nil {
		h.Getenv = os.Getenv
	}
	if h.Now == nil {
		h.Now = time.Now
	}
}

// giveTree gives path and everything below it to the service user.
func giveTree(path string) error {
	u, err := user.Lookup(ServiceUser)
	if err != nil {
		return err
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("setup: the user %s has no numeric ids", ServiceUser)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return os.Lchown(path, uid, gid)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	// Walked within the root, so a symlink planted meanwhile cannot lead outside it.
	return fs.WalkDir(root.FS(), ".", func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return root.Lchown(p, uid, gid)
	})
}

// ready polls the admin listener's /readyz for up to two minutes.
func ready(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	c := &http.Client{Timeout: 5 * time.Second}
	var last error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/readyz", nil)
		if err != nil {
			return err
		}
		resp, err := c.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("/readyz: %s", resp.Status)
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("not ready within two minutes: %w", last)
		case <-time.After(time.Second):
		}
	}
}
