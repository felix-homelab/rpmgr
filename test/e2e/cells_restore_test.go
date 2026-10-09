// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"errors"
	"testing"
	"time"
)

// TestController_Restore: the controller restored from a backup has a new db_epoch, and the agents
// accept its lower revision with it: a route created after the backup stops answering, one from
// before keeps answering, and a route created after the restore works.
func TestController_Restore(t *testing.T) {
	before, after, later := 20501, 20502, 20503
	const boot = "/var/lib/rpmgr/controller.yaml"
	addRoute(t, "restore-before", before, "auto", "con1", "con2")
	eventually(t, 30*time.Second, "the route from before the backup", func() error { return client("check", "-addr", addr("gw1", before)) })
	if _, err := in("ctl", "rpmgr", "backup", "--out", "/var/lib/rpmgr/e2e.backup", "--config", boot); err != nil {
		t.Fatal(err)
	}
	addRoute(t, "restore-after", after, "auto", "con1", "con2")
	eventually(t, 30*time.Second, "the route from after the backup", func() error { return client("check", "-addr", addr("gw1", after)) })

	if err := signal("ctl", "TERM"); err != nil {
		t.Fatal(err)
	}
	out, err := in("ctl", "rpmgr", "restore", "--in", "/var/lib/rpmgr/e2e.backup", "--config", boot)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(out)
	if err := startRole("ctl", "controller"); err != nil {
		t.Fatal(err)
	}
	if err := ready("ctl", 7381); err != nil {
		t.Fatal(err)
	}
	for _, gw := range []string{"gw1", "gw2"} {
		eventually(t, 60*time.Second, "the route from after the backup gone from "+gw, func() error {
			if client("check", "-addr", addr(gw, after)) == nil {
				return errors.New("it still answers")
			}
			return nil
		})
		if err := client("check", "-addr", addr(gw, before)); err != nil {
			t.Errorf("the route from before the backup through %s: %v", gw, err)
		}
	}
	addRoute(t, "restore-later", later, "auto", "con1", "con2")
	eventually(t, 30*time.Second, "a route created after the restore", func() error { return client("check", "-addr", addr("gw1", later)) })
}
