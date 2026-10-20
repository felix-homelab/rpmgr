// SPDX-License-Identifier: Apache-2.0

package allinone_test

import (
	"net/url"
	"slices"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// TestAllInOne_FollowsGroupHostnames (#601): a public hostname added to or removed from the built-in
// gateway group counts, without a restart, among the names whose addresses the all-in-one's
// connector treats as the host's own; the public URL's host always does.
func TestAllInOne_FollowsGroupHostnames(t *testing.T) {
	h := newHost(t)
	h.init(t)
	db, sys, group := h.db(t)
	public, err := url.Parse(h.cfg.PublicURL)
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu  sync.Mutex
		got []string
	)
	allinone.SetNamesFollowed(t, func(names []string) {
		mu.Lock()
		got = names
		mu.Unlock()
	})
	has := func(name string) func() bool {
		return func() bool {
			mu.Lock()
			defer mu.Unlock()
			return slices.Contains(got, name) && slices.Contains(got, public.Hostname())
		}
	}
	setHostnames := func(names ...string) {
		t.Helper()
		if _, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
			return []string{group.ID}, tx.GatewayGroup.UpdateOneID(group.ID).SetPublicHostnames(names).Exec(sys)
		}); err != nil {
			t.Fatal(err)
		}
	}
	h.run(t)
	waitFor(t, "not ready", h.ready)

	setHostnames("home.example.net", "edge.example.net")
	waitFor(t, "an added hostname is not followed", has("home.example.net"))
	waitFor(t, "a second added hostname is not followed", has("edge.example.net"))
	setHostnames("edge.example.net")
	waitFor(t, "a removed hostname is still followed", func() bool { return !has("home.example.net")() && has("edge.example.net")() })
	setHostnames()
	waitFor(t, "with no hostnames, the public URL's host is not kept alone", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return slices.Equal(got, []string{public.Hostname()})
	})
}
