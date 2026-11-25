// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/kms/kmstest"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

var wrappedRe = regexp.MustCompile(`vault:v1:([A-Za-z0-9+/]{40,}={0,2})`)

// TestKMS_CredentialsNeverLoggedInAuditAndStatus provokes the failures of Transit that docs/12
// lists (a refused credential, a server error, a malformed answer, an unreachable host), with a
// fake that puts the token, the role ID, the secret ID and the request, which holds a wrapped key,
// into its own error messages. The output of `kek status`, the errors of `kek rotate` and of the
// start, the metrics and the audit log of the instance must hold none of them.
func TestKMS_CredentialsNeverLoggedInAuditAndStatus(t *testing.T) {
	for name, login := range map[string]func(*kmstest.Server) string{
		"token file": func(s *kmstest.Server) string { return "token_file: " + s.WriteCredential("token", kmstest.Token) },
		"approle": func(s *kmstest.Server) string {
			return "approle: {role_id_file: " + s.WriteCredential("role", kmstest.RoleID) +
				", secret_id_file: " + s.WriteCredential("secret", kmstest.SecretID) + "}"
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			srv := kmstest.New(t)
			h := newHost(t)
			h.writeBoot(t, "kek:\n  source: kms\n  kms: {address: "+srv.URL+", key: "+kmstest.Key+", ca_file: "+srv.CAFile()+", "+login(srv)+"}\n")
			if _, err := controller.Init(ctx, h.opts()); err != nil {
				t.Fatal(err)
			}
			var cfg config.Controller
			if err := config.Load(h.cfg, &cfg); err != nil {
				t.Fatal(err)
			}
			db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
			if err != nil {
				t.Fatal(err)
			}
			row := db.Client().CAKey.Query().FirstX(storetest.SystemCtx(t))
			_ = db.Close()
			m := wrappedRe.FindSubmatch(*row.KeyEnc)
			if m == nil {
				t.Fatalf("no wrapped key in %q", *row.KeyEnc)
			}
			forbidden := []string{kmstest.Token, kmstest.RoleID, kmstest.SecretID, "vault:v", string(m[1])}

			var seen []string
			provoke := func(mode string) {
				t.Helper()
				if _, _, err := controller.RotateKEK(ctx, h.cfg, controller.PreviousKEK{}, noEnv); err == nil {
					t.Errorf("%s: rotate succeeded", mode)
				} else {
					seen = append(seen, "rotate error: "+err.Error())
				}
				st, err := controller.StatusKEK(ctx, h.cfg, noEnv)
				if err != nil {
					t.Fatalf("%s: status: %v", mode, err)
				}
				if st.CurrentErr == nil || len(st.Old) == 0 {
					t.Errorf("%s: status %+v; want the reason and the values counted", mode, st)
				}
				var out bytes.Buffer
				if err := st.Write(&out); err != nil {
					t.Fatal(err)
				}
				seen = append(seen, "kek status:\n"+out.String())
				reg, err := controller.OpenKMSWithMetrics(ctx, cfg)
				if err == nil {
					t.Errorf("%s: the start would succeed", mode)
				} else {
					seen = append(seen, "start error: "+err.Error())
				}
				seen = append(seen, "metrics:\n"+gatherText(t, reg))
			}
			srv.FailWith(403, true)
			provoke("refused")
			srv.FailWith(500, true)
			provoke("server error")
			srv.FailWith(200, true)
			provoke("malformed answer")
			// With Transit back, the audit log holds the successful rotation too.
			srv.FailWith(0, false)
			srv.Rotate()
			if n, _, err := controller.RotateKEK(ctx, h.cfg, controller.PreviousKEK{}, noEnv); err != nil || n == 0 {
				t.Fatalf("rotate with Transit back: %d %v", n, err)
			}
			srv.Close()
			provoke("unreachable")

			db, err = store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
			if err != nil {
				t.Fatal(err)
			}
			entries := db.Client().AuditEntry.Query().AllX(storetest.SystemCtx(t))
			_ = db.Close()
			for _, e := range entries {
				seen = append(seen, fmt.Sprintf("audit: %+v", e))
			}
			if len(entries) == 0 {
				t.Fatal("no audit entries to look in")
			}
			all := strings.Join(seen, "\n")
			for _, f := range forbidden {
				if strings.Contains(all, f) {
					t.Errorf("%q appears in the output, the errors, the metrics or the audit log:\n%s", f, all)
				}
			}
			for _, want := range []string{"rpmgr_kms_up 0", `rpmgr_kms_requests_total{op="check",result="denied"}`,
				`rpmgr_kms_requests_total{op="check",result="unavailable"}`} {
				if !strings.Contains(all, want) {
					t.Errorf("the metrics lack %q", want)
				}
			}
		})
	}
}

// gatherText renders the metrics of reg as name{labels} value lines, sorted.
func gatherText(t *testing.T, reg *prometheus.Registry) string {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, f := range fams {
		for _, m := range f.GetMetric() {
			line := f.GetName()
			var labels []string
			for _, l := range m.GetLabel() {
				labels = append(labels, fmt.Sprintf("%s=%q", l.GetName(), l.GetValue()))
			}
			if len(labels) > 0 {
				line += "{" + strings.Join(labels, ",") + "}"
			}
			lines = append(lines, fmt.Sprintf("%s %g", line, m.GetGauge().GetValue()+m.GetCounter().GetValue()))
		}
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}
