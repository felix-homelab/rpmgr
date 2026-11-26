// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/kms/kmstest"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// lockedBuffer is a buffer that the loggers of parallel tests write to.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var wrappedRe = regexp.MustCompile(`vault:v1:([A-Za-z0-9+/]{40,}={0,2})`)

// TestKMS_CredentialsNeverLoggedInAuditAndStatus provokes the failures of Transit that docs/12
// lists (a refused credential, a server error, a malformed answer, an unreachable host), with a
// fake that puts the token, the role ID, the secret ID and the request, which holds a wrapped key,
// into its own error messages. The output of `kek status`, the errors of `kek rotate` and of the
// start, the metrics and the audit log of the instance must hold none of them.
func TestKMS_CredentialsNeverLoggedInAuditAndStatus(t *testing.T) {
	var logs lockedBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	controller.SetLocalLog(t, logger)
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

			probe, err := controller.OpenKMSWithMetrics(ctx, cfg, logger)
			if err != nil {
				t.Fatal(err)
			}
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
				if _, err := controller.OpenKMSWithMetrics(ctx, cfg, logger); err == nil {
					t.Errorf("%s: the start would succeed", mode)
				} else {
					seen = append(seen, "start error: "+err.Error())
				}
				// A running controller: a request fails, then /readyz says why.
				if err := probe.Touch(ctx); err == nil {
					t.Errorf("%s: a request succeeded", mode)
				} else {
					seen = append(seen, "request error: "+err.Error())
				}
				if err := probe.Ready(ctx); err == nil {
					t.Errorf("%s: ready", mode)
				} else {
					seen = append(seen, "readyz: "+err.Error())
				}
				seen = append(seen, "metrics:\n"+gatherText(t, probe.Registry))
			}
			srv.FailWith(403, true)
			provoke("refused")
			srv.FailWith(500, true)
			provoke("server error")
			srv.FailWith(200, true)
			provoke("malformed answer")
			// Transit fails part of the way through a rotation, on a value's own call: the error of
			// that value names the value, and must not hold its sealed bytes or the request.
			srv.FailWith(0, false)
			srv.Rotate()
			srv.FailRewrapAfter(1)
			if _, _, err := controller.RotateKEK(ctx, h.cfg, controller.PreviousKEK{}, noEnv); err == nil {
				t.Error("a rotation with a failing rewrap succeeded")
			} else {
				seen = append(seen, "rotate error part way: "+err.Error())
			}
			srv.FailRewrapAfter(0)
			// With Transit back, the audit log holds the successful rotation too.
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
			seen = append(seen, "logs:\n"+logs.String())
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
