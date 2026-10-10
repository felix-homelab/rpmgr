// SPDX-License-Identifier: Apache-2.0

package allinone_test

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// recorder is a role's registry that notes the name of every metric registered on it.
type recorder struct {
	*prometheus.Registry
	mu    sync.Mutex
	names map[string]bool
}

func newRecorder() *recorder {
	return &recorder{Registry: telemetry.NewRegistry(), names: map[string]bool{}}
}

var fqName = regexp.MustCompile(`fqName: "([^"]+)"`)

func (r *recorder) Register(c prometheus.Collector) error {
	ch := make(chan *prometheus.Desc, 16)
	go func() { c.Describe(ch); close(ch) }()
	for d := range ch {
		if m := fqName.FindStringSubmatch(d.String()); m != nil {
			r.mu.Lock()
			r.names[m[1]] = true
			r.mu.Unlock()
		}
	}
	return r.Registry.Register(c)
}

func (r *recorder) MustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		if err := r.Register(c); err != nil {
			panic(err)
		}
	}
}

func (r *recorder) has(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.names[name]
}

// p1Metrics reads docs/10-operations.md's metric table: every Phase 1 metric with its roles.
func p1Metrics(t *testing.T) map[string][]string {
	t.Helper()
	b, err := os.ReadFile("../../docs/10-operations.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\| (`rpmgr_[^|]+) \\| [a-z]+ \\| ([a-z, ]+) \\| ([12]) \\|")
	name := regexp.MustCompile("`(rpmgr_[a-z0-9_]+)")
	out := map[string][]string{}
	for _, m := range row.FindAllStringSubmatch(string(b), -1) {
		if m[3] != "1" {
			continue
		}
		for _, n := range name.FindAllStringSubmatch(m[1], -1) {
			out[n[1]] = strings.Split(m[2], ", ")
		}
	}
	if len(out) < 20 {
		t.Fatalf("only %d Phase 1 metrics in 10's table: %v", len(out), out)
	}
	return out
}

// checkP1Metrics (docs/10-operations.md, "Metrics"; plan 9.3): every Phase 1 metric of 10's table
// is registered by each role it names: all-in-one's registry holds the controller's and the
// gateway's, the connector's its own, and the agent metrics are in both. Both admin listeners
// serve them on /metrics.
func checkP1Metrics(t *testing.T, aio, con *recorder, aioAdmin, conAdmin string) {
	t.Helper()
	for metric, roles := range p1Metrics(t) {
		for _, role := range roles {
			regs := map[string][]*recorder{"controller": {aio}, "gateway": {aio}, "connector": {con}, "agent": {aio, con}}[role]
			if regs == nil {
				t.Errorf("%s: unknown role %q", metric, role)
			}
			for _, r := range regs {
				if !r.has(metric) {
					t.Errorf("%s is not registered by the %s", metric, role)
				}
			}
		}
	}
	for addr, want := range map[string][]string{
		aioAdmin: {"rpmgr_gateway_sessions", "rpmgr_controller_control_sessions", "rpmgr_audit_checkpoint_age_seconds", "rpmgr_quic_gso_enabled"},
		conAdmin: {"rpmgr_quic_udp_buffer_warning", "rpmgr_agent_applied_revision"},
	} {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		for _, w := range want {
			if !strings.Contains(string(body), "\n"+w) {
				t.Errorf("%s/metrics lacks %s", addr, w)
			}
		}
	}
}
