// SPDX-License-Identifier: Apache-2.0

package s6

// Two controller replicas as two OS processes. certmagic keeps process-global state (its job
// manager deduplicates renewals by name, and active challenges live in a package map), so two
// replicas in one process could avoid duplicate orders for the wrong reason. Here each replica is
// the test binary re-executed as TestReplicaProcess, with its own certmagic, sharing only the
// database file; challenges reach the gateways over gateway.ControlHandler.

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/felix-homelab/rpmgr/spikes/s6/internal/cfclient"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/controller"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/controlplane"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/dbstore"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/dnsadapter"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/gateway"
)

type replicaConfig struct {
	ID           string
	Directory    string
	ServerCAFile string // PEM of the ACME server's TLS certificate
	DNS          string
	CFURL        string
	DBPath       string
	Gateways     []controlplane.HTTPSession
	Mode         string // "obtain" or "manage"
	Names        []string
	RenewalRatio float64
	DisableARI   bool
}

type replicaEvent struct {
	Replica string `json:"replica"`
	Event   string `json:"event"` // obtained, loaded, waits, error, ready
	Name    string `json:"name,omitempty"`
	Renewal bool   `json:"renewal,omitempty"`
	Serial  string `json:"serial,omitempty"`
	N       int64  `json:"n,omitempty"`
	Err     string `json:"err,omitempty"`
	at      time.Time
}

const replicaEnv = "S6_REPLICA"

// TestReplicaProcess is the body of a replica process; it does nothing in a normal test run.
func TestReplicaProcess(t *testing.T) {
	raw := os.Getenv(replicaEnv)
	if raw == "" {
		t.Skip("helper for the multi-process tests")
	}
	var rc replicaConfig
	if err := json.Unmarshal([]byte(raw), &rc); err != nil {
		t.Fatal(err)
	}
	emit := func(ev replicaEvent) {
		ev.Replica = rc.ID
		b, _ := json.Marshal(ev)
		fmt.Printf("EVENT %s\n", b)
	}
	caPEM, err := os.ReadFile(rc.ServerCAFile)
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	trust.AppendCertsFromPEM(caPEM)
	st, err := dbstore.Open(rc.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	st.LeaseTTL = 10 * time.Second
	defer st.Close()
	logger := zap.NewNop()
	if os.Getenv("S6_CERTMAGIC_LOG") != "" {
		cfg := zap.NewDevelopmentConfig()
		cfg.InitialFields = map[string]any{"replica": rc.ID}
		logger, _ = cfg.Build()
	}
	sessions := make([]controlplane.Session, len(rc.Gateways))
	for i := range rc.Gateways {
		sessions[i] = &rc.Gateways[i]
	}
	syncStore := &controlplane.SyncStorage{Storage: st, Route: func(string) []controlplane.Session { return sessions }}
	ctl, err := controller.New(controller.Options{
		Storage: syncStore, DirectoryURL: rc.Directory, ACMETrust: trust, Email: "spike@rpmgr.test",
		ManagedZones:          []string{managedZone},
		DNSProvider:           &dnsadapter.Provider{Client: cfclient.New(rc.CFURL, cfToken, nil), Marker: marker},
		Resolvers:             []string{rc.DNS},
		DNSPropagationTimeout: -1, // the fake publishes synchronously; no nameserver on port 53
		RenewalWindowRatio:    rc.RenewalRatio,
		DisableARI:            rc.DisableARI,
		CacheOptions:          certmagic.CacheOptions{RenewCheckInterval: time.Second},
		OnObtained: func(name string, renewal bool) {
			emit(replicaEvent{Event: "obtained", Name: name, Renewal: renewal})
		},
		Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Stop()
	ctx := context.Background()
	switch rc.Mode {
	case "obtain":
		var wg sync.WaitGroup
		for _, n := range rc.Names {
			wg.Go(func() {
				if err := ctl.Obtain(ctx, n); err != nil {
					emit(replicaEvent{Event: "error", Name: n, Err: err.Error()})
				}
			})
		}
		wg.Wait()
		for _, n := range rc.Names {
			if c, err := ctl.Load(ctx, n); err == nil {
				emit(replicaEvent{Event: "loaded", Name: n, Serial: c.Leaf.SerialNumber.String()})
			}
		}
	case "manage":
		if err := ctl.Manage(ctx, rc.Names); err != nil {
			emit(replicaEvent{Event: "error", Err: err.Error()})
		}
		emit(replicaEvent{Event: "ready"})
		select {} // until the parent ends the process
	}
	emit(replicaEvent{Event: "waits", N: st.Waits.Load()})
}

type replicaSet struct {
	mu     sync.Mutex
	events []replicaEvent
	cmds   []*exec.Cmd
	done   chan error
}

func (e *env) startReplicas(t *testing.T, ctx context.Context, mode string, names []string, ratio float64, disableARI bool, ids ...string) *replicaSet {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "acme-server.pem")
	if err := os.WriteFile(caFile, e.pebble.ServerCertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	var gws []controlplane.HTTPSession
	for _, gw := range e.gws {
		token := fmt.Sprintf("control-%s-%d", gw.ID, time.Now().UnixNano())
		srv := httptest.NewServer(gateway.ControlHandler(gw, token))
		t.Cleanup(srv.Close)
		gws = append(gws, controlplane.HTTPSession{ID: gw.ID, URL: srv.URL, Token: token})
	}
	rs := &replicaSet{done: make(chan error, len(ids))}
	for _, id := range ids {
		rc := replicaConfig{ID: id, Directory: e.pebble.DirectoryURL, ServerCAFile: caFile,
			DNS: e.dns.Addr, CFURL: e.cfURL, DBPath: e.dbPath, Gateways: gws, Mode: mode,
			Names: names, RenewalRatio: ratio, DisableARI: disableARI}
		b, _ := json.Marshal(rc)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReplicaProcess$", "-test.count=1")
		cmd.Env = append(os.Environ(), replicaEnv+"="+string(b))
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		rs.cmds = append(rs.cmds, cmd)
		go func() {
			sc := bufio.NewScanner(out)
			for sc.Scan() {
				line, ok := strings.CutPrefix(sc.Text(), "EVENT ")
				if !ok {
					continue
				}
				var ev replicaEvent
				if json.Unmarshal([]byte(line), &ev) == nil {
					ev.at = time.Now()
					rs.mu.Lock()
					rs.events = append(rs.events, ev)
					rs.mu.Unlock()
				}
			}
			rs.done <- cmd.Wait()
		}()
	}
	return rs
}

func (rs *replicaSet) snapshot() []replicaEvent {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]replicaEvent(nil), rs.events...)
}

// Two replica processes obtain the same names at the same time: exactly one order per name.
func TestTwoReplicaProcessesNoDuplicateOrders(t *testing.T) {
	e := newEnv(t, envOptions{})
	names := []string{"p1." + otherZone, "p2." + otherZone, "q1." + managedZone, "*.q." + managedZone}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	rs := e.startReplicas(t, ctx, "obtain", names, 0, false, "a", "b")
	for range 2 {
		if err := <-rs.done; err != nil {
			t.Fatalf("replica process failed: %v", err)
		}
	}
	serial := map[string]map[string]bool{}
	var waits int64
	for _, ev := range rs.snapshot() {
		switch ev.Event {
		case "error":
			t.Errorf("replica %s: %s: %s", ev.Replica, ev.Name, ev.Err)
		case "loaded":
			if serial[ev.Name] == nil {
				serial[ev.Name] = map[string]bool{}
			}
			serial[ev.Name][ev.Serial] = true
		case "waits":
			waits += ev.N
		}
	}
	for _, n := range names {
		if got := e.pebble.OrdersFor(n); got != 1 {
			t.Errorf("%s: %d orders, want exactly 1", n, got)
		}
		if len(serial[n]) != 1 {
			t.Errorf("%s: replicas loaded %d different certificates", n, len(serial[n]))
		}
	}
	if waits == 0 {
		t.Fatal("no replica ever waited for the lease: the processes did not contend")
	}
	t.Logf("two processes, %d names: %d orders; %d lock acquisitions waited for the other process",
		len(names), e.pebble.NewOrders.Load(), waits)
}

// Two replica processes manage the same short-lived certificates: each renewal is ordered by one
// replica only. ARI is disabled here: with 40-second certificates Pebble's ARI window starts at
// issuance, so the CA itself may ask for an immediate second renewal (results/raw/renew-ari-*.txt),
// which would hide what this test checks — the lease and certmagic's re-check after it.
func TestTwoReplicaProcessesRenewOnce(t *testing.T) {
	e := newEnv(t, envOptions{validity: 40 * time.Second})
	names := []string{"r." + otherZone, "r." + managedZone}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	rs := e.startReplicas(t, ctx, "manage", names, 0.5, true, "a", "b")
	deadline := time.After(120 * time.Second)
	for {
		renewed := map[string]bool{}
		for _, ev := range rs.snapshot() {
			if ev.Event == "error" {
				t.Fatalf("replica %s: %s", ev.Replica, ev.Err)
			}
			if ev.Event == "obtained" && ev.Renewal {
				renewed[ev.Name] = true
			}
		}
		if len(renewed) == len(names) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("not every name renewed in time; events: %+v", rs.snapshot())
		case err := <-rs.done:
			t.Fatalf("replica exited early: %v", err)
		case <-time.After(500 * time.Millisecond):
		}
	}
	time.Sleep(5 * time.Second) // the other replica gets time to notice and skip
	cancel()
	events := rs.snapshot()
	for _, n := range names {
		var obtained []replicaEvent
		for _, ev := range events {
			if ev.Event == "obtained" && ev.Name == n {
				obtained = append(obtained, ev)
			}
		}
		if got := e.pebble.OrdersFor(n); got != len(obtained) {
			t.Errorf("%s: %d orders but %d obtained events", n, got, len(obtained))
		}
		for i := 1; i < len(obtained); i++ {
			if gap := obtained[i].at.Sub(obtained[i-1].at); gap < 5*time.Second {
				t.Errorf("%s: two issuances %v apart (replicas %s and %s): a duplicate order",
					n, gap.Round(time.Millisecond), obtained[i-1].Replica, obtained[i].Replica)
			}
		}
		var by []string
		for _, ev := range obtained {
			by = append(by, fmt.Sprintf("%s(renewal=%v)", ev.Replica, ev.Renewal))
		}
		t.Logf("%s: %d orders: %s", n, e.pebble.OrdersFor(n), strings.Join(by, ", "))
	}
}
