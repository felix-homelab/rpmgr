// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// cells builds one repetition of every cell the tables read, with the given QUIC/h2 factors for
// single-stream throughput, 32-stream goodput, setup latency and CPU per Gbit/s (above 1 favours
// QUIC) and the tunnels' share of a direct connection's single-stream throughput.
func cells(testbed string, f [4]float64, ofDirect float64) []Record {
	var recs []Record
	add := func(r Record, sys string) { r.Testbed, r.System = testbed, sys; recs = append(recs, r) }
	for _, rtt := range []float64{1, 80} {
		for _, dir := range []string{"up", "down"} {
			base := Record{RTTms: rtt, Workload: dir, Streams: 1}
			add(withTput(base, 1000), "direct")
			add(withTput(base, 1000*ofDirect*f[0]), "quic")
			add(withTput(base, 1000*ofDirect), "h2")
			lossy := Record{RTTms: rtt, LossPct: 1, Workload: dir, Streams: 32}
			add(withTput(lossy, 600*f[1]), "quic")
			add(withTput(lossy, 600), "h2")
		}
		setup := Record{RTTms: rtt, Workload: "setup"}
		setup.P99ms = rtt + 1
		add(setup, "direct")
		q := setup
		q.P99ms = (rtt + 1.5) / f[2]
		add(q, "quic")
		h := setup
		h.P99ms = rtt + 1.5
		add(h, "h2")
	}
	for i := range recs {
		r := &recs[i]
		if r.LossPct == 0 && r.Workload != "setup" && r.System != "direct" {
			r.CPUPerGbit = 2.0
			if r.System == "quic" {
				r.CPUPerGbit = 2.0 / f[3]
			}
		}
	}
	return recs
}

func withTput(r Record, mbps float64) Record { r.GoodputMbps = mbps; return r }

func summary(t *testing.T, recs, base []Record) string {
	t.Helper()
	var buf bytes.Buffer
	if err := summarize(&buf, recs, base); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// TestTargets: each target of 03 is checked per cell, met and missed.
func TestTargets(t *testing.T) {
	out := summary(t, cells("gh-amd64", [4]float64{1, 2, 1, 1}, 0.9), nil)
	for _, want := range []string{
		"| Single stream against direct (quic) | gh-amd64 RTT 1 ms loss 0 % up ×1 | 90 % | yes |",
		"| 32 streams at 1 % loss: QUIC against h2 | gh-amd64 RTT 80 ms loss 1 % down ×32 | 2.00 × | yes |",
		"| Added setup latency p99 (h2) | gh-amd64 RTT 1 ms loss 0 % setup | +0.50 ms | yes |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	out = summary(t, cells("gh-amd64", [4]float64{1, 1.2, 1, 1}, 0.7), nil)
	for _, want := range []string{
		"| Single stream against direct (h2) | gh-amd64 RTT 80 ms loss 0 % down ×1 | 70 % | **no** |",
		"| 32 streams at 1 % loss: QUIC against h2 | gh-amd64 RTT 1 ms loss 1 % up ×32 | 1.20 × | **no** |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
}

// TestSummarizeMarksRunners: runner results say they are not the reference testbed's.
func TestSummarizeMarksRunners(t *testing.T) {
	if out := summary(t, cells("gh-arm64", [4]float64{1, 1, 1, 1}, 1), nil); !strings.Contains(out, "Not the reference testbed** (gh-arm64)") {
		t.Fatal("runner output not marked")
	}
	if out := summary(t, cells("ref-x86", [4]float64{1, 1, 1, 1}, 1), nil); strings.Contains(out, "Not the reference testbed") {
		t.Fatal("reference-testbed output marked")
	}
	if err := summarize(&bytes.Buffer{}, nil, nil); err == nil {
		t.Fatal("a summary of nothing")
	}
}

// TestRegressions: a cell more than 10 % worse than the baseline is listed, in the direction of
// its metric; one within the margin is not.
func TestRegressions(t *testing.T) {
	base := cells("gh-amd64", [4]float64{1, 1, 1, 1}, 1)
	if out := summary(t, cells("gh-amd64", [4]float64{1, 1, 1, 1.05}, 0.95), base); !strings.Contains(out, "no cell more than 10 % worse") {
		t.Errorf("within the margin:\n%s", out)
	}
	// QUIC's single-stream throughput down 20 %; its CPU per Gbit/s up 25 % (f = 0.8 halves the
	// favour): both are regressions, h2's unchanged cells are not.
	out := summary(t, cells("gh-amd64", [4]float64{0.8, 1, 1, 0.8}, 1), base)
	for _, want := range []string{
		"| Single-stream throughput (Mbit/s) | gh-amd64 RTT 1 ms loss 0 % down ×1 | quic | 1e+03 | 800 | -20 % |",
		"| CPU per Gbit/s (CPU s per Gbit) | gh-amd64 RTT 1 ms loss 0 % down ×1 | quic | 2 | 2.5 | +25 % |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "| h2 |") {
		t.Errorf("an unchanged cell listed:\n%s", out)
	}
}

// TestOtherWorkloads: the workloads without a transport table each get a row.
func TestOtherWorkloads(t *testing.T) {
	recs := []Record{
		{Testbed: "gh-amd64", System: "quic", Workload: "udp", Size: 1400, Rate: 2000, PPS: 1990, UDPLossPct: 0.5, OversizeShare: 1},
		{Testbed: "gh-amd64", System: "h2", Workload: "changes", Routes: 200, ApplyP50s: 0.3, ApplyP99s: 0.9, Conns: 8},
		{Testbed: "gh-amd64", System: "quic", Workload: "kill-gateway", RecoveryS: 3.2, Lost: 8, Conns: 8},
		{Testbed: "gh-amd64", System: "quic", Workload: "idle", Connectors: 20, DurationS: 30, MemoryMiB: map[string]float64{"gateway": 64, "gateway_without": 40},
			CPUs: map[string]float64{"gateway": 0.3}},
		{Testbed: "gh-amd64", System: "h2", Workload: "vb18", Share: map[string]float64{"before": 0.5, "blocked": 0.1}},
	}
	out := summary(t, recs, nil)
	for _, want := range []string{
		"| UDP, 1400 B at 2000/s | quic | 1990 /s back, loss 0.50 %, 100 % on the oversize path |",
		"| 1 change/s, 200 routes | h2 | apply p50 0.30 s, p99 0.90 s; 0 of 8 held connections lost |",
		"| SIGKILL gateway under load | quic | answers again after 3.2 s; 8 of 8 held connections lost |",
		"| 20 idle connectors | quic | gateway 64 MiB (40 MiB without them), 0.010 CPU s/s |",
		"| VB-18: new connections to a blocked connector | h2 | 50 % before, 10 % while its session is blocked |",
		"| Snapshot apply p99 (h2, 200 routes, not 1 000) | gh-amd64 RTT 0 ms | 0.90 s | yes |",
		"| Resets on unchanged routes during changes (h2) | gh-amd64 RTT 0 ms | 0 | yes |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
}

func TestReadRecordsRejectsGarbage(t *testing.T) {
	if _, err := readRecords(strings.NewReader("{\"system\":\"quic\"}\nnot json\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("got %v", err)
	}
	recs, err := readRecords(strings.NewReader("\n{\"system\":\"h2\"}\n\n"))
	if err != nil || len(recs) != 1 {
		t.Fatalf("blank lines: %v, %d records", err, len(recs))
	}
}

func TestMedian(t *testing.T) {
	if m := median([]float64{3, 1, 2}); m != 2 {
		t.Fatal(m)
	}
	if m := median([]float64{4, 1, 2, 3}); m != 2.5 {
		t.Fatal(m)
	}
	if m := median(nil); m == m { // NaN
		t.Fatal("median of nothing is not NaN")
	}
}

// TestSumMetrics: samples of a name are summed over their labels; other names, comments and a
// name that only starts like a wanted one do not count; a sample without a number is an error.
func TestSumMetrics(t *testing.T) {
	text := `# HELP process_cpu_seconds_total Total user and system CPU time.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 12.5
rpmgr_udp_oversize_total{route="a"} 3
rpmgr_udp_oversize_total{route="b",x="}"} 4 1700000000000
rpmgr_udp_oversize_total_extra 100
rpmgr_agent_applied_revision 41
`
	got, err := sumMetrics(strings.NewReader(text), []string{"process_cpu_seconds_total", "rpmgr_udp_oversize_total", "missing"})
	if err != nil || got["process_cpu_seconds_total"] != 12.5 || got["rpmgr_udp_oversize_total"] != 7 || got["missing"] != 0 || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := sumMetrics(strings.NewReader("missing {a=\"b\"}\n"), []string{"missing"}); err == nil {
		t.Fatal("a sample without a value")
	}
}

func TestMeasureRefuses(t *testing.T) {
	for _, r := range []Record{{Workload: "sideways"}, {Workload: "http"}} {
		if err := measure(context.Background(), &r, loadArgs{target: "127.0.0.1:1"}); !errors.Is(err, errUsage) {
			t.Errorf("%s: %v", r.Workload, err)
		}
	}
}

func TestShares(t *testing.T) {
	s := shares(map[string]int{"con1": 3, "con2": 1})
	if s["con1"] != 0.75 || s["con2"] != 0.25 {
		t.Fatal(s)
	}
	if len(shares(map[string]int{})) != 0 {
		t.Fatal("shares of nothing")
	}
}
