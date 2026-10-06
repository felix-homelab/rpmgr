// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

// cells builds one repetition of every cell the rule reads, with the given QUIC/h2 factors per
// metric (oriented: above 1 favours QUIC).
func cells(testbed string, f [4]float64) []Record {
	var recs []Record
	add := func(r Record, sys string) { r.Testbed, r.System = testbed, sys; recs = append(recs, r) }
	for _, rtt := range []float64{1, 80} {
		for _, dir := range []string{"up", "down"} {
			base := Record{RTTms: rtt, Workload: dir, Streams: 1}
			add(withTput(base, 900), "direct")
			add(withTput(base, 800*f[0]), "quic")
			add(withTput(base, 800), "h2")
			lossy := Record{RTTms: rtt, LossPct: 1, Workload: dir, Streams: 32}
			add(withTput(lossy, 600*f[1]), "quic")
			add(withTput(lossy, 600), "h2")
		}
		setup := Record{RTTms: rtt, Workload: "setup"}
		setup.P99ms = rtt + 5
		add(setup, "direct")
		q := setup
		q.P99ms = (rtt + 5) / f[2]
		add(q, "quic")
		add(setup, "h2")
	}
	for i := range recs {
		r := &recs[i]
		if r.RTTms == 1 && r.LossPct == 0 && r.Workload != "setup" && r.System != "direct" {
			r.CPUPerGbit = 2.0
			if r.System == "quic" {
				r.CPUPerGbit = 2.0 / f[3]
			}
		}
	}
	return recs
}

func withTput(r Record, mbps float64) Record { r.GoodputMbps = mbps; return r }

func TestRule(t *testing.T) {
	tests := []struct {
		name string
		f    [4]float64
		want string
		perM string
	}{
		{"QUIC wins all", [4]float64{1.2, 2, 1.5, 1.1}, "quic", "quic quic quic quic"},
		{"h2 wins three", [4]float64{0.8, 2, 0.9, 0.5}, "h2", "h2 quic h2 h2"},
		{"two each keeps QUIC", [4]float64{0.8, 2, 1.5, 0.5}, "quic", "h2 quic quic h2"},
		{"all within the margin is a tie, QUIC kept", [4]float64{1.04, 0.96, 1.0, 1.049}, "quic", "tie tie tie tie"},
		{"just over 5 % counts as a win", [4]float64{1.051, 1 / 1.051, 1, 1}, "quic", "quic h2 tie tie"},
		{"one h2 win against ties flips the default", [4]float64{1, 1, 1, 0.5}, "h2", "tie tie tie h2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, _, err := applyRule(cells("ref-x86", tc.f))
			if err != nil {
				t.Fatal(err)
			}
			if v.Default != tc.want || strings.Join(v.PerMetric, " ") != tc.perM {
				t.Fatalf("default %s, per metric %v; want %s, %s", v.Default, v.PerMetric, tc.want, tc.perM)
			}
		})
	}
}

// TestRulePoolsTestbeds: per-metric means combine every testbed, so one testbed cannot decide
// alone.
func TestRulePoolsTestbeds(t *testing.T) {
	recs := append(cells("ref-x86", [4]float64{1.3, 1.3, 1.3, 1.3}), cells("ref-pi5", [4]float64{0.7, 0.7, 0.7, 0.7})...)
	v, gms, err := applyRule(recs)
	if err != nil {
		t.Fatal(err)
	}
	for i, gm := range gms {
		if gm < 0.95 || gm > 1.05 {
			t.Fatalf("metric %d: pooled mean %.3f, want ≈ 0.954 (tie)", i, gm)
		}
	}
	if v.Default != "quic" {
		t.Fatalf("default %s", v.Default)
	}
}

func TestRuleFailsWithoutData(t *testing.T) {
	recs := cells("ref-x86", [4]float64{1, 1, 1, 1})
	var noSetup []Record
	for _, r := range recs {
		if r.Workload != "setup" {
			noSetup = append(noSetup, r)
		}
	}
	if _, _, err := applyRule(noSetup); err == nil {
		t.Fatal("rule applied without any setup-latency cell")
	}
}

func TestSummarizeMarksDryRun(t *testing.T) {
	var buf bytes.Buffer
	if err := summarize(&buf, cells("docker-dryrun", [4]float64{1, 1, 1, 1})); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "do not decide the rule") {
		t.Fatal("dry-run output not marked as non-deciding")
	}
	buf.Reset()
	if err := summarize(&buf, cells("ref-x86", [4]float64{1, 1, 1, 1})); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "do not decide the rule") {
		t.Fatal("reference-testbed output marked as non-deciding")
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
