// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/spikes/s1/internal/load"
)

// Record is one measurement, one JSON line in results.jsonl.
type Record struct {
	Testbed     string             `json:"testbed"` // e.g. docker-dryrun, ref-x86, ref-arm64, ref-pi5
	System      string             `json:"system"`  // direct, quic, h2
	RTTms       float64            `json:"rtt_ms"`
	LossPct     float64            `json:"loss_pct"`
	Rep         int                `json:"rep"`
	Workload    string             `json:"workload"` // up, down, setup
	Streams     int                `json:"streams,omitempty"`
	DurationS   float64            `json:"duration_s"`
	Bytes       int64              `json:"bytes,omitempty"`
	GoodputMbps float64            `json:"goodput_mbps,omitempty"`
	Rate        int                `json:"rate,omitempty"`
	Conns       int                `json:"conns,omitempty"`
	P50ms       float64            `json:"p50_ms,omitempty"`
	P99ms       float64            `json:"p99_ms,omitempty"`
	Failures    int                `json:"failures"`
	CPUs        map[string]float64 `json:"cpu_s,omitempty"`
	CPUPerGbit  float64            `json:"cpu_s_per_gbit,omitempty"`
	Time        string             `json:"time"`
}

func cmdLoad(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	target := fs.String("target", "", "host:port to connect to")
	workload := fs.String("workload", "up", "up, down or setup")
	streams := fs.Int("streams", 1, "parallel connections (up, down)")
	dur := fs.Duration("duration", 10*time.Second, "measurement time")
	rate := fs.Int("rate", 1000, "connections per second (setup)")
	stats := fs.String("stats", "", "role=host:port of the stats listeners, comma-separated")
	r := Record{}
	fs.StringVar(&r.Testbed, "testbed", "local", "label: testbed")
	fs.StringVar(&r.System, "system", "direct", "label: direct, quic or h2")
	fs.Float64Var(&r.RTTms, "rtt", 0, "label: netem RTT in ms")
	fs.Float64Var(&r.LossPct, "loss", 0, "label: netem loss in %")
	fs.IntVar(&r.Rep, "rep", 1, "label: repetition")
	_ = fs.Parse(args)
	if *target == "" {
		return fmt.Errorf("load: -target is required")
	}
	roles := map[string]string{}
	for _, kv := range strings.Split(*stats, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			roles[k] = v
		}
	}
	before := map[string]Stats{}
	for role, addr := range roles {
		s, err := fetchStats(addr)
		if err != nil {
			return fmt.Errorf("stats %s: %w", role, err)
		}
		before[role] = s
	}
	r.Workload, r.Streams, r.DurationS = *workload, *streams, dur.Seconds()
	switch *workload {
	case "up", "down":
		res, err := load.Throughput(ctx, *target, *workload, *streams, *dur)
		if err != nil {
			return err
		}
		r.Bytes, r.GoodputMbps, r.Failures = res.Bytes, res.Mbps(), res.Failures
	case "setup":
		res, err := load.Setup(ctx, *target, *rate, *dur)
		if err != nil {
			return err
		}
		r.Streams = 0
		r.Rate, r.Conns, r.Failures = *rate, len(res.Latencies), res.Failures
		r.P50ms, r.P99ms = res.Percentile(50), res.Percentile(99)
	default:
		return fmt.Errorf("load: unknown workload %q", *workload)
	}
	if len(roles) > 0 {
		r.CPUs = map[string]float64{}
		var cpu float64
		for role, addr := range roles {
			s, err := fetchStats(addr)
			if err != nil {
				return fmt.Errorf("stats %s: %w", role, err)
			}
			d := s.CPUSeconds - before[role].CPUSeconds
			r.CPUs[role] = d
			cpu += d
		}
		if gbit := float64(r.Bytes) * 8 / 1e9; gbit > 0 {
			r.CPUPerGbit = cpu / gbit
		}
	}
	r.Time = time.Now().UTC().Format(time.RFC3339)
	return json.NewEncoder(os.Stdout).Encode(r)
}
