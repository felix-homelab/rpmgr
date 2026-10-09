// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/felix-homelab/rpmgr/bench/load"
)

// Record is one measurement, one JSON line in results.jsonl.
type Record struct {
	Testbed  string  `json:"testbed"` // gh-amd64, gh-arm64, local, …; ref-… only on the reference testbed (VB-20)
	System   string  `json:"system"`  // direct, quic, h2
	RTTms    float64 `json:"rtt_ms"`
	LossPct  float64 `json:"loss_pct"`
	GSO      string  `json:"gso,omitempty"` // on, off
	Rep      int     `json:"rep"`
	Workload string  `json:"workload"` // up, down, setup, http, udp, hold, who, changes, kill-gateway, kill-controller, idle, vb18

	Streams     int     `json:"streams,omitempty"`
	DurationS   float64 `json:"duration_s"`
	Bytes       int64   `json:"bytes,omitempty"`
	GoodputMbps float64 `json:"goodput_mbps,omitempty"`
	Rate        int     `json:"rate,omitempty"`
	Conns       int     `json:"conns,omitempty"`
	P50ms       float64 `json:"p50_ms,omitempty"`
	P99ms       float64 `json:"p99_ms,omitempty"`
	RPS         float64 `json:"rps,omitempty"`

	Size          int     `json:"size,omitempty"` // UDP payload
	Sent          int     `json:"sent,omitempty"`
	PPS           float64 `json:"pps,omitempty"`
	UDPLossPct    float64 `json:"udp_loss_pct,omitempty"`
	OversizeShare float64 `json:"oversize_share,omitempty"` // datagrams on the oversize path ÷ sent

	Routes     int     `json:"routes,omitempty"`      // changes: routes in the snapshot
	ApplyP50s  float64 `json:"apply_p50_s,omitempty"` // changes: commit until the gateway applied it
	ApplyP99s  float64 `json:"apply_p99_s,omitempty"`
	Lost       int     `json:"lost,omitempty"`       // held connections that failed
	RecoveryS  float64 `json:"recovery_s,omitempty"` // kill: until the route answers again
	Connectors int     `json:"connectors,omitempty"` // idle: idle connectors on the gateway

	MemoryMiB map[string]float64 `json:"memory_mib,omitempty"`
	Share     map[string]float64 `json:"share,omitempty"` // who, vb18: share of new connections per connector

	Failures   int                `json:"failures"`
	CPUs       map[string]float64 `json:"cpu_s,omitempty"`
	CPUPerGbit float64            `json:"cpu_s_per_gbit,omitempty"`
	Time       string             `json:"time"`
}

// loadArgs are the parameters of one measurement.
type loadArgs struct {
	target, url, ca                     string
	streams, rate, size, workers, conns int
	dur                                 time.Duration
}

func cmdLoad(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	var a loadArgs
	fs.StringVar(&a.target, "target", "", "host:port to connect to")
	workload := fs.String("workload", "up", "up, down, setup, http, udp, hold or who")
	fs.IntVar(&a.streams, "streams", 1, "parallel connections (up, down)")
	fs.DurationVar(&a.dur, "duration", 10*time.Second, "measurement time")
	fs.IntVar(&a.rate, "rate", 1000, "connections (setup, who) or datagrams (udp) per second")
	fs.IntVar(&a.size, "size", 1200, "UDP payload in bytes")
	fs.IntVar(&a.workers, "workers", 32, "concurrent requests (http)")
	fs.StringVar(&a.url, "url", "", "the URL to get (http); -target is the gateway it is sent to")
	fs.StringVar(&a.ca, "ca", "", "PEM file of the CA the route's certificate chains to (http)")
	fs.IntVar(&a.conns, "conns", 8, "connections to hold (hold)")
	r := Record{}
	fs.StringVar(&r.Testbed, "testbed", "local", "label: testbed")
	fs.StringVar(&r.System, "system", "direct", "label: direct, quic or h2")
	fs.Float64Var(&r.RTTms, "rtt", 0, "label: netem RTT in ms")
	fs.Float64Var(&r.LossPct, "loss", 0, "label: netem loss in %")
	fs.IntVar(&r.Rep, "rep", 1, "label: repetition")
	fs.StringVar(&r.GSO, "gso", "", "label: on or off")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if a.target == "" {
		return fmt.Errorf("%w: load needs -target", errUsage)
	}
	r.Workload, r.DurationS = *workload, a.dur.Seconds()
	if err := measure(ctx, &r, a); err != nil {
		return err
	}
	r.Time = time.Now().UTC().Format(time.RFC3339)
	return json.NewEncoder(os.Stdout).Encode(r)
}

// measure runs one workload and fills r.
func measure(ctx context.Context, r *Record, a loadArgs) error {
	switch r.Workload {
	case "up", "down":
		res, err := load.Throughput(ctx, a.target, r.Workload, a.streams, a.dur)
		if err != nil {
			return err
		}
		r.Streams, r.Bytes, r.GoodputMbps, r.Failures = a.streams, res.Bytes, res.Mbps(), res.Failures
	case "setup":
		res, err := load.Setup(ctx, a.target, a.rate, a.dur)
		if err != nil {
			return err
		}
		r.Rate, r.Conns, r.Failures = a.rate, len(res.Latencies), res.Failures
		r.P50ms, r.P99ms = res.Percentile(50), res.Percentile(99)
	case "http":
		if a.ca == "" {
			return fmt.Errorf("%w: http needs -ca", errUsage)
		}
		pem, err := os.ReadFile(a.ca)
		if err != nil {
			return err
		}
		res, err := load.HTTP(ctx, a.target, a.url, pem, a.workers, a.dur)
		if err != nil {
			return err
		}
		r.Conns, r.Failures, r.RPS = a.workers, res.Failures, res.RPS()
		r.P50ms, r.P99ms = res.Percentile(50), res.Percentile(99)
	case "udp":
		res, err := load.UDP(ctx, a.target, a.size, a.rate, a.dur)
		if err != nil {
			return err
		}
		r.Size, r.Rate, r.Sent, r.PPS, r.UDPLossPct = a.size, a.rate, res.Sent, res.PPS(), res.Loss()
		r.Failures = res.Sent - res.Received
	case "hold":
		res, err := load.Hold(ctx, a.target, a.conns, a.dur)
		if err != nil {
			return err
		}
		r.Conns, r.Lost = res.Conns, res.Lost
	case "who":
		res, err := load.Who(ctx, a.target, a.rate, a.dur)
		if err != nil {
			return err
		}
		r.Rate, r.Failures, r.Share = a.rate, res.Failures, shares(res.By)
		for _, n := range res.By {
			r.Conns += n
		}
	default:
		return fmt.Errorf("%w: unknown workload %q", errUsage, r.Workload)
	}
	return nil
}

// shares turns counts into fractions of their total.
func shares(by map[string]int) map[string]float64 {
	total := 0
	for _, n := range by {
		total += n
	}
	out := map[string]float64{}
	for k, n := range by {
		if total > 0 {
			out[k] = float64(n) / float64(total)
		}
	}
	return out
}
