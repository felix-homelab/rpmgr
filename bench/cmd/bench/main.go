// SPDX-License-Identifier: Apache-2.0

// Command bench is the benchmark suite (docs/12-testing-and-quality.md, "Benchmarks"): the harness
// of spike S1 (tag spike/s1) driving real rpmgr processes instead of the spike's tunnel.
//
//	bench run       -out results.jsonl …   the matrix, on Docker: build, start, measure, stop
//	bench service   -name con1             the service beside each connector
//	bench load      -workload … -target …  one measurement, JSON to stdout (inside a container)
//	bench metrics   -url … -names …        sums of Prometheus metrics, JSON to stdout
//	bench ready     -url … -duration …     waits until a URL answers 200
//	bench summarize -in results.jsonl [-baseline base.jsonl]   Markdown tables, the targets of 03
//	                                       and the regression check against a baseline
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(ctx, os.Args[2:])
	case "service":
		err = cmdService(os.Args[2:])
	case "load":
		err = cmdLoad(ctx, os.Args[2:])
	case "metrics":
		err = cmdMetrics(os.Args[2:])
	case "ready":
		err = cmdReady(ctx, os.Args[2:])
	case "summarize":
		err = cmdSummarize(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: bench run|service|load|metrics|ready|summarize [flags]")
	os.Exit(2)
}

var errUsage = errors.New("bench: invalid arguments")
