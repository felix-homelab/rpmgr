// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/bench/load"
)

// cmdService runs the services beside a connector: sink, source, echo, who, UDP echo and HTTP.
func cmdService(args []string) error {
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	name := fs.String("name", "", "the name the who service answers with")
	sink := fs.String("sink", ":7001", "sink address")
	source := fs.String("source", ":7002", "source address")
	echo := fs.String("echo", ":7003", "echo address")
	who := fs.String("who", ":7004", "who address")
	udp := fs.String("udp", ":7008", "UDP echo address")
	httpAddr := fs.String("http", ":7080", "HTTP upstream address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	errc := make(chan error, 6)
	for addr, serve := range map[string]func(net.Listener) error{*sink: load.ServeSink, *source: load.ServeSource, *echo: load.ServeEcho,
		*httpAddr: load.ServeHTTP, *who: func(ln net.Listener) error { return load.ServeWho(ln, *name) }} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go func() { errc <- serve(ln) }()
	}
	pc, err := net.ListenPacket("udp", *udp)
	if err != nil {
		return err
	}
	go func() { errc <- load.ServeUDPEcho(pc) }()
	return <-errc
}

// cmdMetrics prints the sum over all label sets of each named metric at a Prometheus endpoint, as
// a JSON object; a metric the endpoint does not have is 0. With -above it instead waits until the
// first name's sum exceeds that value and prints when it saw that, as at_unix_ns.
func cmdMetrics(args []string) error {
	fs := flag.NewFlagSet("metrics", flag.ContinueOnError)
	url := fs.String("url", "", "the /metrics URL")
	names := fs.String("names", "", "metric names, comma-separated")
	above := fs.Float64("above", math.NaN(), "wait until the first metric exceeds this value")
	timeout := fs.Duration("timeout", 20*time.Second, "how long to wait (-above)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *names == "" {
		return fmt.Errorf("%w: metrics needs -url and -names", errUsage)
	}
	list := strings.Split(*names, ",")
	if math.IsNaN(*above) {
		sums, err := scrape(*url, list)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(sums)
	}
	for end := time.Now().Add(*timeout); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		sums, err := scrape(*url, list[:1])
		if err != nil {
			return err
		}
		if v := sums[list[0]]; v > *above {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"at_unix_ns": time.Now().UnixNano(), "value": v})
		}
	}
	return fmt.Errorf("bench: %s stayed at most %g for %s", list[0], *above, *timeout)
}

func scrape(url string, names []string) (map[string]float64, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url) //nolint:gosec // G107: the benchmark's own admin listener
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bench: %s: %s", url, resp.Status)
	}
	return sumMetrics(resp.Body, names)
}

// sumMetrics reads the Prometheus text format and sums the samples of each name.
func sumMetrics(r io.Reader, names []string) (map[string]float64, error) {
	out := map[string]float64{}
	for _, n := range names {
		out[n] = 0
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rest, _ := strings.Cut(line, " ")
		if i := strings.IndexByte(name, '{'); i >= 0 {
			name = name[:i]
			if j := strings.LastIndexByte(line, '}'); j >= 0 {
				rest = line[j+1:]
			}
		}
		if _, ok := out[name]; !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return nil, fmt.Errorf("bench: a sample without a value: %q", line)
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("bench: %q: %w", line, err)
		}
		out[name] += v
	}
	return out, sc.Err()
}

// cmdReady waits until url answers 200.
func cmdReady(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ready", flag.ContinueOnError)
	url := fs.String("url", "", "the URL, e.g. an admin listener's /readyz")
	d := fs.Duration("duration", time.Minute, "how long to wait")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c := &http.Client{Timeout: 2 * time.Second}
	var last error
	for end := time.Now().Add(*d); time.Now().Before(end) && ctx.Err() == nil; time.Sleep(200 * time.Millisecond) {
		resp, err := c.Get(*url) //nolint:gosec // G107: the benchmark's own admin listener
		if err != nil {
			last = err
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		last = errors.New(resp.Status)
	}
	if last == nil {
		last = ctx.Err()
	}
	return fmt.Errorf("bench: %s not ready after %s: %w", *url, *d, last)
}
