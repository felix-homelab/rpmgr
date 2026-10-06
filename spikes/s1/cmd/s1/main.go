// SPDX-License-Identifier: Apache-2.0

// Command s1 is the S1 transport benchmark: QUIC versus TLS + reverse HTTP/2 against a direct
// TCP connection (docs/13-roadmap.md#phase-0--spikes, docs/12-testing-and-quality.md#benchmarks).
//
//	s1 certs     -dir DIR                               test PKI
//	s1 service   -sink :7001 -source :7002 -echo :7003  upstream service
//	s1 gateway   -certs DIR -tunnel :4443 -route 9001=sink …
//	s1 connector -certs DIR -gateway HOST:4443 -transport quic|h2 -route sink=HOST:7001 …
//	s1 load      -target HOST:PORT -workload up|down|setup …   one measurement, JSON to stdout
//	s1 summarize -in results.jsonl                      tables and the D19 rule
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/felix-homelab/rpmgr/spikes/s1/internal/load"
	"github.com/felix-homelab/rpmgr/spikes/s1/internal/pki"
	"github.com/felix-homelab/rpmgr/spikes/s1/internal/tunnel"
)

const (
	trustDomain = "rpmgr-bench"
	gatewayID   = "gw1"
	connectorID = "con1"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "certs":
		err = cmdCerts(os.Args[2:])
	case "service":
		err = cmdService(os.Args[2:])
	case "gateway":
		err = cmdGateway(ctx, os.Args[2:])
	case "connector":
		err = cmdConnector(ctx, os.Args[2:])
	case "load":
		err = cmdLoad(ctx, os.Args[2:])
	case "summarize":
		err = cmdSummarize(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "s1:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: s1 certs|service|gateway|connector|load|summarize [flags]")
	os.Exit(2)
}

type routeFlags map[string]string

func (r routeFlags) String() string { return fmt.Sprint(map[string]string(r)) }
func (r routeFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" || val == "" {
		return fmt.Errorf("route %q is not KEY=VALUE", v)
	}
	r[k] = val
	return nil
}

func cmdCerts(args []string) error {
	fs := flag.NewFlagSet("certs", flag.ExitOnError)
	dir := fs.String("dir", "certs", "output directory")
	_ = fs.Parse(args)
	return pki.Generate(*dir, trustDomain, gatewayID, connectorID)
}

func cmdService(args []string) error {
	fs := flag.NewFlagSet("service", flag.ExitOnError)
	sink := fs.String("sink", ":7001", "sink address")
	source := fs.String("source", ":7002", "source address")
	echo := fs.String("echo", ":7003", "echo address")
	_ = fs.Parse(args)
	errc := make(chan error, 3)
	for addr, serve := range map[string]func(net.Listener) error{*sink: load.ServeSink, *source: load.ServeSource, *echo: load.ServeEcho} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go func() { errc <- serve(ln) }()
	}
	return <-errc
}

func cmdGateway(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	certs := fs.String("certs", "certs", "certificate directory")
	tunnelAddr := fs.String("tunnel", ":4443", "tunnel address (UDP for QUIC, TCP for h2)")
	admin := fs.String("admin", "127.0.0.1:7382", "stats listener")
	routes := routeFlags{}
	fs.Var(routes, "route", "public port to route ID, e.g. 9001=sink (repeatable)")
	_ = fs.Parse(args)
	pool, cert, err := pki.Load(*certs, "gateway")
	if err != nil {
		return err
	}
	tlsConf := pki.ServerConfig(pool, cert, trustDomain)
	g := tunnel.NewGateway()
	qln, err := tunnel.ListenQUIC(*tunnelAddr, tlsConf)
	if err != nil {
		return err
	}
	go func() { _ = g.AcceptQUIC(ctx, qln) }()
	tln, err := net.Listen("tcp", *tunnelAddr)
	if err != nil {
		return err
	}
	t2, err := tunnel.H2Transport()
	if err != nil {
		return err
	}
	go func() { _ = g.AcceptH2(tln, tlsConf, t2) }()
	for port, route := range routes {
		ln, err := net.Listen("tcp", ":"+port)
		if err != nil {
			return err
		}
		go func() { _ = g.ServeRoute(ln, route) }()
	}
	go serveStats(*admin)
	slog.Info("gateway up", "tunnel", *tunnelAddr, "routes", routes)
	<-ctx.Done()
	return nil
}

func cmdConnector(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("connector", flag.ExitOnError)
	certs := fs.String("certs", "certs", "certificate directory")
	gw := fs.String("gateway", "127.0.0.1:4443", "gateway tunnel address")
	transport := fs.String("transport", "quic", "quic or h2")
	h2conns := fs.Int("h2-conns", 2, "TCP connections per gateway on the h2 transport")
	admin := fs.String("admin", "127.0.0.1:7383", "stats listener")
	routes := routeFlags{}
	fs.Var(routes, "route", "route ID to target, e.g. sink=127.0.0.1:7001 (repeatable)")
	_ = fs.Parse(args)
	pool, cert, err := pki.Load(*certs, "connector")
	if err != nil {
		return err
	}
	tlsConf := pki.ClientConfig(pool, cert, pki.Identity{TrustDomain: trustDomain, Role: "gateway", ID: gatewayID})
	c := &tunnel.Connector{Routes: routes}
	go serveStats(*admin)
	errc := make(chan error, *h2conns)
	switch *transport {
	case "quic":
		go func() { errc <- c.RunQUIC(ctx, *gw, tlsConf) }()
	case "h2":
		for range *h2conns {
			go func() { errc <- c.RunH2(ctx, *gw, tlsConf) }()
		}
	default:
		return fmt.Errorf("unknown transport %q", *transport)
	}
	slog.Info("connector up", "transport", *transport, "gateway", *gw)
	defer c.Close()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return nil
	}
}

// Stats is what the gateway and the connector report for the CPU measurement.
type Stats struct {
	CPUSeconds   float64 `json:"cpu_s"`
	RelayedBytes int64   `json:"relayed_bytes"`
	Goroutines   int     `json:"goroutines"`
	HeapBytes    uint64  `json:"heap_bytes"`
}

func currentStats() Stats {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return Stats{
		CPUSeconds:   tv(ru.Utime) + tv(ru.Stime),
		RelayedBytes: tunnel.Counter.Load(),
		Goroutines:   runtime.NumGoroutine(),
		HeapBytes:    ms.HeapInuse,
	}
}

func tv(t syscall.Timeval) float64 { return float64(t.Sec) + float64(t.Usec)/1e6 }

func serveStats(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(currentStats())
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("stats listener", "err", err)
	}
}

func fetchStats(addr string) (Stats, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + addr + "/stats")
	if err != nil {
		return Stats{}, err
	}
	defer resp.Body.Close()
	var s Stats
	return s, json.NewDecoder(resp.Body).Decode(&s)
}
