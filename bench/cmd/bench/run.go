// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The topology (compose.yaml): the controller, the gateway, two connectors with the service beside
// each, a host for idle connectors and the client. netem shapes only the gateway↔connector link,
// as in spike S1: half the RTT and the full loss on each side. "direct" is a plain TCP connection
// over that link, from the gateway host to the service beside con1.
const (
	project  = "rpmgr-bench"
	gwPub    = "10.232.1.20"
	gwLink   = "10.232.2.20"
	con1Link = "10.232.2.31"
	con2Link = "10.232.2.32"
	ctlURL   = "https://ctl:8443"
	bootDir  = "/var/lib/rpmgr"
	ctlBoot  = bootDir + "/controller.yaml"
	policy   = "version: 1\nallow_targets:\n  - cidr: 127.0.0.1/32\n    ports: [7001, 7002, 7003, 7004, 7008, 7080]\n"
)

var nodes = []string{"ctl", "gw", "con1", "con2", "idle", "client"}

// transportRoutes are the routes of one transport: the tcp ports of the sink, source and echo, the
// UDP echo, the who route both connectors serve and the sink only con2 serves (VB-18), and the
// http route's host name.
type transportRoutes struct {
	sink, source, echo, udp, who, blockedSink int
	host                                      string
}

var routesOf = map[string]transportRoutes{
	"quic": {9001, 9002, 9003, 9005, 9201, 9211, "bench-quic.bench.test"},
	"h2":   {9101, 9102, 9103, 9105, 9202, 9212, "bench-h2.bench.test"},
}

// routesPerTransport is how many routes routes() seeds for each transport.
const routesPerTransport = 7

// runOpts are the parameters of a run.
type runOpts struct {
	out, testbed, gso    string
	rtts, losses         []float64
	reps                 int
	dur, setupDur, extra time.Duration
	rate, udpRate        int
	routes, idle         int
	workloads            map[string]bool
	keep                 bool
}

var allWorkloads = []string{"throughput", "setup", "http", "udp", "vb18", "changes", "kill", "idle"}

func parseRunFlags(args []string) (runOpts, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var o runOpts
	var rtts, losses, workloads string
	fs.StringVar(&o.out, "out", "results.jsonl", "results file, appended to; the run's details go next to it, .meta.txt")
	fs.StringVar(&o.testbed, "testbed", "local", "label: gh-amd64, gh-arm64, local, …")
	fs.StringVar(&o.gso, "gso", "on", "on, or off to run QUIC without GSO")
	fs.StringVar(&rtts, "rtts", "1,80", "RTTs of the gateway↔connector link in ms, comma-separated")
	fs.StringVar(&losses, "losses", "0,1", "loss rates of the link in %, comma-separated")
	fs.IntVar(&o.reps, "reps", 3, "repetitions of each throughput and setup cell")
	fs.DurationVar(&o.dur, "duration", 10*time.Second, "time of each throughput, HTTP and UDP measurement")
	fs.DurationVar(&o.setupDur, "setup-duration", 5*time.Second, "time of each setup-latency measurement")
	fs.DurationVar(&o.extra, "extra-duration", 30*time.Second, "time of the VB-18, changes and idle workloads")
	fs.IntVar(&o.rate, "rate", 1000, "connections per second of the setup-latency workload")
	fs.IntVar(&o.udpRate, "udp-rate", 2000, "datagrams per second of the UDP workload")
	fs.IntVar(&o.routes, "routes", 1000, "routes in the snapshot while one changes per second")
	fs.IntVar(&o.idle, "idle", 20, "idle connectors on the gateway (03 asks for 10 000; a runner holds a few)")
	fs.StringVar(&workloads, "workloads", strings.Join(allWorkloads, ","), "workloads to run, comma-separated")
	fs.BoolVar(&o.keep, "keep", false, "leave the containers running afterwards")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	var err error
	if o.rtts, err = floats(rtts); err != nil {
		return o, err
	}
	if o.losses, err = floats(losses); err != nil {
		return o, err
	}
	o.workloads = map[string]bool{}
	for _, w := range strings.Split(workloads, ",") {
		if !slices.Contains(allWorkloads, w) {
			return o, fmt.Errorf("%w: unknown workload %q; there are %s", errUsage, w, strings.Join(allWorkloads, ", "))
		}
		o.workloads[w] = true
	}
	switch {
	case o.gso != "on" && o.gso != "off":
		return o, fmt.Errorf("%w: -gso is on or off", errUsage)
	case o.reps < 1 || o.rate < 1 || o.udpRate < 1 || o.routes < 1 || o.idle < 1:
		return o, fmt.Errorf("%w: -reps, -rate, -udp-rate, -routes and -idle must be at least 1", errUsage)
	case o.dur <= 0 || o.setupDur <= 0 || o.extra < 2*time.Second:
		return o, fmt.Errorf("%w: -duration and -setup-duration must be positive, -extra-duration at least 2s", errUsage)
	}
	return o, nil
}

func floats(s string) ([]float64, error) {
	var out []float64
	for _, f := range strings.Split(s, ",") {
		v, err := strconv.ParseFloat(strings.TrimSpace(f), 64)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("%w: %q is not a number of at least 0", errUsage, f)
		}
		out = append(out, v)
	}
	return out, nil
}

// bench is one run on Docker.
type bench struct {
	o           runOpts
	repo, here  string // the repository and bench/
	run         string // the containers' /var/lib/rpmgr directories
	pin         string
	links       map[string]string // the interface on the gateway↔connector link, per node
	out         *os.File
	rtt, loss   float64 // the link's current shape
	routeCount  int
	idleStarted bool
}

func (b *bench) log(format string, a ...any) {
	fmt.Fprintf(os.Stderr, time.Now().Format("15:04:05 ")+format+"\n", a...)
}

func cmdRun(ctx context.Context, args []string) error {
	o, err := parseRunFlags(args)
	if err != nil {
		return err
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	here := filepath.Join(wd, "bench")
	if _, err := os.Stat(filepath.Join(here, "compose.yaml")); err != nil {
		return fmt.Errorf("bench: run from the repository's root: %w", err)
	}
	b := &bench{o: o, repo: wd, here: here, links: map[string]string{}}
	if b.out, err = os.OpenFile(o.out, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err != nil { //nolint:gosec // G304: the operator's results file
		return err
	}
	defer func() { _ = b.out.Close() }()
	if b.run, err = os.MkdirTemp("", "rpmgr-bench-"); err != nil {
		return err
	}
	defer func() {
		if !o.keep {
			_, _ = b.compose(context.Background(), "down", "--volumes", "--timeout", "2")
			_ = os.RemoveAll(b.run)
		}
	}()
	if err := b.setUp(ctx); err != nil {
		b.dumpLogs()
		return err
	}
	if err := b.meta(ctx); err != nil {
		return err
	}
	if err := b.matrix(ctx); err != nil {
		b.dumpLogs()
		return err
	}
	return nil
}

// command runs docker with args and returns its output.
func (b *bench) command(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204: the benchmark's own commands
	cmd.Dir = b.here
	cmd.Env = append(os.Environ(), "BENCH_RUN="+b.run, "BENCH_UID="+strconv.Itoa(os.Getuid()), "BENCH_GID="+strconv.Itoa(os.Getgid()))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("docker %s: %w\n%s", strings.Join(args, " "), err, out.String())
	}
	return out.String(), nil
}

func (b *bench) compose(ctx context.Context, args ...string) (string, error) {
	return b.command(ctx, append([]string{"compose", "--project-name", project, "--file", filepath.Join(b.here, "compose.yaml")}, args...)...)
}

func (b *bench) in(ctx context.Context, node string, args ...string) (string, error) {
	return b.compose(ctx, append([]string{"exec", "-T", node}, args...)...)
}

func (b *bench) asRoot(ctx context.Context, node string, args ...string) (string, error) {
	return b.compose(ctx, append([]string{"exec", "-T", "--user", "0", node}, args...)...)
}

func (b *bench) seed(ctx context.Context, verb string, args ...string) (string, error) {
	out, err := b.in(ctx, "ctl", append([]string{"rpmgr", "testseed", verb, "--config", ctlBoot}, args...)...)
	return strings.TrimSpace(out), err
}

// seedRoute creates a route of kind (route, udp-route, http-route) on the benchmark's gateway group.
func (b *bench) seedRoute(ctx context.Context, kind string, args ...string) error {
	_, err := b.seed(ctx, kind, append([]string{"--group", "bench"}, args...)...)
	return err
}

func (b *bench) writeFile(node, name, data string) error {
	return os.WriteFile(filepath.Join(b.run, node, name), []byte(data), 0o600)
}

// start runs an rpmgr role in node in the background, logging to <config>.log; GSO off sets
// quic-go's switch for it.
func (b *bench) start(ctx context.Context, node, role, config string) error {
	args := []string{"exec", "-d", "-T"}
	if b.o.gso == "off" {
		args = append(args, "--env", "QUIC_GO_DISABLE_GSO=true")
	}
	cmd := fmt.Sprintf("exec rpmgr %s --config %s/%s.yaml >> %s/%s.log 2>&1", role, bootDir, config, bootDir, config)
	_, err := b.compose(ctx, append(args, node, "sh", "-c", cmd)...)
	return err
}

func (b *bench) ready(ctx context.Context, node string, port int) error {
	_, err := b.in(ctx, node, "bench", "ready", "-url", fmt.Sprintf("http://127.0.0.1:%d/readyz", port), "-duration", "60s")
	return err
}

// metrics reads metrics from the admin listener on node's port.
func (b *bench) metrics(ctx context.Context, node string, port int, names ...string) (map[string]float64, error) {
	out, err := b.in(ctx, node, "bench", "metrics", "-url", fmt.Sprintf("http://127.0.0.1:%d/metrics", port), "-names", strings.Join(names, ","))
	if err != nil {
		return nil, err
	}
	m := map[string]float64{}
	return m, json.Unmarshal([]byte(out), &m)
}

// load runs one measurement from node with the run's labels.
func (b *bench) load(ctx context.Context, node, system string, rep int, args ...string) (Record, error) {
	labels := []string{"-testbed", b.o.testbed, "-system", system, "-rtt", fmtFloat(b.rtt), "-loss", fmtFloat(b.loss), "-rep",
		strconv.Itoa(rep), "-gso", b.o.gso}
	out, err := b.in(ctx, node, append(append([]string{"bench", "load"}, labels...), args...)...)
	if err != nil {
		return Record{}, err
	}
	var r Record
	return r, json.Unmarshal([]byte(out), &r)
}

// record is a Record of the run's labels for the workloads the orchestration measures itself.
func (b *bench) record(system, workload string) Record {
	return Record{Testbed: b.o.testbed, System: system, RTTms: b.rtt, LossPct: b.loss, GSO: b.o.gso, Rep: 1, Workload: workload,
		DurationS: b.o.extra.Seconds()}
}

func (b *bench) write(r Record) error {
	if r.Time == "" {
		r.Time = time.Now().UTC().Format(time.RFC3339)
	}
	b.log("%s %s: %s", r.System, r.Workload, brief(r))
	return json.NewEncoder(b.out).Encode(r)
}

func brief(r Record) string {
	switch {
	case r.GoodputMbps > 0:
		return fmt.Sprintf("×%d %.0f Mbit/s, %d failed", r.Streams, r.GoodputMbps, r.Failures)
	case r.RPS > 0:
		return fmt.Sprintf("%.0f requests/s, p99 %.1f ms", r.RPS, r.P99ms)
	case r.P99ms > 0:
		return fmt.Sprintf("p50 %.2f ms, p99 %.2f ms, %d failed", r.P50ms, r.P99ms, r.Failures)
	}
	return fmt.Sprintf("%d failed", r.Failures)
}

func fmtFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// setUp builds the binaries and the image, starts the topology, enrols the agents and seeds the
// routes.
func (b *bench) setUp(ctx context.Context) error {
	for _, n := range nodes {
		if err := os.MkdirAll(filepath.Join(b.run, n), 0o750); err != nil {
			return err
		}
	}
	for _, bin := range [][3]string{{"rpmgr", "./cmd/rpmgr", "rpmgrtest"}, {"bench", "./bench/cmd/bench", ""}} {
		cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-tags", bin[2], "-o", filepath.Join(b.here, "bin", bin[0]), bin[1]) //nolint:gosec // G204: the benchmark's own build
		cmd.Dir = b.repo
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go build %s: %w\n%s", bin[1], err, out)
		}
	}
	if err := b.certificates(); err != nil {
		return err
	}
	if err := b.writeFile("ctl", "controller.yaml", "version: 1\npublic_url: "+ctlURL+
		"\nlisten: {https: \":8443\", http: \"\", admin: \"127.0.0.1:7381\"}\ndatabase: {dsn: "+bootDir+"/controller.db}\n"+
		"kek: {source: file, path: "+bootDir+"/kek}\ntls: {cert_file: "+bootDir+"/web.crt, key_file: "+bootDir+"/web.key}\n"); err != nil {
		return err
	}
	b.log("starting the containers")
	if _, err := b.compose(ctx, "down", "--volumes", "--timeout", "1"); err != nil {
		return err
	}
	if _, err := b.compose(ctx, "up", "--detach", "--build", "--wait"); err != nil {
		return err
	}
	out, err := b.in(ctx, "ctl", "rpmgr", "controller", "init", "--config", ctlBoot)
	if err != nil {
		return err
	}
	m := regexp.MustCompile(`CA pin:\s+(\S+)`).FindStringSubmatch(out)
	if m == nil {
		return fmt.Errorf("bench: no CA pin in %q", out)
	}
	b.pin = m[1]
	if err := b.start(ctx, "ctl", "controller", "controller"); err != nil {
		return err
	}
	if err := b.ready(ctx, "ctl", 7381); err != nil {
		return err
	}
	tok, err := b.seed(ctx, "gateway", "--group", "bench", "--name", "gw", "--endpoint", gwLink+":8443")
	if err != nil {
		return err
	}
	if err := b.enroll(ctx, "gw", tok, bootDir+"/identity"); err != nil {
		return err
	}
	if err := b.writeFile("gw", "gateway.yaml", "version: 1\ncontroller: {endpoints: ["+ctlURL+"]}\nidentity_dir: "+bootDir+
		"/identity\nstate_dir: "+bootDir+"\nlisten: {tcp: \":8443\", udp: \":8443\", http: \"\", admin: \"127.0.0.1:7382\"}\n"); err != nil {
		return err
	}
	if err := b.start(ctx, "gw", "gateway", "gateway"); err != nil {
		return err
	}
	if tok, err = b.seed(ctx, "connector-token", "--uses", "2"); err != nil {
		return err
	}
	for _, con := range []string{"con1", "con2"} {
		if err := b.enroll(ctx, con, tok, bootDir+"/identity"); err != nil {
			return err
		}
		if err := errors.Join(b.writeFile(con, "policy.yaml", policy), b.writeFile(con, "connector.yaml", connectorConfig(bootDir, 7383))); err != nil {
			return err
		}
		if err := b.start(ctx, con, "connector", "connector"); err != nil {
			return err
		}
		if _, err := b.compose(ctx, "exec", "-d", "-T", con, "sh", "-c", "exec bench service -name "+con+" >> "+bootDir+"/service.log 2>&1"); err != nil {
			return err
		}
	}
	for node, port := range map[string]int{"gw": 7382, "con1": 7383, "con2": 7383} {
		if err := b.ready(ctx, node, port); err != nil {
			return fmt.Errorf("%s: %w", node, err)
		}
	}
	for node, ip := range map[string]string{"gw": gwLink, "con1": con1Link, "con2": con2Link} {
		out, err := b.in(ctx, node, "ip", "-o", "-4", "addr", "show")
		if err != nil {
			return err
		}
		if b.links[node] = linkOf(out, ip); b.links[node] == "" {
			return fmt.Errorf("bench: no interface with %s on %s", ip, node)
		}
	}
	return b.routes(ctx)
}

// linkOf finds the interface with address ip in the output of `ip -o -4 addr show`.
func linkOf(out, ip string) string {
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 3 && strings.HasPrefix(f[3], ip+"/") {
			return strings.TrimSuffix(f[1], ":")
		}
	}
	return ""
}

func connectorConfig(dir string, admin int) string {
	return "version: 1\ncontroller: {endpoints: [" + ctlURL + "]}\nidentity_dir: " + dir + "/identity\nstate_dir: " + dir +
		"\npolicy_file: " + bootDir + "/policy.yaml\nlisten: {admin: \"127.0.0.1:" + strconv.Itoa(admin) + "\"}\n"
}

func (b *bench) enroll(ctx context.Context, node, tok, identity string) error {
	if err := b.writeFile(node, "token", tok+"\n"); err != nil {
		return err
	}
	_, err := b.in(ctx, node, "rpmgr", "enroll", "--controller", ctlURL, "--ca-pin", b.pin, "--token-file", bootDir+"/token",
		"--identity-dir", identity)
	return err
}

// routes seeds the routes of both transports and waits until each answers.
func (b *bench) routes(ctx context.Context) error {
	for t, r := range routesOf {
		tcp := func(name string, port, target int, connectors ...string) error {
			args := []string{"--name", name + "-" + t, "--port", strconv.Itoa(port), "--target", "127.0.0.1:" + strconv.Itoa(target), "--transport", t}
			for _, c := range connectors {
				args = append(args, "--connector", c)
			}
			return b.seedRoute(ctx, "route", args...)
		}
		if err := errors.Join(tcp("sink", r.sink, 7001, "con1"), tcp("source", r.source, 7002, "con1"), tcp("echo", r.echo, 7003, "con1"),
			tcp("who", r.who, 7004, "con1", "con2"), tcp("blocked-sink", r.blockedSink, 7001, "con2")); err != nil {
			return err
		}
		if err := b.seedRoute(ctx, "udp-route", "--name", "udp-"+t, "--port", strconv.Itoa(r.udp), "--target", "127.0.0.1:7008",
			"--connector", "con1", "--transport", t); err != nil {
			return err
		}
		if err := b.seedRoute(ctx, "http-route", "--name", "http-"+t, "--hostname", r.host, "--connector", "con1", "--target", "127.0.0.1:7080",
			"--upstream", "http", "--transport", t, "--cert-file", bootDir+"/route-"+t+".crt", "--key-file", bootDir+"/route-"+t+".key"); err != nil {
			return err
		}
	}
	b.routeCount = routesPerTransport * len(routesOf)
	for t, r := range routesOf {
		if err := b.until(ctx, 60*time.Second, "the "+t+" routes", func() error { return b.answers(ctx, r.echo) }); err != nil {
			return err
		}
	}
	return nil
}

// answers checks that the echo route on port works from the client.
func (b *bench) answers(ctx context.Context, port int) error {
	r, err := b.load(ctx, "client", "probe", 0, "-workload", "setup", "-target", gwPub+":"+strconv.Itoa(port), "-rate", "10", "-duration", "300ms")
	if err == nil && (r.Failures > 0 || r.Conns == 0) {
		err = fmt.Errorf("%d of %d connections failed", r.Failures, r.Failures+r.Conns)
	}
	return err
}

func (b *bench) until(ctx context.Context, d time.Duration, what string, f func() error) error {
	var err error
	for end := time.Now().Add(d); time.Now().Before(end) && ctx.Err() == nil; time.Sleep(200 * time.Millisecond) {
		if err = f(); err == nil {
			return nil
		}
	}
	return fmt.Errorf("bench: %s: %w", what, err)
}

// certificates writes a CA every node trusts, the controller's certificate and the http routes'.
func (b *bench) certificates() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rpmgr bench CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for _, n := range nodes {
		if err := b.writeFile(n, "ca.pem", caPEM); err != nil {
			return err
		}
	}
	for file, name := range map[string]string{"web": "ctl", "route-quic": routesOf["quic"].host, "route-h2": routesOf["h2"].host} {
		crt, k, err := issue(ca, key, name)
		if err != nil {
			return err
		}
		if err := errors.Join(b.writeFile("ctl", file+".crt", crt), b.writeFile("ctl", file+".key", k)); err != nil {
			return err
		}
	}
	return nil
}

// issue returns a TLS server certificate of the CA for name, and its key, in PEM.
func issue(ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})), nil
}

// meta records the host's kernel, CPUs and buffer limits, and the QUIC metrics of GSO and buffers.
func (b *bench) meta(ctx context.Context) error {
	f, err := os.OpenFile(strings.TrimSuffix(b.o.out, ".jsonl")+".meta.txt", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // G304: next to the operator's results file
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fmt.Fprintf(f, "# %s %s, GSO %s\n", b.o.testbed, time.Now().UTC().Format(time.RFC3339), b.o.gso)
	out, err := b.in(ctx, "gw", "sh", "-c", "uname -srm; nproc; cat /proc/sys/net/core/rmem_max /proc/sys/net/core/wmem_max")
	if err != nil {
		return err
	}
	fmt.Fprintf(f, "host (kernel, CPUs, rmem_max, wmem_max): %s\n", strings.Join(strings.Fields(out), " "))
	for _, n := range []struct {
		node string
		port int
	}{{"gw", 7382}, {"con1", 7383}} {
		m, err := b.metrics(ctx, n.node, n.port, "rpmgr_quic_gso_enabled", "rpmgr_quic_udp_buffer_warning")
		if err != nil {
			return err
		}
		fmt.Fprintf(f, "%s: rpmgr_quic_gso_enabled %g, rpmgr_quic_udp_buffer_warning %g\n", n.node, m["rpmgr_quic_gso_enabled"],
			m["rpmgr_quic_udp_buffer_warning"])
	}
	return nil
}

// netem shapes the gateway↔connector link: half the RTT and the full loss on each side, with the
// queue limit raised so that netem itself does not cap the bandwidth-delay product. extra adds
// parameters on con2's side, such as a rate.
func (b *bench) netem(ctx context.Context, rtt, loss float64, extra ...string) error {
	b.rtt, b.loss = rtt, loss
	for _, node := range []string{"gw", "con1", "con2"} {
		args := []string{"tc", "qdisc", "replace", "dev", b.links[node], "root", "netem", "delay", fmtFloat(rtt/2) + "ms", "loss",
			fmtFloat(loss) + "%", "limit", "1000000"}
		if node == "con2" {
			args = append(args, extra...)
		}
		if _, err := b.asRoot(ctx, node, args...); err != nil {
			return err
		}
	}
	return nil
}

// matrix runs the cells: every RTT × loss × repetition × system for throughput and setup, the
// HTTP and UDP workloads per transport, then the other workloads on the first RTT without loss.
func (b *bench) matrix(ctx context.Context) error {
	w := b.o.workloads
	for _, rtt := range b.o.rtts {
		for _, loss := range b.o.losses {
			if err := b.netem(ctx, rtt, loss); err != nil {
				return err
			}
			for rep := 1; rep <= b.o.reps; rep++ {
				for _, sys := range []string{"direct", "quic", "h2"} {
					if err := b.cell(ctx, sys, rep); err != nil {
						return err
					}
				}
			}
			for _, t := range []string{"quic", "h2"} {
				if w["http"] {
					if err := b.http(ctx, t); err != nil {
						return err
					}
				}
				// 1 200 and 1 400 bytes as docs/12 asks; 3 000 bytes always take the oversize path,
				// so that its counter is shown to work.
				for _, size := range []int{1200, 1400, 3000} {
					if !w["udp"] {
						break
					}
					if err := b.udp(ctx, t, size); err != nil {
						return err
					}
				}
			}
		}
	}
	if err := b.netem(ctx, b.o.rtts[0], 0); err != nil {
		return err
	}
	for _, step := range []struct {
		name string
		run  func(context.Context, string) error
	}{{"vb18", b.vb18}, {"changes", b.changes}, {"kill", b.kill}, {"idle", b.idleConnectors}} {
		if !w[step.name] {
			continue
		}
		for _, t := range []string{"quic", "h2"} {
			if err := step.run(ctx, t); err != nil {
				return fmt.Errorf("%s %s: %w", step.name, t, err)
			}
		}
	}
	return nil
}

// cell runs one repetition of the throughput and setup workloads of a system.
func (b *bench) cell(ctx context.Context, sys string, rep int) error {
	if b.o.workloads["throughput"] {
		for _, streams := range []int{1, 32} {
			for _, dir := range []string{"up", "down"} {
				if err := b.throughput(ctx, sys, rep, dir, streams); err != nil {
					return err
				}
			}
		}
	}
	if b.o.workloads["setup"] {
		return b.setup(ctx, sys, rep)
	}
	return nil
}

// cpu returns the CPU seconds the gateway and con1 have used so far.
func (b *bench) cpu(ctx context.Context) (map[string]float64, error) {
	out := map[string]float64{}
	for role, n := range map[string]struct {
		node string
		port int
	}{"gateway": {"gw", 7382}, "connector": {"con1", 7383}} {
		m, err := b.metrics(ctx, n.node, n.port, "process_cpu_seconds_total")
		if err != nil {
			return nil, err
		}
		out[role] = m["process_cpu_seconds_total"]
	}
	return out, nil
}

func (b *bench) throughput(ctx context.Context, sys string, rep int, dir string, streams int) error {
	port := map[string]int{"up": 7001, "down": 7002}[dir]
	node, target := "gw", con1Link+":"+strconv.Itoa(port)
	var before map[string]float64
	if sys != "direct" {
		node, target = "client", gwPub+":"+strconv.Itoa(map[string]int{"up": routesOf[sys].sink, "down": routesOf[sys].source}[dir])
		var err error
		if before, err = b.cpu(ctx); err != nil {
			return err
		}
	}
	r, err := b.load(ctx, node, sys, rep, "-workload", dir, "-target", target, "-streams", strconv.Itoa(streams), "-duration", b.o.dur.String())
	if err != nil {
		return err
	}
	if before != nil {
		after, err := b.cpu(ctx)
		if err != nil {
			return err
		}
		r.CPUs = map[string]float64{}
		var total float64
		for role, v := range after {
			r.CPUs[role] = v - before[role]
			total += v - before[role]
		}
		if gbit := float64(r.Bytes) * 8 / 1e9; gbit > 0 {
			r.CPUPerGbit = total / gbit
		}
	}
	return b.write(r)
}

func (b *bench) setup(ctx context.Context, sys string, rep int) error {
	node, target := "gw", con1Link+":7003"
	if sys != "direct" {
		node, target = "client", gwPub+":"+strconv.Itoa(routesOf[sys].echo)
	}
	r, err := b.load(ctx, node, sys, rep, "-workload", "setup", "-target", target, "-rate", strconv.Itoa(b.o.rate), "-duration", b.o.setupDur.String())
	if err != nil {
		return err
	}
	return b.write(r)
}

func (b *bench) http(ctx context.Context, t string) error {
	r, err := b.load(ctx, "client", t, 1, "-workload", "http", "-target", gwPub+":8443", "-url", "https://"+routesOf[t].host+"/",
		"-ca", bootDir+"/ca.pem", "-workers", "32", "-duration", b.o.dur.String())
	if err != nil {
		return err
	}
	return b.write(r)
}

func (b *bench) udp(ctx context.Context, t string, size int) error {
	before, err := b.metrics(ctx, "gw", 7382, "rpmgr_udp_oversize_total")
	if err != nil {
		return err
	}
	r, err := b.load(ctx, "client", t, 1, "-workload", "udp", "-target", gwPub+":"+strconv.Itoa(routesOf[t].udp), "-size", strconv.Itoa(size),
		"-rate", strconv.Itoa(b.o.udpRate), "-duration", b.o.dur.String())
	if err != nil {
		return err
	}
	after, err := b.metrics(ctx, "gw", 7382, "rpmgr_udp_oversize_total")
	if err != nil {
		return err
	}
	if r.Sent > 0 {
		r.OversizeShare = (after["rpmgr_udp_oversize_total"] - before["rpmgr_udp_oversize_total"]) / float64(r.Sent)
	}
	return b.write(r)
}

// vb18 measures the share of new connections con2 gets on a route both connectors serve, before
// and while its session's writers are blocked by uploads through its link limited to 10 Mbit/s.
func (b *bench) vb18(ctx context.Context, t string) error {
	r := routesOf[t]
	half := b.o.extra / 2
	who := func() (float64, error) {
		rec, err := b.load(ctx, "client", t, 1, "-workload", "who", "-target", gwPub+":"+strconv.Itoa(r.who), "-rate", "50", "-duration", half.String())
		return rec.Share["con2"], err
	}
	before, err := who()
	if err != nil {
		return err
	}
	if err := b.netem(ctx, b.rtt, b.loss, "rate", "10mbit"); err != nil {
		return err
	}
	defer func() { _ = b.netem(context.Background(), b.rtt, b.loss) }()
	uploads := make(chan error, 1)
	go func() {
		_, err := b.load(ctx, "client", t, 1, "-workload", "up", "-target", gwPub+":"+strconv.Itoa(r.blockedSink), "-streams", "32",
			"-duration", (half + 5*time.Second).String())
		uploads <- err
	}()
	time.Sleep(3 * time.Second)
	blocked, err := who()
	if err := errors.Join(err, <-uploads); err != nil {
		return err
	}
	rec := b.record(t, "vb18")
	rec.Share = map[string]float64{"before": before, "blocked": blocked}
	return b.write(rec)
}

// changes measures, with o.routes more routes in the snapshot, one change per second for the
// extra duration while connections are held on an unchanged route; each change's apply time runs
// from its commit until the gateway reports its revision applied.
func (b *bench) changes(ctx context.Context, t string) error {
	if b.routeCount < b.o.routes {
		b.log("seeding %d routes", b.o.routes)
		for i := 1; i <= b.o.routes; i++ {
			if err := b.seedRoute(ctx, "route", "--name", "chg-"+strconv.Itoa(i), "--port", strconv.Itoa(10000+i), "--target", "127.0.0.1:7003",
				"--connector", "con1"); err != nil {
				return err
			}
		}
		b.routeCount += b.o.routes
	}
	held := make(chan Record, 1)
	go func() {
		r, err := b.load(ctx, "client", t, 1, "-workload", "hold", "-target", gwPub+":"+strconv.Itoa(routesOf[t].echo), "-conns", "8",
			"-duration", (b.o.extra + 10*time.Second).String())
		if err != nil {
			r.Conns, r.Lost = 8, 8
		}
		held <- r
	}()
	time.Sleep(2 * time.Second)
	var applies []float64
	for k, end := 0, time.Now().Add(b.o.extra); time.Now().Before(end); k++ {
		next := time.Now().Add(time.Second)
		d, err := b.change(ctx, k)
		if err != nil {
			return err
		}
		applies = append(applies, d.Seconds())
		time.Sleep(time.Until(next))
	}
	h := <-held
	slices.Sort(applies)
	pct := func(p float64) float64 { return applies[int(float64(len(applies)-1)*p)] }
	rec := b.record(t, "changes")
	rec.Routes, rec.ApplyP50s, rec.ApplyP99s, rec.Conns, rec.Lost = b.routeCount, pct(0.5), pct(0.99), h.Conns, h.Lost
	return b.write(rec)
}

// change changes one route and returns how long the gateway took to apply it after the commit.
func (b *bench) change(ctx context.Context, k int) (time.Duration, error) {
	m, err := b.metrics(ctx, "gw", 7382, "rpmgr_agent_applied_revision")
	if err != nil {
		return 0, err
	}
	seen := make(chan string, 1)
	go func() {
		out, err := b.in(ctx, "gw", "bench", "metrics", "-url", "http://127.0.0.1:7382/metrics", "-names", "rpmgr_agent_applied_revision",
			"-above", fmtFloat(m["rpmgr_agent_applied_revision"]), "-timeout", "20s")
		if err != nil {
			out = ""
		}
		seen <- out
	}()
	time.Sleep(300 * time.Millisecond) // the waiter has its first sample
	if _, err := b.seed(ctx, "route-update", "--name", "chg-"+strconv.Itoa(k%b.o.routes+1), "--idle", strconv.Itoa(k%50+1)+"m"); err != nil {
		return 0, err
	}
	committed := time.Now()
	var got struct {
		At int64 `json:"at_unix_ns"`
	}
	if err := json.Unmarshal([]byte(<-seen), &got); err != nil || got.At == 0 {
		return 0, fmt.Errorf("bench: the gateway did not apply change %d within 20 s", k)
	}
	return max(0, time.Unix(0, got.At).Sub(committed)), nil
}

// kill sends SIGKILL to the gateway, then to the controller, while connections are held, and
// times until the route answers again (gateway) or the controller is ready.
func (b *bench) kill(ctx context.Context, t string) error {
	for _, k := range []struct {
		node, role, workload string
		port                 int
	}{{"gw", "gateway", "kill-gateway", 7382}, {"ctl", "controller", "kill-controller", 7381}} {
		held := make(chan Record, 1)
		go func() {
			r, err := b.load(ctx, "client", t, 1, "-workload", "hold", "-target", gwPub+":"+strconv.Itoa(routesOf[t].echo), "-conns", "8",
				"-duration", "20s")
			if err != nil {
				r.Conns, r.Lost = 8, 8
			}
			held <- r
		}()
		time.Sleep(3 * time.Second)
		killed := time.Now()
		if _, err := b.in(ctx, k.node, "pkill", "-KILL", "-x", "rpmgr"); err != nil {
			return err
		}
		if err := b.until(ctx, 30*time.Second, "the end of "+k.node, func() error {
			if _, err := b.in(ctx, k.node, "pgrep", "-x", "rpmgr"); err == nil {
				return errors.New("still running")
			}
			return nil
		}); err != nil {
			return err
		}
		if err := b.start(ctx, k.node, k.role, k.role); err != nil {
			return err
		}
		probe := func() error { return b.ready(ctx, k.node, k.port) }
		if k.node == "gw" {
			probe = func() error { return b.answers(ctx, routesOf[t].echo) }
		}
		if err := b.until(ctx, 120*time.Second, k.node+" after SIGKILL", probe); err != nil {
			return err
		}
		recovery := time.Since(killed)
		h := <-held
		rec := b.record(t, k.workload)
		rec.RecoveryS, rec.Conns, rec.Lost = recovery.Seconds(), h.Conns, h.Lost
		if err := b.write(rec); err != nil {
			return err
		}
	}
	return nil
}

// idleConnectors enrols o.idle connectors once, each serving an idle route of each transport, and
// reads the gateway's memory and CPU over the extra duration with them and, before, without.
// Only the first transport's call measures; the connectors hold sessions of both.
func (b *bench) idleConnectors(ctx context.Context, t string) error {
	if b.idleStarted {
		return nil
	}
	gw := func() (map[string]float64, error) {
		return b.metrics(ctx, "gw", 7382, "process_resident_memory_bytes", "process_cpu_seconds_total")
	}
	without, err := gw()
	if err != nil {
		return err
	}
	b.log("enrolling %d idle connectors", b.o.idle)
	tok, err := b.seed(ctx, "connector-token", "--uses", strconv.Itoa(b.o.idle))
	if err != nil {
		return err
	}
	if err := b.writeFile("idle", "policy.yaml", policy); err != nil {
		return err
	}
	var names []string
	for i := 1; i <= b.o.idle; i++ {
		dir := fmt.Sprintf("%s/c%d", bootDir, i)
		if err := os.MkdirAll(filepath.Join(b.run, "idle", fmt.Sprintf("c%d", i)), 0o750); err != nil {
			return err
		}
		if err := b.enroll(ctx, "idle", tok, dir+"/identity"); err != nil {
			return err
		}
		if err := b.writeFile("idle", fmt.Sprintf("c%d.yaml", i), connectorConfig(dir, 7400+i)); err != nil {
			return err
		}
		if err := b.start(ctx, "idle", "connector", fmt.Sprintf("c%d", i)); err != nil {
			return err
		}
		names = append(names, idleName(i))
	}
	for tr, port := range map[string]string{"quic": "9301", "h2": "9302"} {
		args := []string{"--name", "idle-" + tr, "--port", port, "--target", "127.0.0.1:7003", "--transport", tr}
		for _, n := range names {
			args = append(args, "--connector", n)
		}
		if err := b.seedRoute(ctx, "route", args...); err != nil {
			return err
		}
	}
	b.idleStarted = true
	time.Sleep(10 * time.Second) // the sessions open
	before, err := gw()
	if err != nil {
		return err
	}
	time.Sleep(b.o.extra)
	after, err := gw()
	if err != nil {
		return err
	}
	rec := b.record("quic+h2", "idle")
	rec.Connectors = b.o.idle
	rec.MemoryMiB = map[string]float64{"gateway": after["process_resident_memory_bytes"] / (1 << 20),
		"gateway_without": without["process_resident_memory_bytes"] / (1 << 20)}
	rec.CPUs = map[string]float64{"gateway": after["process_cpu_seconds_total"] - before["process_cpu_seconds_total"]}
	return b.write(rec)
}

// idleName is the name the controller gives the i-th connector enrolled from the host "idle".
func idleName(i int) string {
	if i == 1 {
		return "idle"
	}
	return fmt.Sprintf("idle-%d", i)
}

// dumpLogs prints the end of every role's log, for a failed run.
func (b *bench) dumpLogs() {
	logs, _ := filepath.Glob(filepath.Join(b.run, "*", "*.log"))
	for _, l := range logs {
		data, _ := os.ReadFile(l) //nolint:gosec // G304: the run's own directory
		if len(data) > 4000 {
			data = data[len(data)-4000:]
		}
		fmt.Fprintf(os.Stderr, "==== %s\n%s\n", l, data)
	}
}
