// SPDX-License-Identifier: Apache-2.0

// Command idle measures the cost of many idle control sessions (spike S4, criterion 6). The
// driver process plays N agents, each with its own TCP and TLS connection and one open Session
// stream; it starts the controller as a child process, so each side's memory is measured on its
// own. Both ends use the liveness values of docs/03 (HTTP/2 PING after 20 s idle, 10 s timeout;
// grpc-go: keepalive 20 s / 10 s).
//
//	go run ./cmd/idle -stack connect -n 10000 -out results/idle-connect-10000.json
//	go run ./cmd/idle -stack grpc -n 10000 -out results/idle-grpc-10000.json
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	agentv1 "github.com/felix-homelab/rpmgr/spikes/s4/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/control"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/grpcstack"
	"github.com/felix-homelab/rpmgr/spikes/s4/internal/pki"
)

const td = "rpmgr-s4idle01"

// Mem is one process's memory after a forced GC.
type Mem struct {
	HeapAlloc  uint64 `json:"heap_alloc"`
	HeapInuse  uint64 `json:"heap_inuse"`
	StackInuse uint64 `json:"stack_inuse"`
	Sys        uint64 `json:"sys"`
	RSS        uint64 `json:"rss"`
	Goroutines int    `json:"goroutines"`
	Active     int    `json:"active_sessions,omitempty"`
}

func readMem() Mem {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return Mem{HeapAlloc: ms.HeapAlloc, HeapInuse: ms.HeapInuse, StackInuse: ms.StackInuse, Sys: ms.Sys,
		RSS: rss("self"), Goroutines: runtime.NumGoroutine()}
}

func rss(pid string) uint64 {
	b, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "VmRSS:" {
			kb, _ := strconv.ParseUint(f[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// cpuTicks returns utime+stime of pid in clock ticks (100 Hz on Linux).
func cpuTicks(pid string) uint64 {
	b, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+2:])
	u, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	return u + st
}

func main() {
	role := flag.String("role", "driver", "driver or server")
	stack := flag.String("stack", "connect", "connect or grpc")
	n := flag.Int("n", 10000, "number of idle sessions")
	dir := flag.String("dir", "", "server: directory with the TLS material")
	idle := flag.Duration("idle", 60*time.Second, "idle period over which CPU is measured")
	out := flag.String("out", "", "driver: JSON result file")
	flag.Parse()
	if *role == "server" {
		serve(*stack, *dir)
		return
	}
	drive(*stack, *n, *idle, *out)
}

func serve(stack, dir string) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	if err != nil {
		log.Fatal(err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(dir, "root.pem"))
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	ca := &pki.CA{TrustDomain: td, Roots: pool}
	so := control.ServerOptions{CA: ca, Cert: cert, SendPingTimeout: 20 * time.Second, PingTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	var active func() int
	switch stack {
	case "connect":
		svc := control.NewService()
		control.Serve(control.NewHTTPServer(svc, so), ln)
		active = svc.Active
	case "grpc":
		svc := grpcstack.NewService()
		grpcstack.TrustDomain = td
		gs := grpcstack.NativeServer(svc, so, grpcstack.Options{Time: 20 * time.Second, Timeout: 10 * time.Second, MinTime: 10 * time.Second})
		go func() { _ = gs.Serve(ln) }()
		active = svc.Active
	default:
		log.Fatalf("unknown stack %q", stack)
	}
	admin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		m := readMem()
		m.Active = active()
		_ = json.NewEncoder(w).Encode(m)
	})
	go func() { _ = http.Serve(admin, mux) }()
	fmt.Printf("READY %s %s\n", ln.Addr(), admin.Addr())
	select {}
}

func writePEM(path, typ string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		log.Fatal(err)
	}
}

func serverStats(admin string) Mem {
	res, err := http.Get("http://" + admin + "/stats")
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	var m Mem
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		log.Fatal(err)
	}
	return m
}

// Result is written as JSON.
type Result struct {
	Stack                 string  `json:"stack"`
	Sessions              int     `json:"sessions"`
	GoVersion             string  `json:"go_version"`
	SetupSeconds          float64 `json:"setup_seconds"`
	IdleSeconds           float64 `json:"idle_seconds"`
	ServerBefore          Mem     `json:"server_before"`
	ServerAfter           Mem     `json:"server_after"`
	ClientBefore          Mem     `json:"client_before"`
	ClientAfter           Mem     `json:"client_after"`
	ServerHeapPerSession  float64 `json:"server_heap_plus_stack_bytes_per_session"`
	ServerRSSPerSession   float64 `json:"server_rss_bytes_per_session"`
	ClientHeapPerSession  float64 `json:"client_heap_plus_stack_bytes_per_session"`
	ClientRSSPerSession   float64 `json:"client_rss_bytes_per_session"`
	ServerCPUPercentIdle  float64 `json:"server_cpu_percent_of_one_core_while_idle"`
	ClientCPUPercentIdle  float64 `json:"client_cpu_percent_of_one_core_while_idle"`
	ServerGoroutinesPerSn float64 `json:"server_goroutines_per_session"`
	ClientGoroutinesPerSn float64 `json:"client_goroutines_per_session"`
	FileDescriptorLimit   string  `json:"fd_limit"`
}

func drive(stack string, n int, idle time.Duration, out string) {
	ca, err := pki.NewCA(td)
	if err != nil {
		log.Fatal(err)
	}
	srvCert, err := ca.Leaf("/controller/n1", []string{"controller." + td}, true, true)
	if err != nil {
		log.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "s4-idle-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	chain := []byte{}
	for _, der := range srvCert.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.pem"), chain, 0o600); err != nil {
		log.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(srvCert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		log.Fatal(err)
	}
	writePEM(filepath.Join(dir, "server.key"), "EC PRIVATE KEY", keyDER)
	writePEM(filepath.Join(dir, "root.pem"), "CERTIFICATE", ca.Root.Raw)

	self, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command(self, "-role", "server", "-stack", stack, "-dir", dir)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	f := strings.Fields(line)
	addr, admin := f[1], f[2]
	pid := strconv.Itoa(cmd.Process.Pid)

	// One client certificate is reused: certificate issuance is not what is measured, and every
	// session still has its own key exchange, TLS state and HTTP/2 connection.
	cert, err := ca.Leaf("/org/org_1/connector/bench", []string{"bench.connector." + td}, true, true)
	if err != nil {
		log.Fatal(err)
	}
	co := control.ClientOptions{CA: ca, Cert: cert, Addr: addr, SendPingTimeout: 20 * time.Second, PingTimeout: 10 * time.Second}

	res := Result{Stack: stack, Sessions: n, GoVersion: runtime.Version()}
	if b, err := exec.Command("sh", "-c", "ulimit -n").Output(); err == nil {
		res.FileDescriptorLimit = strings.TrimSpace(string(b))
	}
	res.ServerBefore = serverStats(admin)
	res.ClientBefore = readMem()

	var keep sync.Map // session index -> stream, so nothing is collected
	var opened atomic.Int64
	start := time.Now()
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(256)
	for i := range n {
		g.Go(func() error {
			id := "a" + strconv.Itoa(i)
			hello := &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{AgentId: id}}}
			switch stack {
			case "connect":
				c, _ := control.NewClient(co)
				st := c.Session(context.Background())
				if err := st.Send(hello); err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				if _, err := st.Receive(); err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				keep.Store(i, st)
			case "grpc":
				cc, err := grpcstack.Dial(co, grpcstack.Options{})
				if err != nil {
					return err
				}
				st, err := agentv1.NewControlClient(cc).Session(context.Background())
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				if err := st.Send(hello); err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				if _, err := st.Recv(); err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				keep.Store(i, st)
			}
			if k := opened.Add(1); k%1000 == 0 {
				log.Printf("%d sessions open", k)
			}
			return ctx.Err()
		})
	}
	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
	res.SetupSeconds = time.Since(start).Seconds()
	for serverStats(admin).Active < n {
		time.Sleep(100 * time.Millisecond)
	}
	log.Printf("%d sessions open after %.1f s; idling %v", n, res.SetupSeconds, idle)
	time.Sleep(10 * time.Second) // let connection setup settle
	s0, c0, t0 := cpuTicks(pid), cpuTicks("self"), time.Now()
	time.Sleep(idle)
	s1, c1, el := cpuTicks(pid), cpuTicks("self"), time.Since(t0).Seconds()
	res.IdleSeconds = el
	res.ServerCPUPercentIdle = float64(s1-s0) / el
	res.ClientCPUPercentIdle = float64(c1-c0) / el
	res.ServerAfter = serverStats(admin)
	res.ClientAfter = readMem()
	if res.ServerAfter.Active != n {
		log.Fatalf("only %d of %d sessions still open on the server", res.ServerAfter.Active, n)
	}
	per := func(a, b uint64) float64 { return (float64(a) - float64(b)) / float64(n) }
	res.ServerHeapPerSession = per(res.ServerAfter.HeapInuse+res.ServerAfter.StackInuse, res.ServerBefore.HeapInuse+res.ServerBefore.StackInuse)
	res.ServerRSSPerSession = per(res.ServerAfter.RSS, res.ServerBefore.RSS)
	res.ClientHeapPerSession = per(res.ClientAfter.HeapInuse+res.ClientAfter.StackInuse, res.ClientBefore.HeapInuse+res.ClientBefore.StackInuse)
	res.ClientRSSPerSession = per(res.ClientAfter.RSS, res.ClientBefore.RSS)
	res.ServerGoroutinesPerSn = float64(res.ServerAfter.Goroutines-res.ServerBefore.Goroutines) / float64(n)
	res.ClientGoroutinesPerSn = float64(res.ClientAfter.Goroutines-res.ClientBefore.Goroutines) / float64(n)
	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))
	if out != "" {
		if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
