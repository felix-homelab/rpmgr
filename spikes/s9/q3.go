// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type probeResult struct {
	Via   string  `json:"via"`
	Ms    float64 `json:"ms"`
	Error string  `json:"error"`
}

func probeVia(p *proc, agent string, delay time.Duration) (probeResult, error) {
	var res probeResult
	u := fmt.Sprintf("http://%s/probe?agent=%s&delay=%s", p.admin, url.QueryEscape(agent), delay)
	resp, err := http.Get(u) //nolint:noctx,gosec // spike
	if err != nil {
		return res, err
	}
	defer func() { _ = resp.Body.Close() }()
	return res, json.NewDecoder(resp.Body).Decode(&res)
}

// runQ3: ProbeTarget forwarded over controller-to-controller mutual TLS to the replica that holds
// the agent's session, below the probe timeout (15 s for ProbeTargetCertificate, 03).
func runQ3(args []string) error {
	fs := flag.NewFlagSet("q3", flag.ExitOnError)
	n := fs.Int("probes", 1000, "probes per kind")
	_ = fs.Parse(args)
	ctx := context.Background()
	r, err := newReport("q3")
	if err != nil {
		return err
	}
	defer r.close()
	certs := filepath.Join(resultsDir(), "logs", "pki")
	_ = os.RemoveAll(certs)
	if err := writePKI(certs, []string{"r1", "r2", "r3"}); err != nil {
		return err
	}
	f, err := startFleet(ctx, 3, 300, []string{"-poll", "1s", "-internal", "127.0.0.1:0", "-certs", certs}, true)
	if err != nil {
		return err
	}
	defer f.close()
	r.printf("Q3: 3 replicas with c2c mutual TLS (HTTP/2, TLS 1.3, controller SPIFFE IDs), 300 agents")
	run := func(name string, delay time.Duration, count int, pick func(i int) string) ([]float64, map[string]int) {
		var lat []float64
		errs := map[string]int{}
		for i := range count {
			res, err := probeVia(f.procs[0], pick(i), delay)
			if err == nil && res.Error != "" {
				err = errors.New(res.Error)
			}
			if err != nil {
				errs[err.Error()]++
				continue
			}
			lat = append(lat, res.Ms)
		}
		r.printf("%s: %s, errors %v", name, dist(lat), errs)
		return lat, errs
	}
	// Agents i%3==0 are on r1 (direct), the others on r2 and r3 (forwarded).
	direct := func(i int) string { return agentID((i * 3) % 300) }
	fwd := func(i int) string { return agentID((i*3)%300 + 1 + i%2) }
	d0, e0 := run("direct, connector answers at once", 0, *n, direct)
	f0, e1 := run("forwarded, connector answers at once", 0, *n, fwd)
	f200, e2 := run("forwarded, connector takes 200 ms", 200*time.Millisecond, max(*n/5, 100), fwd)
	overhead := p99(f0) - p99(d0)
	pass := r.verdict(len(e0)+len(e1)+len(e2) == 0, "every probe answered")
	pass = r.verdict(p99(f0) < 15000 && p99(f200) < 15000, "forwarded p99 %.2f ms (0 ms connector) and %.2f ms (200 ms) below the 15 s probe timeout", p99(f0), p99(f200)) && pass
	r.printf("forwarding adds %.2f ms at p99", overhead)

	// A fresh connection per probe: the first probe to a replica pays the handshake.
	cert, roots, err := loadPKI(certs, "r1")
	if err != nil {
		return err
	}
	var addrs = map[string]string{}
	rows, err := f.pool.Query(ctx, `SELECT node_id, internal_address FROM controller_nodes`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var node, a string
		_ = rows.Scan(&node, &a)
		addrs[node] = a
	}
	var hs []float64
	for range 100 {
		cl := c2cClient(cert, roots, "r2")
		t := time.Now()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addrs["r2"]+"/c2c/probe?agent="+agentID(1)+"&delay=0s", nil)
		resp, err := cl.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		hs = append(hs, float64(time.Since(t).Microseconds())/1000)
		cl.CloseIdleConnections()
	}
	r.printf("forwarded over a new connection each time (TLS 1.3 handshake included): %s", dist(hs))

	// Error paths.
	try := func(name string, cfg *tls.Config, addr string) {
		cfg.MinVersion, cfg.NextProtos = tls.VersionTLS13, []string{"h2"}
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}, Timeout: 10 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/c2c/probe?agent="+agentID(1)+"&delay=0s", nil)
		resp, err := cl.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			pass = r.verdict(false, "%s: accepted with %s", name, resp.Status) && pass
			return
		}
		pass = r.verdict(true, "%s: refused: %v", name, err) && pass
	}
	conn, _, err := loadPKI(certs, "connector")
	if err != nil {
		return err
	}
	try("a connector's certificate at the internal listener", &tls.Config{Certificates: []tls.Certificate{conn}, RootCAs: roots,
		ServerName: controllerDNS("r2")}, addrs["r2"])
	try("no client certificate at the internal listener", &tls.Config{RootCAs: roots, ServerName: controllerDNS("r2")}, addrs["r2"])
	try("r3 answering where r2 is expected", &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots,
		ServerName: controllerDNS("r2"), VerifyConnection: func(cs tls.ConnectionState) error { return peerIsController(cs, "r2") }}, addrs["r3"])

	// A replica that is gone: its agents' registry rows still name it until they reconnect.
	f.procs[2].kill()
	t := time.Now()
	res, err := probeVia(f.procs[0], agentID(2), 0)
	el := time.Since(t)
	r.printf("probe of an agent whose replica (r3) was killed a moment ago: %v %+v after %s", err, res, el.Round(time.Millisecond))
	pass = r.verdict(res.Error != "" && el < 6*time.Second, "a dead replica fails the probe within the 5 s dial timeout (%s)", el.Round(time.Millisecond)) && pass
	// The dial to a closed port is refused at once on one host; an unreachable host takes the
	// dial timeout instead: probe a blackholed address directly.
	t = time.Now()
	_, err = c2cClient(cert, roots, "r9").Get("https://192.0.2.1:9/") //nolint:noctx // TEST-NET-1, never routed
	r.printf("dial to an unreachable replica address (192.0.2.1): %v after %s", err, time.Since(t).Round(time.Millisecond))
	var ne net.Error
	_ = errors.As(err, &ne)
	r.printf("Q3 overall: %v", map[bool]string{true: "PASS", false: "FAIL"}[pass])
	return nil
}
