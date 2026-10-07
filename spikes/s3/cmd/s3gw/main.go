// SPDX-License-Identifier: Apache-2.0

// Command s3gw runs the spike S3 test gateway on loopback for the real-client runs: TCP and UDP
// on one port, plus an MSS-segmenting relay in front of the TCP port. It writes the test CA
// certificates and the connector's credentials to -certs (outside the repository), records every
// routing decision in -results as JSON lines, and on SIGINT/SIGTERM writes what the handlers saw
// and the UDP window budgets there.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/felix-homelab/rpmgr/spikes/s3/mux"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18443", "TCP and UDP address of the gateway")
	relay := flag.String("relay", "127.0.0.1:18444", "address of the MSS-segmenting relay to -addr")
	out := flag.String("certs", "", "directory for the test certificates and the connector key (outside the repository)")
	res := flag.String("results", "", "directory for routing events, handler notes and budgets")
	flag.Parse()
	if *out == "" || *res == "" {
		log.Fatal("-certs and -results are required")
	}
	for _, d := range []string{*out, *res} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			log.Fatal(err)
		}
	}
	certs, err := mux.NewCerts()
	if err != nil {
		log.Fatal(err)
	}
	must(writeCerts(*out, certs))

	evf, err := os.Create(filepath.Join(*res, "tcp-events.jsonl"))
	if err != nil {
		log.Fatal(err)
	}
	var evmu sync.Mutex
	enc := json.NewEncoder(evf)
	g, err := mux.NewGateway(certs, func(ev mux.Event) {
		evmu.Lock()
		_ = enc.Encode(ev)
		evmu.Unlock()
	})
	must(err)

	tl, err := net.Listen("tcp", *addr)
	must(err)
	go func() { _ = g.Router.Serve(tl) }()

	pc, err := net.ListenPacket("udp", *addr)
	must(err)
	g.UDP, err = mux.NewUDPMux(pc, mux.UDPConfig{
		Certs:           certs,
		HTTPHostnames:   map[string]tls.Certificate{mux.TestHTTPHost: certs.HTTP, mux.TestHTTPHost2: certs.HTTP2},
		TunnelBudget:    1 << 30,
		H3Budget:        256 << 20,
		StreamWindowMax: 16 << 20,
		ConnWindowMax:   256 << 20,
	})
	must(err)

	rl, err := net.Listen("tcp", *relay)
	must(err)
	go mux.SegmentingRelay(rl, *addr, 1448, 2*time.Millisecond)

	log.Printf("s3gw: TCP+UDP %s, segmenting relay %s, results in %s", *addr, *relay, *res)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	_ = tl.Close()
	_ = rl.Close()
	notes := append(g.Notes(), g.UDP.Events()...)
	must(os.WriteFile(filepath.Join(*res, "handler-notes.txt"), []byte(strings.Join(notes, "\n")+"\n"), 0o644))
	st, _ := json.MarshalIndent(g.UDP.Stats(), "", "  ")
	must(os.WriteFile(filepath.Join(*res, "udp-budgets.json"), append(st, '\n'), 0o644))
	g.Close()
	evf.Close()
}

func writeCerts(dir string, c *mux.Certs) error {
	key, err := mux.KeyPEM(c.Connector)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"public-ca.pem":   c.Public.PEM,
		"internal-ca.pem": c.Internal.PEM,
		"connector.pem":   mux.CertPEM(c.Connector),
		"connector.key":   key,
		"h3-spki.txt": []byte(fmt.Sprintf("%s,%s\n",
			mux.SPKIHash(c.HTTP.Leaf), mux.SPKIHash(c.HTTP2.Leaf))),
		"names.txt": []byte(fmt.Sprintf("trust_domain=%s\ntunnel_name=%s\nconnector=%s\n",
			mux.TestTrustDomain, mux.TunnelName(), c.ConnectorSPIFFE)),
	}
	for name, b := range files {
		mode := os.FileMode(0o644)
		if strings.HasSuffix(name, ".key") {
			mode = 0o600 // test key of a throw-away CA, but still a key
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, mode); err != nil {
			return err
		}
	}
	return nil
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
