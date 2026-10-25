// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

// event is one thing the load generator saw, with its wall-clock time in ms.
type event struct {
	T      int64  `json:"t"`
	Kind   string `json:"kind"`
	Who    string `json:"who"`
	Detail string `json:"detail,omitempty"`
}

type recorder struct {
	mu     sync.Mutex
	events []event
}

func (r *recorder) add(kind, who, detail string) {
	r.mu.Lock()
	r.events = append(r.events, event{time.Now().UnixMilli(), kind, who, detail})
	r.mu.Unlock()
}

type loadCfg struct {
	TCP, Tunnel, UDP, QUIC, TLSDir, Out string
	Transport                           string
	Connectors, Rate, Long, Flows       int
	Dur                                 time.Duration
	BulkAt                              string
	BulkBytes                           int64
}

func load(args []string) error {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	var c loadCfg
	fs.StringVar(&c.TCP, "tcp", "127.0.0.1:9000", "the gateway's visitor TCP address")
	fs.StringVar(&c.UDP, "udp", "127.0.0.1:9001", "the gateway's visitor UDP address")
	fs.StringVar(&c.QUIC, "quic", "127.0.0.1:9002", "the gateway's QUIC address")
	fs.StringVar(&c.Tunnel, "tunnel", "127.0.0.1:9003", "the gateway's TCP address for data sessions")
	fs.StringVar(&c.Transport, "transport", "quic", "connectors' transport: quic, tcp or auto; a list (auto,quic) assigns them in turn")
	fs.StringVar(&c.TLSDir, "tls", "/var/lib/s10/tls", "directory with the test CA")
	fs.StringVar(&c.Out, "out", "", "write the raw results as JSON here")
	fs.IntVar(&c.Connectors, "connectors", 2, "model connectors")
	fs.IntVar(&c.Rate, "rate", 500, "new visitor TCP connections per second")
	fs.IntVar(&c.Long, "long", 20, "long-lived visitor TCP connections")
	fs.IntVar(&c.Flows, "flows", 10, "long-lived UDP flows (one new short flow starts every second too)")
	fs.DurationVar(&c.Dur, "dur", 60*time.Second, "how long to run")
	fs.StringVar(&c.BulkAt, "bulk-at", "", "comma-separated offsets at which connector c0 sends a bulk stream")
	fs.Int64Var(&c.BulkBytes, "bulk-bytes", 64<<20, "bytes per bulk stream")
	_ = fs.Parse(args)
	tlsConf, err := clientTLS(c.TLSDir)
	if err != nil {
		return err
	}
	rec := &recorder{}
	// Connectors outlive the visitors by 5 s, so that the last visitors are not cut by the load
	// generator itself.
	cctx, ccancel := context.WithTimeout(context.Background(), c.Dur+5*time.Second)
	defer ccancel()
	ctx, cancel := context.WithTimeout(context.Background(), c.Dur)
	defer cancel()
	start := time.Now()
	rec.add("start", "load", "")

	conns := make([]*connector, c.Connectors)
	for i := range conns {
		ts := strings.Split(c.Transport, ",")
		conns[i] = &connector{name: "c" + strconv.Itoa(i), addr: c.QUIC, tunnel: c.Tunnel, transport: ts[i%len(ts)], tls: tlsConf, rec: rec}
		go conns[i].run(cctx)
	}
	// Give the connectors their sessions before visitors arrive.
	for _, x := range conns {
		for x.sessions.Load() == 0 && time.Since(start) < 10*time.Second {
			time.Sleep(10 * time.Millisecond)
		}
	}
	tcpRes := &tcpStats{buckets: map[int64]*bucket{}}
	var wg sync.WaitGroup
	for i := 0; i < c.Long; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); longConn(ctx, c.TCP, "long"+strconv.Itoa(i), rec) }(i)
	}
	udpRes := &udpStats{}
	for i := 0; i < c.Flows; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); udpFlow(ctx, c.UDP, "flow"+strconv.Itoa(i), 0, udpRes, rec) }(i)
	}
	go func() { // a short new flow every second, so that new flows during the drain are measured
		t := time.NewTicker(time.Second)
		defer t.Stop()
		n := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n++
				wg.Add(1)
				go func(n int) { defer wg.Done(); udpFlow(ctx, c.UDP, "short"+strconv.Itoa(n), 2*time.Second, udpRes, rec) }(n)
			}
		}
	}()
	for _, off := range strings.Split(c.BulkAt, ",") {
		if off == "" {
			continue
		}
		d, err := time.ParseDuration(off)
		if err != nil {
			return err
		}
		go func() {
			select {
			case <-time.After(time.Until(start.Add(d))):
				conns[0].bulk(cctx, c.BulkBytes)
			case <-ctx.Done():
			}
		}()
	}
	// New visitor connections at the given rate.
	sem := make(chan struct{}, 4000)
	tick := time.NewTicker(time.Second / time.Duration(c.Rate))
	for running := true; running; {
		select {
		case <-ctx.Done():
			running = false
		case <-tick.C:
			select {
			case sem <- struct{}{}:
				wg.Add(1)
				go func() { defer wg.Done(); defer func() { <-sem }(); tcpRes.one(c.TCP) }()
			default:
				tcpRes.record(time.Now().Unix(), "client_backlog", 0, 0)
			}
		}
	}
	tick.Stop()
	rec.add("stop", "load", "")
	waitTimeout(&wg, 15*time.Second)
	<-cctx.Done()

	res := map[string]any{"tcp": tcpRes.summary(), "udp": udpRes.summary(), "events": rec.events, "started": start.UnixMilli()}
	js, _ := json.MarshalIndent(res, "", "  ")
	if c.Out != "" {
		if err := os.WriteFile(c.Out, js, 0o644); err != nil {
			return err
		}
	}
	sum, _ := json.MarshalIndent(map[string]any{"tcp": tcpRes.summary(), "udp": udpRes.summary()}, "", "  ")
	fmt.Println(string(sum))
	rec.mu.Lock()
	for _, e := range rec.events {
		if e.Kind != "bulk_start" {
			fmt.Printf("%s %-14s %-8s %s\n", time.UnixMilli(e.T).Format("15:04:05.000"), e.Kind, e.Who, e.Detail)
		}
	}
	rec.mu.Unlock()
	return nil
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// ---- model connectors -----------------------------------------------------------------------

// connector models rpmgr's connector: a data session to the gateway over QUIC or TCP (transport
// auto races them, TCP 300 ms after QUIC, as happy eyeballs does), echoing every stream the
// gateway opens; a Drain makes it open a new session at once and keep the draining one.
type connector struct {
	name      string
	addr      string // QUIC
	tunnel    string // TCP
	transport string // auto, quic, tcp
	tls       *tls.Config
	rec       *recorder
	sessions  atomic.Int32
	mu        sync.Mutex
	newest    *quic.Conn
}

// sess is one data session of a connector.
type sess struct {
	kind  string
	gen   int
	qconn *quic.Conn
	tconn net.Conn
	br    *bufio.Reader
	ended chan string // why the session ended
}

func (c *connector) run(ctx context.Context) {
	for ctx.Err() == nil {
		s, err := c.dial(ctx)
		if err != nil {
			c.rec.add("dial_error", c.name, err.Error())
			time.Sleep(time.Second)
			continue
		}
		c.rec.add("session", c.name, fmt.Sprintf("%s gen %d", s.kind, s.gen))
		if !c.serve(ctx, s) {
			continue // ended without a drain: reconnect, as after a crash
		}
		return // the drain started a replacement, which runs its own loop
	}
}

func (c *connector) dial(ctx context.Context) (*sess, error) {
	switch c.transport {
	case "quic":
		return c.dialQUIC(ctx)
	case "tcp":
		return c.dialTCP(ctx)
	}
	type res struct {
		s   *sess
		err error
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan res, 2)
	go func() { s, err := c.dialQUIC(rctx); ch <- res{s, err} }()
	go func() {
		select {
		case <-time.After(300 * time.Millisecond):
		case <-rctx.Done():
			ch <- res{nil, rctx.Err()}
			return
		}
		s, err := c.dialTCP(rctx)
		ch <- res{s, err}
	}()
	var errs []string
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil {
			cancel()
			go func(left int) { // close a second winner
				for ; left > 0; left-- {
					if r2 := <-ch; r2.s != nil {
						r2.s.close()
					}
				}
			}(1 - i)
			return r.s, nil
		}
		errs = append(errs, r.err.Error())
	}
	return nil, errors.New(strings.Join(errs, "; "))
}

func (s *sess) close() {
	if s.qconn != nil {
		_ = s.qconn.CloseWithError(0, "lost the race")
	}
	if s.tconn != nil {
		s.tconn.Close()
	}
}

func (c *connector) dialQUIC(ctx context.Context) (*sess, error) {
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(dctx, c.addr, c.tls, &quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second, HandshakeIdleTimeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	ctl, err := conn.OpenStreamSync(dctx)
	if err != nil {
		_ = conn.CloseWithError(1, "")
		return nil, err
	}
	gen, br, err := helloGen(ctl, c.name)
	if err != nil {
		_ = conn.CloseWithError(1, "")
		return nil, err
	}
	s := &sess{kind: "quic", gen: gen, qconn: conn, br: br, ended: make(chan string, 1)}
	c.mu.Lock()
	c.newest = conn
	c.mu.Unlock()
	c.sessions.Add(1)
	go func() {
		for {
			st, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(st, st); _ = st.Close() }()
		}
	}()
	go func() {
		<-conn.Context().Done()
		cause := context.Cause(conn.Context())
		kind := "other"
		var sr *quic.StatelessResetError
		var ae *quic.ApplicationError
		var it *quic.IdleTimeoutError
		switch {
		case errors.As(cause, &sr):
			kind = "stateless_reset"
		case errors.As(cause, &ae) && ae.ErrorMessage == "drain over":
			kind = "drain_end"
		case errors.As(cause, &it):
			kind = "idle_timeout"
		}
		s.ended <- fmt.Sprintf("%s (%v)", kind, cause)
	}()
	return s, nil
}

func (c *connector) dialTCP(ctx context.Context) (*sess, error) {
	d := tls.Dialer{Config: c.tls, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
	conn, err := d.DialContext(ctx, "tcp", c.tunnel)
	if err != nil {
		return nil, err
	}
	gen, br, err := helloGen(conn, c.name)
	if err != nil {
		conn.Close()
		return nil, err
	}
	s := &sess{kind: "tcp", gen: gen, tconn: conn, br: br, ended: make(chan string, 1)}
	c.sessions.Add(1)
	return s, nil
}

func helloGen(rw io.ReadWriter, name string) (int, *bufio.Reader, error) {
	if _, err := fmt.Fprintf(rw, "HELLO %s\n", name); err != nil {
		return 0, nil, err
	}
	br := bufio.NewReader(rw)
	if d, ok := rw.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
		defer d.SetReadDeadline(time.Time{})
	}
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, nil, fmt.Errorf("no GEN: %w", err)
	}
	gen, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "GEN ")))
	return gen, br, nil
}

// serve reads the session's control messages until it ends and reports whether it was drained.
func (c *connector) serve(ctx context.Context, s *sess) bool {
	drained := atomic.Bool{}
	go func() {
		for {
			line, err := s.br.ReadString('\n')
			if err != nil {
				if s.kind == "tcp" {
					why := "closed"
					if drained.Load() {
						why = "drain_end"
					}
					s.ended <- fmt.Sprintf("%s (%v)", why, err)
				}
				return
			}
			line = strings.TrimSpace(line)
			switch {
			case line == "DRAIN":
				drained.Store(true)
				c.rec.add("drain", c.name, fmt.Sprintf("%s gen %d", s.kind, s.gen))
				go c.rehome(ctx, time.Now())
			case strings.HasPrefix(line, "OPEN ") && s.kind == "tcp":
				go c.dialBack(strings.TrimPrefix(line, "OPEN "))
			}
		}
	}()
	var why string
	select {
	case why = <-s.ended:
	case <-ctx.Done():
		s.close()
		return true
	}
	c.sessions.Add(-1)
	c.rec.add("session_end", c.name, fmt.Sprintf("%s gen %d: %s", s.kind, s.gen, why))
	return strings.HasPrefix(why, "drain_end")
}

func (c *connector) rehome(ctx context.Context, t0 time.Time) {
	for i := 0; ctx.Err() == nil; i++ {
		ns, err := c.dial(ctx)
		if err != nil {
			c.rec.add("redial_error", c.name, err.Error())
			time.Sleep(50 * time.Millisecond)
			continue
		}
		c.rec.add("rehomed", c.name, fmt.Sprintf("%s gen %d after %d ms, %d attempts", ns.kind, ns.gen, time.Since(t0).Milliseconds(), i+1))
		if !c.serve(ctx, ns) {
			c.run(ctx)
		}
		return
	}
}

// dialBack answers the gateway's OPEN on a TCP session with a new TLS connection for the stream.
func (c *connector) dialBack(id string) {
	d := tls.Dialer{Config: c.tls, NetDialer: &net.Dialer{Timeout: 3 * time.Second}}
	conn, err := d.Dial("tcp", c.tunnel)
	if err != nil {
		c.rec.add("stream_error", c.name, err.Error())
		return
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "STREAM %s\n", id); err != nil {
		return
	}
	_, _ = io.Copy(conn, conn)
}

// bulk sends n bytes on a new stream of the connector's newest QUIC session and records the rate.
func (c *connector) bulk(ctx context.Context, n int64) {
	c.mu.Lock()
	conn := c.newest
	c.mu.Unlock()
	if conn == nil {
		return
	}
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		c.rec.add("bulk_error", c.name, err.Error())
		return
	}
	t := time.Now()
	buf := make([]byte, 64<<10)
	for sent := int64(0); sent < n; sent += int64(len(buf)) {
		if _, err := st.Write(buf); err != nil {
			c.rec.add("bulk_error", c.name, err.Error())
			return
		}
	}
	_ = st.Close()
	line, err := bufio.NewReader(st).ReadString('\n')
	if err != nil {
		c.rec.add("bulk_error", c.name, err.Error())
		return
	}
	f := strings.Fields(line)
	d := time.Since(t)
	c.rec.add("bulk", c.name, fmt.Sprintf("%d bytes in %v = %.1f MB/s, served by gen %s", n, d.Round(time.Millisecond), float64(n)/d.Seconds()/1e6, f[len(f)-1]))
}

// ---- visitors -------------------------------------------------------------------------------

type bucket struct {
	OK, Refused, Reset, Timeout, EOF, Other, Backlog int
	Gens                                             map[int]int
}

type tcpStats struct {
	mu      sync.Mutex
	buckets map[int64]*bucket
	lat     []time.Duration
	others  map[string]int
}

func classify(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "reset"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	}
	return "other"
}

func (s *tcpStats) record(sec int64, kind string, gen int, lat time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[sec]
	if b == nil {
		b = &bucket{Gens: map[int]int{}}
		s.buckets[sec] = b
	}
	switch kind {
	case "ok":
		b.OK++
		b.Gens[gen]++
		s.lat = append(s.lat, lat)
	case "refused":
		b.Refused++
	case "reset":
		b.Reset++
	case "timeout":
		b.Timeout++
	case "eof":
		b.EOF++
	case "client_backlog":
		b.Backlog++
	default:
		b.Other++
	}
}

func (s *tcpStats) one(addr string) {
	t := time.Now()
	sec := t.Unix()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		if k := classify(err); k == "other" {
			s.mu.Lock()
			if s.others == nil {
				s.others = map[string]int{}
			}
			s.others[err.Error()]++
			s.mu.Unlock()
		}
		s.record(sec, classify(err), 0, 0)
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	g := make([]byte, 1)
	if _, err := io.ReadFull(c, g); err != nil {
		s.record(sec, classify(err), 0, 0)
		return
	}
	msg := make([]byte, 64)
	_, _ = rand.Read(msg)
	if _, err := c.Write(msg); err != nil {
		s.record(sec, classify(err), 0, 0)
		return
	}
	back := make([]byte, 64)
	if _, err := io.ReadFull(c, back); err != nil {
		s.record(sec, classify(err), 0, 0)
		return
	}
	if !bytes.Equal(msg, back) {
		s.record(sec, "other", 0, 0)
		return
	}
	s.record(sec, "ok", int(g[0]), time.Since(t))
}

func (s *tcpStats) summary() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	tot := bucket{Gens: map[int]int{}}
	secs := make([]int64, 0, len(s.buckets))
	for k, b := range s.buckets {
		secs = append(secs, k)
		tot.OK += b.OK
		tot.Refused += b.Refused
		tot.Reset += b.Reset
		tot.Timeout += b.Timeout
		tot.EOF += b.EOF
		tot.Other += b.Other
		tot.Backlog += b.Backlog
		for g, n := range b.Gens {
			tot.Gens[g] += n
		}
	}
	sort.Slice(secs, func(i, j int) bool { return secs[i] < secs[j] })
	var failSecs []string
	for _, k := range secs {
		b := s.buckets[k]
		if b.Refused+b.Reset+b.Timeout+b.EOF+b.Other+b.Backlog > 0 {
			failSecs = append(failSecs, fmt.Sprintf("%s: ok %d refused %d reset %d timeout %d eof %d other %d backlog %d",
				time.Unix(k, 0).Format("15:04:05"), b.OK, b.Refused, b.Reset, b.Timeout, b.EOF, b.Other, b.Backlog))
		}
	}
	sort.Slice(s.lat, func(i, j int) bool { return s.lat[i] < s.lat[j] })
	p := func(q float64) string {
		if len(s.lat) == 0 {
			return "-"
		}
		return s.lat[int(q*float64(len(s.lat)-1))].String()
	}
	return map[string]any{"total": tot, "seconds": len(secs), "failing_seconds": failSecs, "p50": p(0.5), "p99": p(0.99), "max": p(1), "dial_errors": s.others}
}

// longConn holds one visitor connection and pings through it every 100 ms until it ends.
func longConn(ctx context.Context, addr, who string, rec *recorder) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		rec.add("long_error", who, err.Error())
		return
	}
	defer c.Close()
	g := make([]byte, 1)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, g); err != nil {
		rec.add("long_error", who, err.Error())
		return
	}
	n := 0
	for ctx.Err() == nil {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("pingpong")); err != nil {
			rec.add("long_end", who, fmt.Sprintf("gen %d after %d pings: %s", g[0], n, classify(err)))
			return
		}
		b := make([]byte, 8)
		if _, err := io.ReadFull(c, b); err != nil {
			rec.add("long_end", who, fmt.Sprintf("gen %d after %d pings: %s", g[0], n, classify(err)))
			return
		}
		n++
		time.Sleep(100 * time.Millisecond)
	}
	rec.add("long_ok", who, fmt.Sprintf("gen %d, %d pings", g[0], n))
}

type udpStats struct {
	mu               sync.Mutex
	sent, recv       int64
	shortSent, short int64
	lostBySec        map[int64]int64
	gens             map[int]int64
}

func (u *udpStats) summary() map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	return map[string]any{"long_sent": u.sent, "long_recv": u.recv, "short_sent": u.shortSent, "short_recv": u.short,
		"lost_by_second": u.lostBySec, "replies_by_gen": u.gens}
}

// udpFlow sends a datagram every 20 ms and counts the answers; life 0 runs until ctx ends.
func udpFlow(ctx context.Context, addr, who string, life time.Duration, st *udpStats, rec *recorder) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}
	c, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		rec.add("udp_error", who, err.Error())
		return
	}
	defer c.Close()
	got := map[uint64]bool{}
	var gmu sync.Mutex
	gens := map[int]int64{}
	go func() {
		b := make([]byte, 64)
		for {
			n, err := c.Read(b)
			if err != nil {
				return
			}
			if n >= 9 {
				gmu.Lock()
				got[binary.BigEndian.Uint64(b[1:9])] = true
				gens[int(b[0])]++
				gmu.Unlock()
			}
		}
	}()
	end := time.Time{}
	if life > 0 {
		end = time.Now().Add(life)
	}
	sentAt := map[uint64]int64{}
	var seq uint64
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for ctx.Err() == nil && (end.IsZero() || time.Now().Before(end)) {
		<-t.C
		seq++
		b := make([]byte, 16)
		binary.BigEndian.PutUint64(b, seq)
		sentAt[seq] = time.Now().Unix()
		_, _ = c.Write(b)
	}
	time.Sleep(500 * time.Millisecond)
	gmu.Lock()
	defer gmu.Unlock()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.lostBySec == nil {
		st.lostBySec = map[int64]int64{}
		st.gens = map[int]int64{}
	}
	for s, sec := range sentAt {
		if !got[s] {
			st.lostBySec[sec]++
		}
	}
	for g, n := range gens {
		st.gens[g] += n
	}
	if life > 0 {
		st.shortSent += int64(len(sentAt))
		st.short += int64(len(got))
	} else {
		st.sent += int64(len(sentAt))
		st.recv += int64(len(got))
	}
}
