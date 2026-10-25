// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

// The hand-off modes of the UDP sockets (ADR-0022, S-2 and S-3):
//
//	relay    the old process reads the sockets during the drain and passes Initial packets,
//	         packets of the new generation and new udp flows to the new process (the default)
//	pause    the fallback: the old process keeps reading and serving every datagram until it
//	         exits; the new process reads the sockets only then, and connectors use TCP meanwhile
//	norelay  counterfactual: the new process reads the sockets at once, next to the old one
const (
	modeRelay   = "relay"
	modePause   = "pause"
	modeNoRelay = "norelay"
)

type serverCfg struct {
	TCP, Tunnel, UDP, QUIC string
	TLSDir, Run            string
	Bin                    string
	Drain                  time.Duration
	ReadyWindow            time.Duration
	SessionWait            time.Duration
	Mode                   string
	FastPath               bool
	ResetKey               string
}

// session is a connector's data session, over QUIC or over TCP.
type session struct {
	kind     string // quic, tcp
	name     string
	draining bool
	// QUIC
	conn *quic.Conn
	// TCP: the control connection; streams are dialled back by the connector ("STREAM <id>")
	ctl  net.Conn
	done chan struct{}
	w    io.Writer // where control messages go
}

type server struct {
	cfg     serverCfg
	gen     int
	log     *log.Logger
	tlsConf *tls.Config
	tcp     *net.TCPListener // visitors
	tun     *net.TCPListener // connectors' TCP sessions
	udpV    *udpSock
	udpQ    *udpSock
	tr      *quic.Transport
	ql      *quic.Listener

	mu       sync.Mutex
	sessions map[*session]bool
	visitors map[net.Conn]bool
	flows    map[string]bool
	waiting  map[uint64]chan net.Conn // TCP streams being dialled back
	nextID   uint64
	rr       int
	draining bool

	parent   *os.File // status pipe to the predecessor; nil once it is gone
	parentCh <-chan string
	active   atomic.Bool
	seq      int
	cut      chan struct{}
	cutOnce  sync.Once

	noSession, served, udpServed atomic.Int64
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var c serverCfg
	fs.StringVar(&c.TCP, "tcp", ":9000", "visitor TCP address (a tcp route)")
	fs.StringVar(&c.Tunnel, "tunnel", ":9003", "TCP address for the connectors' TCP data sessions")
	fs.StringVar(&c.UDP, "udp", ":9001", "visitor UDP address (a udp route)")
	fs.StringVar(&c.QUIC, "quic", ":9002", "QUIC address for the connectors' data sessions")
	fs.StringVar(&c.TLSDir, "tls", "/var/lib/s10/tls", "test CA and gateway certificate (created once)")
	fs.StringVar(&c.Run, "run", "/run/s10", "run directory: pid file and hand-off outcome")
	fs.StringVar(&c.Bin, "bin", "/usr/local/bin/s10", "the installed binary a hand-off starts")
	fs.DurationVar(&c.Drain, "drain", 20*time.Second, "hand-off drain")
	fs.DurationVar(&c.ReadyWindow, "ready-window", 10*time.Second, "hand-off readiness window")
	fs.DurationVar(&c.SessionWait, "session-wait", 5*time.Second, "how long a visitor waits for a session")
	fs.StringVar(&c.Mode, "mode", modeRelay, "UDP hand-off mode: relay, pause or norelay")
	fs.BoolVar(&c.FastPath, "fastpath", false, "quic-go on the plain UDP socket (its fast path); implied by -mode pause")
	fs.StringVar(&c.ResetKey, "reset-key", "/var/lib/s10/reset.key", "persisted QUIC stateless reset key")
	_ = fs.Parse(args)
	if c.Mode == modePause {
		c.FastPath = true
	}

	m, err := readManifest()
	if err != nil {
		return err
	}
	s := &server{cfg: c, sessions: map[*session]bool{}, visitors: map[net.Conn]bool{}, flows: map[string]bool{},
		waiting: map[uint64]chan net.Conn{}, cut: make(chan struct{})}
	s.gen = 1
	var closed []int
	if m != nil {
		closed = closeUnexpected(m, 64)
		s.gen = m.Gen
	}
	s.log = log.New(os.Stderr, fmt.Sprintf("s10[gen %d pid %d] ", s.gen, os.Getpid()), log.Lmicroseconds)
	if len(closed) > 0 {
		s.log.Printf("closed unexpected inherited descriptors %v", closed)
	}
	if err := ensureTLS(c.TLSDir); err != nil {
		return err
	}
	if s.tlsConf, err = serverTLS(c.TLSDir); err != nil {
		return err
	}
	_ = os.MkdirAll(c.Run, 0o755)
	if err := s.open(m); err != nil {
		if m != nil {
			s.log.Printf("hand-off refused by the new process: %v", err)
		}
		return err
	}
	key, err := resetKey(c.ResetKey)
	if err != nil {
		return err
	}
	startQUIC := func() error {
		var qc net.PacketConn = s.udpQ
		if c.FastPath {
			qc = s.udpQ.real // quic-go's batch reads and GSO; nothing can filter these reads
		}
		s.tr = &quic.Transport{Conn: qc, StatelessResetKey: key, ConnectionIDGenerator: genCIDs{byte(s.gen)}}
		var err error
		if s.ql, err = s.tr.Listen(s.tlsConf, &quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second}); err != nil {
			return err
		}
		go s.acceptQUIC()
		return nil
	}
	quicStarted := make(chan struct{})
	if m == nil || c.Mode != modePause {
		if err := startQUIC(); err != nil {
			return err
		}
		close(quicStarted)
	}
	go s.serveUDP()

	if m != nil {
		if os.Getenv("S10_NOT_READY") == "1" {
			s.log.Printf("injected: never ready")
			select {}
		}
		if _, err := s.parent.Write([]byte("READY\n")); err != nil {
			return err
		}
		go func() {
			for msg := range s.parentCh {
				s.log.Printf("from the old process: %s", msg)
				if msg == "DONE" {
					break
				}
			}
			s.log.Printf("the old process is done: reading the UDP sockets now")
			s.udpV.startDirect()
			if c.Mode == modePause {
				if err := startQUIC(); err != nil {
					s.log.Printf("QUIC: %v", err)
				}
				close(quicStarted)
			} else if !c.FastPath {
				s.udpQ.startDirect()
			}
			s.mu.Lock()
			s.parent = nil
			s.mu.Unlock()
		}()
		if err := sdNotify(fmt.Sprintf("MAINPID=%d\nREADY=1", os.Getpid())); err != nil {
			s.log.Printf("sd_notify: %v", err)
		}
	} else {
		s.udpV.startDirect()
		if !c.FastPath {
			s.udpQ.startDirect()
		}
		_ = sdNotify("READY=1")
	}
	_ = os.WriteFile(filepath.Join(c.Run, "pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
	s.log.Printf("serving tcp %s tunnel %s udp %s quic %s (mode %s)", c.TCP, c.Tunnel, c.UDP, c.QUIC, c.Mode)
	go s.acceptVisitors(s.tcp)
	go s.acceptTunnels(s.tun)

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGINT)
	for x := range sig {
		if x == syscall.SIGUSR2 {
			select {
			case <-quicStarted:
			default:
				// A process whose predecessor still drains in pause mode ends that drain first,
				// which starts its QUIC; handoff does that.
			}
			if s.handoff(quicStarted) {
				return nil // drained and exited
			}
			continue
		}
		s.log.Printf("stopping on %v", x)
		s.stop()
		return nil
	}
	return nil
}

func resetKey(path string) (*quic.StatelessResetKey, error) {
	var k quic.StatelessResetKey
	if b, err := os.ReadFile(path); err == nil && len(b) == len(k) {
		copy(k[:], b)
		return &k, nil
	}
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return nil, err
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	return &k, os.WriteFile(path, k[:], 0o600)
}

// open binds the sockets, or adopts the ones the manifest names.
func (s *server) open(m *manifest) error {
	if m == nil {
		var err error
		for _, x := range []struct {
			addr string
			dst  **net.TCPListener
		}{{s.cfg.TCP, &s.tcp}, {s.cfg.Tunnel, &s.tun}} {
			a, err := net.ResolveTCPAddr("tcp", x.addr)
			if err != nil {
				return err
			}
			if *x.dst, err = net.ListenTCP("tcp", a); err != nil {
				return err
			}
		}
		for _, x := range []struct {
			addr string
			dst  **udpSock
		}{{s.cfg.UDP, &s.udpV}, {s.cfg.QUIC, &s.udpQ}} {
			ua, err := net.ResolveUDPAddr("udp", x.addr)
			if err != nil {
				return err
			}
			u, err := net.ListenUDP("udp", ua)
			if err != nil {
				return err
			}
			_ = u.SetReadBuffer(7 << 20)
			*x.dst = newUDPSock(u)
		}
		return err
	}
	s.parent = os.NewFile(uintptr(m.Status), "status")
	s.parentCh = lineReader(s.parent)
	byName := map[string]entry{}
	for _, e := range m.Entries {
		byName[e.Name] = e
	}
	var err error
	if s.tcp, err = adoptTCP(byName["visitor-tcp"], s.cfg.TCP); err != nil {
		return err
	}
	if s.tun, err = adoptTCP(byName["tunnel-tcp"], s.cfg.Tunnel); err != nil {
		return err
	}
	uv, err := adoptUDP(byName["visitor-udp"], s.cfg.UDP)
	if err != nil {
		return err
	}
	uq, err := adoptUDP(byName["agent-quic"], s.cfg.QUIC)
	if err != nil {
		return err
	}
	_ = uv.SetReadBuffer(7 << 20)
	_ = uq.SetReadBuffer(7 << 20)
	s.udpV, s.udpQ = newUDPSock(uv), newUDPSock(uq)
	switch s.cfg.Mode {
	case modeNoRelay:
		s.udpV.startDirect()
		s.udpQ.startDirect()
	case modeRelay:
		if e, ok := byName["relay-visitor-udp"]; ok {
			s.udpV.startRelayIn(os.NewFile(uintptr(e.FD), e.Name))
		}
		if e, ok := byName["relay-agent-quic"]; ok {
			s.udpQ.startRelayIn(os.NewFile(uintptr(e.FD), e.Name))
		}
	}
	return nil
}

// ---- visitors -------------------------------------------------------------------------------

func (s *server) acceptVisitors(l *net.TCPListener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go s.visitor(c)
	}
}

func (s *server) visitor(c net.Conn) {
	s.mu.Lock()
	s.visitors[c] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.visitors, c)
		s.mu.Unlock()
		c.Close()
	}()
	ss := s.pickSession()
	if ss == nil {
		s.noSession.Add(1)
		return
	}
	st, err := s.openStream(ss)
	if err != nil {
		s.noSession.Add(1)
		return
	}
	defer st.Close()
	if _, err := c.Write([]byte{byte(s.gen)}); err != nil {
		return
	}
	s.served.Add(1)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(st, c)
		if cw, ok := st.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = st.Close()
		}
		done <- struct{}{}
	}()
	go func() { _, _ = io.Copy(c, st); done <- struct{}{} }()
	<-done
}

// pickSession returns a session that is not draining, waiting up to the session wait for one. A
// connection the old process accepted before it stopped accepting is served on its draining
// sessions: they stay open for exactly such connections.
func (s *server) pickSession() *session {
	deadline := time.Now().Add(s.cfg.SessionWait)
	for {
		s.mu.Lock()
		var list []*session
		for x := range s.sessions {
			if (!x.draining || s.draining) && !(s.draining && x.kind == "tcp") {
				list = append(list, x)
			}
		}
		if len(list) > 0 {
			s.rr++
			x := list[s.rr%len(list)]
			s.mu.Unlock()
			return x
		}
		s.mu.Unlock()
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *server) openStream(ss *session) (io.ReadWriteCloser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if ss.kind == "quic" {
		return ss.conn.OpenStreamSync(ctx)
	}
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	ch := make(chan net.Conn, 1)
	s.waiting[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.waiting, id)
		s.mu.Unlock()
	}()
	if _, err := fmt.Fprintf(ss.w, "OPEN %d\n", id); err != nil {
		return nil, err
	}
	select {
	case c := <-ch:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---- connectors over QUIC -------------------------------------------------------------------

func (s *server) acceptQUIC() {
	for {
		conn, err := s.ql.Accept(context.Background())
		if err != nil {
			return
		}
		go s.quicSession(conn)
	}
}

func (s *server) quicSession(conn *quic.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ctl, err := conn.AcceptStream(ctx)
	cancel()
	if err != nil {
		_ = conn.CloseWithError(1, "no control stream")
		return
	}
	name, ok := hello(bufio.NewReader(ctl))
	if !ok {
		_ = conn.CloseWithError(1, "no hello")
		return
	}
	ss := &session{kind: "quic", conn: conn, name: name, w: ctl}
	if _, err := fmt.Fprintf(ctl, "GEN %d\n", s.gen); err != nil {
		return
	}
	s.add(ss)
	go s.bulk(conn)
	<-conn.Context().Done()
	s.remove(ss)
}

func hello(br *bufio.Reader) (string, bool) {
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HELLO ") {
		return "", false
	}
	return strings.TrimSpace(line[6:]), true
}

func (s *server) add(ss *session) {
	s.mu.Lock()
	ss.draining = s.draining
	s.sessions[ss] = true
	s.mu.Unlock()
}

func (s *server) remove(ss *session) {
	s.mu.Lock()
	delete(s.sessions, ss)
	s.mu.Unlock()
}

// bulk serves connector-opened streams that send data to measure throughput: it reads to EOF
// and answers with the byte count and the time it took.
func (s *server) bulk(conn *quic.Conn) {
	for {
		st, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			t := time.Now()
			n, _ := io.Copy(io.Discard, st)
			fmt.Fprintf(st, "%d %d %d\n", n, time.Since(t).Microseconds(), s.gen)
			_ = st.Close()
		}()
	}
}

// ---- connectors over TCP: a TLS control connection; streams are TLS connections the connector
// dials back on request (a model of the reverse HTTP/2 session, enough for its availability) ----

func (s *server) acceptTunnels(l *net.TCPListener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go s.tunnel(tls.Server(c, s.tlsConf))
	}
}

func (s *server) tunnel(c *tls.Conn) {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	switch {
	case strings.HasPrefix(line, "STREAM "):
		id, _ := strconv.ParseUint(strings.TrimSpace(line[7:]), 10, 64)
		s.mu.Lock()
		ch := s.waiting[id]
		s.mu.Unlock()
		if ch == nil {
			c.Close()
			return
		}
		ch <- c
	case strings.HasPrefix(line, "HELLO "):
		ss := &session{kind: "tcp", ctl: c, name: strings.TrimSpace(line[6:]), w: c, done: make(chan struct{})}
		if _, err := fmt.Fprintf(c, "GEN %d\n", s.gen); err != nil {
			c.Close()
			return
		}
		s.add(ss)
		_, _ = io.Copy(io.Discard, br) // until the connector or the gateway closes it
		s.remove(ss)
		c.Close()
	default:
		c.Close()
	}
}

// ---- visitors over UDP ----------------------------------------------------------------------

func (s *server) serveUDP() {
	b := make([]byte, 1500)
	for {
		n, addr, err := s.udpV.ReadFrom(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.mu.Lock()
		s.flows[addr.String()] = true
		s.mu.Unlock()
		out := append([]byte{byte(s.gen)}, b[:n]...)
		_, _ = s.udpV.WriteTo(out, addr)
		s.udpServed.Add(1)
	}
}

func (s *server) flowForeign(_ []byte, addr *net.UDPAddr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.flows[addr.String()]
}

// ---- the hand-off ---------------------------------------------------------------------------

// handoff runs one hand-off as the old process; it returns true once this process has drained
// and must exit, false if the hand-off failed or was refused and this process serves on.
func (s *server) handoff(quicStarted chan struct{}) bool {
	if s.active.Swap(true) {
		s.log.Printf("hand-off refused: one is in progress")
		writeOutcome(s.cfg.Run, outcome{Seq: int(time.Now().UnixNano()), State: "refused", Reason: "hand-off in progress", OldPID: os.Getpid(), Gen: s.gen})
		return false
	}
	start := time.Now()
	s.seq = int(start.UnixNano())
	fail := func(reason string) bool {
		s.log.Printf("hand-off failed: %s", reason)
		writeOutcome(s.cfg.Run, outcome{Seq: s.seq, State: "failed", Reason: reason, OldPID: os.Getpid(), Gen: s.gen, Took: time.Since(start).String()})
		s.active.Store(false)
		return false
	}
	// At most one old process: a predecessor still draining ends its drain now.
	s.mu.Lock()
	p := s.parent
	s.mu.Unlock()
	if p != nil {
		s.log.Printf("ending the predecessor's drain first")
		_, _ = p.Write([]byte("CUT\n"))
		for t := time.Now(); time.Since(t) < 10*time.Second; time.Sleep(20 * time.Millisecond) {
			s.mu.Lock()
			p = s.parent
			s.mu.Unlock()
			if p == nil {
				break
			}
		}
		<-quicStarted
	}
	var files []*os.File
	for _, x := range []interface{ File() (*os.File, error) }{s.tcp, s.tun, s.udpV.real, s.udpQ.real} {
		f, err := x.File()
		if err != nil {
			closeAll(files...)
			return fail(err.Error())
		}
		files = append(files, f)
	}
	entries := []entry{{Name: "visitor-tcp", Net: "tcp", Addr: s.cfg.TCP}, {Name: "tunnel-tcp", Net: "tcp", Addr: s.cfg.Tunnel},
		{Name: "visitor-udp", Net: "udp", Addr: s.cfg.UDP}, {Name: "agent-quic", Net: "udp", Addr: s.cfg.QUIC}}
	var relayV, relayQ *os.File
	if s.cfg.Mode == modeRelay {
		var cv, cq *os.File
		var err error
		if relayV, cv, err = socketpairFiles(syscall.SOCK_DGRAM, "relay-v"); err != nil {
			return fail(err.Error())
		}
		if relayQ, cq, err = socketpairFiles(syscall.SOCK_DGRAM, "relay-q"); err != nil {
			return fail(err.Error())
		}
		files = append(files, cv, cq)
		entries = append(entries, entry{Name: "relay-visitor-udp", Net: "unixgram"}, entry{Name: "relay-agent-quic", Net: "unixgram"})
	}
	var extraEnv []string
	if b, err := os.ReadFile(filepath.Join(s.cfg.Run, "inject")); err == nil {
		switch strings.TrimSpace(string(b)) {
		case "extra": // a socket the manifest does not name
			if u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err == nil {
				if f, err := u.File(); err == nil {
					files = append(files, f)
				}
				u.Close()
			}
		case "wrong": // the manifest's visitor-tcp is a listener on another port
			if l, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
				f, _ := l.(*net.TCPListener).File()
				files[0].Close()
				files[0] = f
				l.Close()
			}
		case "notready":
			extraEnv = append(extraEnv, "S10_NOT_READY=1")
		}
		_ = os.Remove(filepath.Join(s.cfg.Run, "inject"))
	}
	args := append([]string{"serve"}, os.Args[2:]...)
	cmd, status, err := spawn(s.cfg.Bin, args, s.gen+1, files, entries, extraEnv)
	closeAll(files...)
	if err != nil {
		closeAll(relayV, relayQ)
		return fail(err.Error())
	}
	ch := lineReader(status)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case msg, ok := <-ch:
		if !ok || msg != "READY" {
			_ = cmd.Process.Kill()
			<-exited
			closeAll(relayV, relayQ, status)
			return fail(fmt.Sprintf("the new process ended before it was ready (%q)", msg))
		}
	case err := <-exited:
		closeAll(relayV, relayQ, status)
		return fail(fmt.Sprintf("the new process exited: %v", err))
	case <-time.After(s.cfg.ReadyWindow):
		_ = cmd.Process.Kill()
		<-exited
		closeAll(relayV, relayQ, status)
		return fail("the new process was not ready within the readiness window")
	}
	// Switch: stop accepting, relay or keep the datagrams, tell the connectors to move.
	ready := time.Since(start)
	_ = s.tcp.Close()
	_ = s.tun.Close()
	switch s.cfg.Mode {
	case modeRelay:
		_ = s.ql.Close()
		s.udpQ.startRelayOut(relayQ, quicForeign(byte(s.gen), 8))
		s.udpV.startRelayOut(relayV, s.flowForeign)
	case modePause:
		_ = s.ql.Close() // no new QUIC connection here: connectors on auto move over TCP
	case modeNoRelay:
		_ = s.ql.Close()
		s.udpV.Close() // only the new process reads the visitor socket
	}
	s.mu.Lock()
	s.draining = true
	for x := range s.sessions {
		x.draining = true
		_, _ = x.w.Write([]byte("DRAIN\n"))
	}
	s.mu.Unlock()
	writeOutcome(s.cfg.Run, outcome{Seq: s.seq, State: "ok", OldPID: os.Getpid(), NewPID: cmd.Process.Pid, Gen: s.gen + 1, Took: ready.String()})
	s.log.Printf("hand-off to pid %d ready after %v; draining for %v", cmd.Process.Pid, ready, s.cfg.Drain)
	go func() {
		for msg := range ch {
			if msg == "CUT" {
				s.log.Printf("the new process ends the drain early")
				s.cutOnce.Do(func() { close(s.cut) })
			}
		}
	}()
	select {
	case <-time.After(s.cfg.Drain):
	case <-s.cut:
	}
	s.mu.Lock()
	nv, ns := len(s.visitors), len(s.sessions)
	s.mu.Unlock()
	s.log.Printf("drain over: cutting %d visitor connections and %d sessions; relayed %d+%d datagrams, dropped %d+%d; served %d udp datagrams",
		nv, ns, s.udpQ.Relayed.Load(), s.udpV.Relayed.Load(), s.udpQ.Dropped.Load(), s.udpV.Dropped.Load(), s.udpServed.Load())
	s.stop()
	_, _ = status.Write([]byte("DONE\n"))
	status.Close()
	return true
}

func (s *server) stop() {
	s.mu.Lock()
	for c := range s.visitors {
		c.Close()
	}
	for x := range s.sessions {
		if x.kind == "quic" {
			_ = x.conn.CloseWithError(0, "drain over")
		} else {
			x.ctl.Close()
		}
	}
	s.mu.Unlock()
	_ = s.tcp.Close()
	_ = s.tun.Close()
	if s.ql != nil {
		_ = s.ql.Close()
		_ = s.tr.Close()
	}
	_ = s.udpQ.Close()
	_ = s.udpV.Close()
}

func closeAll(fs ...*os.File) {
	for _, f := range fs {
		if f != nil {
			f.Close()
		}
	}
}
