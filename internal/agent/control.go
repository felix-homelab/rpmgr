// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
)

// The agent's control-session timing (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	keepaliveTime    = 20 * time.Second
	keepaliveTimeout = 10 * time.Second
	// MaxSkew is the clock difference to the controller above which the agent warns.
	MaxSkew = 30 * time.Second
)

// ErrRevoked ends Run: the controller revoked this agent's identity.
var ErrRevoked = errors.New("agent: the controller revoked this agent; enroll it again")

// ClientOptions configure the control-session client.
type ClientOptions struct {
	Identity     Loaded
	Endpoints    []string // controller URLs, tried in order
	Version      string
	Capabilities []string
	BootID       string
	Now          func() time.Time
	Logger       *slog.Logger
	// Hello fills the revision and deny-list fields of a Hello (later slices); may be nil.
	Hello func(*agentv1.Hello)
	// OnWelcome gets every Welcome; may be nil.
	OnWelcome func(*agentv1.Welcome)
	// OnMessage gets every message after Welcome; may be nil.
	OnMessage func(*agentv1.ControllerMessage)
	// Backoff between attempts; nil is ControlBackoff.
	Backoff *Backoff
	// SaveCertificate stores a renewed key and chain before the client uses them; nil keeps them
	// in memory only.
	SaveCertificate func(key *ecdsa.PrivateKey, chain [][]byte) error
	// RenewJitter returns a number in [0, 1) that places each renewal within its window; nil is
	// random.
	RenewJitter func() float64
}

// Client keeps the agent's one control session to the controller.
type Client struct {
	o  ClientOptions
	mu sync.Mutex
	// state, for status and tests
	skew     time.Duration
	welcomes int
	goodbyes map[agentv1.GoodbyeReason]int
	endpoint string
	cert     tls.Certificate // the certificate new connections present
	// the current session, for Send, Renew and Reconnect
	sendMu sync.Mutex
	stream agentv1.Control_SessionClient
	live   bool // the controller welcomed the current session
	conn   *grpc.ClientConn
	creds  *stateCreds
	end    context.CancelFunc
}

// NewClient returns the control-session client.
func NewClient(o ClientOptions) *Client {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Backoff == nil {
		o.Backoff = ControlBackoff()
	}
	if o.RenewJitter == nil {
		o.RenewJitter = randomFraction
	}
	return &Client{o: o, goodbyes: map[agentv1.GoodbyeReason]int{}, cert: o.Identity.Certificate}
}

// Run keeps a control session until ctx ends or the controller revokes the agent. It tries the
// endpoints in order and moves to the next on a failure or a Drain; after a whole round failed,
// or after a session ended, it waits the backoff, at least a Goodbye's retry_after.
func (c *Client) Run(ctx context.Context) error {
	if len(c.o.Endpoints) == 0 {
		return errors.New("agent: no controller endpoint")
	}
	rctx, stopRenewal := context.WithCancel(ctx)
	renewing := make(chan struct{})
	go func() { c.renewLoop(rctx); close(renewing) }()
	defer func() { stopRenewal(); <-renewing }()
	next := 0
	for ctx.Err() == nil {
		start := c.o.Now()
		endpoints := c.Endpoints()
		ep := endpoints[next%len(endpoints)]
		var out outcome
		err := c.reauthIfExpired(ctx, ep)
		if err == nil {
			out, err = c.session(ctx, ep)
		}
		c.o.Backoff.Healthy(c.o.Now().Sub(start))
		switch {
		case ctx.Err() != nil:
			return nil
		case out.reason == agentv1.GoodbyeReason_GOODBYE_REASON_REVOKED:
			return ErrRevoked
		case out.drained || out.reason == agentv1.GoodbyeReason_GOODBYE_REASON_SHUTDOWN || err != nil && !out.welcomed:
			next++ // another endpoint
		}
		if err != nil {
			c.o.Logger.Warn("control session ended", "endpoint", ep, "error", err)
		}
		if out.drained && next%len(endpoints) != 0 {
			continue // move at once; the deadline is short
		}
		if !sleep(ctx, c.o.Backoff.Next(out.retryAfter)) {
			return nil
		}
	}
	return nil
}

// outcome is how a session ended.
type outcome struct {
	welcomed   bool
	drained    bool
	reason     agentv1.GoodbyeReason
	retryAfter time.Duration
}

// session runs one control session to endpoint until it ends.
func (c *Client) session(ctx context.Context, endpoint string) (outcome, error) {
	var out outcome
	addr, err := dialAddr(endpoint)
	if err != nil {
		return out, err
	}
	creds := c.credentials("controller." + c.o.Identity.TrustDomain)
	cc, err := grpc.NewClient("passthrough:///"+addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: keepaliveTime, Timeout: keepaliveTimeout, PermitWithoutStream: true}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(agentproto.MaxControlMessage), grpc.MaxCallSendMsgSize(agentproto.MaxControlMessage)))
	if err != nil {
		return out, err
	}
	defer func() { _ = cc.Close() }()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := agentv1.NewControlClient(cc).Session(sctx, grpc.WaitForReady(false))
	if err != nil {
		return out, err
	}
	hello := &agentv1.Hello{Version: c.o.Version, Capabilities: c.o.Capabilities, BootId: c.o.BootID,
		AgentTime: timestamppb.New(c.o.Now())}
	if c.o.Hello != nil {
		c.o.Hello(hello)
	}
	// io.EOF means the controller ended the stream first, as it does when it turns the agent away
	// before reading Hello; Recv then returns its Goodbye.
	if err := st.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Hello{Hello: hello}}); err != nil && !errors.Is(err, io.EOF) {
		return out, err
	}
	c.sendMu.Lock()
	c.stream, c.conn, c.creds, c.end = st, cc, creds, cancel
	c.sendMu.Unlock()
	defer func() {
		c.sendMu.Lock()
		c.stream, c.conn, c.creds, c.end, c.live = nil, nil, nil, nil, false
		c.sendMu.Unlock()
	}()
	for {
		m, err := st.Recv()
		if err != nil {
			return out, err
		}
		switch {
		case m.GetWelcome() != nil:
			out.welcomed = true
			c.welcome(endpoint, m.GetWelcome())
			c.sendMu.Lock()
			c.live = true
			c.sendMu.Unlock()
			if c.o.OnWelcome != nil {
				c.o.OnWelcome(m.GetWelcome())
			}
		case m.GetGoodbye() != nil:
			g := m.GetGoodbye()
			out.reason, out.retryAfter = g.GetReason(), g.GetRetryAfter().AsDuration()
			c.mu.Lock()
			c.goodbyes[g.GetReason()]++
			c.mu.Unlock()
			c.o.Logger.Info("controller said goodbye", "reason", g.GetReason().String(), "retry_after", out.retryAfter)
			return out, nil
		case m.GetDrain() != nil:
			out.drained = true
			c.o.Logger.Info("controller drains; moving to another endpoint", "endpoint", endpoint)
			return out, nil
		}
		if c.o.OnMessage != nil {
			c.o.OnMessage(m)
		}
	}
}

// welcome records the controller's clock against the agent's and warns about skew.
func (c *Client) welcome(endpoint string, w *agentv1.Welcome) {
	skew := w.GetServerTime().AsTime().Sub(c.o.Now())
	c.mu.Lock()
	c.skew, c.welcomes, c.endpoint = skew, c.welcomes+1, endpoint
	c.mu.Unlock()
	if skew > MaxSkew || -skew > MaxSkew {
		c.o.Logger.Warn("clock skew to the controller; TLS and certificate checks may fail", "skew", skew.Round(time.Second))
	}
}

// Connected reports whether the client has a control session that the controller welcomed.
func (c *Client) Connected() bool {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.live
}

// Send sends m on the current session; it reports false if there is none or the send failed, in
// which case the next session's Hello tells the controller what the agent runs.
func (c *Client) Send(m *agentv1.AgentMessage) bool {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.stream != nil && c.stream.Send(m) == nil
}

// SetEndpoints replaces the controller endpoints, as every snapshot names them; the next
// connection attempt uses them. An empty list is ignored.
func (c *Client) SetEndpoints(endpoints []string) {
	if len(endpoints) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.o.Endpoints = slices.Clone(endpoints)
}

// Endpoints returns the controller endpoints in the order the client tries them.
func (c *Client) Endpoints() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.o.Endpoints)
}

// Skew returns the controller's clock minus the agent's at the last Welcome.
func (c *Client) Skew() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.skew
}

// Stats returns how many Welcomes the client got, how many Goodbyes of each reason, and the
// endpoint of the last session.
func (c *Client) Stats() (welcomes int, goodbyes map[agentv1.GoodbyeReason]int, endpoint string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	g := make(map[agentv1.GoodbyeReason]int, len(c.goodbyes))
	for k, v := range c.goodbyes {
		g[k] = v
	}
	return c.welcomes, g, c.endpoint
}

// dialAddr turns a controller URL into host:port.
func dialAddr(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", fmt.Errorf("agent: controller endpoint %q: want https://<host>[:<port>]", endpoint)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
