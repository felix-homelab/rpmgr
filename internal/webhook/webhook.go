// SPDX-License-Identifier: Apache-2.0

// Package webhook signs and sends webhook deliveries (docs/07-api.md, "Webhooks (Phase 2)";
// docs/04-security.md, "Webhooks and the egress guard (Phase 2)"): HTTPS only with the receiver's
// certificate verified, no redirect followed, every address checked by the egress guard at the
// moment it is dialled, a capped request and a capped read of the answer.
package webhook

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// The limits of a delivery (docs/03-connections.md, "Timeouts, keepalive and backoff") and the
// maximum age of a signature receivers accept (docs/04-security.md).
const (
	Timeout = 5 * time.Second
	// DialTimeout bounds one address of a receiver, so that a blackholed first address leaves
	// time for the next.
	DialTimeout = 2 * time.Second
	MaxBody     = 64 << 10
	MaxAnswer   = 64 << 10
	MaxAge      = 5 * time.Minute
)

// The headers of a delivery.
const (
	HeaderEventID   = "Rpmgr-Event-Id"
	HeaderEventType = "Rpmgr-Event-Type"
	HeaderSignature = "Rpmgr-Signature"
)

// Sign is the Rpmgr-Signature of body at t: t=<unix>,v1=<HMAC-SHA256(secret, t.body)>, one v1
// value per secret, keyed with the secret as it was shown, prefix included.
func Sign(t time.Time, body []byte, secrets ...string) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	parts := []string{"t=" + ts}
	for _, s := range secrets {
		parts = append(parts, "v1="+hex.EncodeToString(mac(s, ts, body)))
	}
	return strings.Join(parts, ",")
}

func mac(secret, ts string, body []byte) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "."))
	m.Write(body)
	return m.Sum(nil)
}

// Verify is the check documented for receivers: header must carry a v1 value of body under secret,
// with a timestamp at most MaxAge from now.
func Verify(header string, body []byte, secret string, now time.Time) error {
	var ts string
	var sigs [][]byte
	for _, p := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			if b, err := hex.DecodeString(v); err == nil {
				sigs = append(sigs, b)
			}
		}
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("webhook: the signature has no timestamp")
	}
	if age := now.Sub(time.Unix(unix, 0)); age > MaxAge || age < -MaxAge {
		return fmt.Errorf("webhook: the signature is %s old, more than %s", age.Round(time.Second), MaxAge)
	}
	want := mac(secret, ts, body)
	for _, s := range sigs {
		if subtle.ConstantTimeCompare(s, want) == 1 {
			return nil
		}
	}
	return errors.New("webhook: no signature matches")
}

// Envelope is what a delivery posts: the thin envelope of D144, never a resource or a secret.
type Envelope struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"`
	Time    time.Time `json:"time"`
	OrgID   *string   `json:"org_id"`
	Actor   Ref       `json:"actor"`
	Subject Ref       `json:"subject"`
	Summary string    `json:"summary"`
	Changed []string  `json:"changed"`
}

// Ref names an actor or a subject.
type Ref struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Body is the JSON envelope of e.
func Body(e events.Event) ([]byte, error) {
	env := Envelope{ID: e.ID, Type: e.Type, Time: e.Time.UTC(), Actor: Ref{Type: e.ActorType, ID: e.ActorID},
		Subject: Ref{Type: e.SubjectType, ID: e.SubjectID, Name: e.SubjectName}, Summary: e.Summary, Changed: e.Changed}
	if e.OrgID != "" {
		env.OrgID = &e.OrgID
	}
	if env.Changed == nil {
		env.Changed = []string{}
	}
	return json.Marshal(env)
}

// Delivery is one request to one endpoint.
type Delivery struct {
	URL       string
	EventID   string
	EventType string
	Body      []byte
	Secrets   []secret.Value // the current secret, then the previous one while it still signs
	Policy    egress.Policy
}

// ErrNotDelivered marks a delivery that was not sent, or had no 2xx answer.
var ErrNotDelivered = errors.New("webhook: not delivered")

// Sender sends deliveries.
type Sender struct {
	// Lookup resolves a receiver's name; nil is the system resolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Proxy picks the proxy of a request, as proxyenv.FromEnvironment does; nil is none.
	Proxy func(*http.Request) (*url.URL, error)
	// RootCAs replaces the system roots; only tests set it.
	RootCAs *x509.CertPool
	Now     func() time.Time
}

// Send posts d and returns the answer's status code; an error wraps ErrNotDelivered, and an
// address the guard refused also an egress.RefusedError.
func (s *Sender) Send(ctx context.Context, d Delivery) (int, error) {
	u, err := url.Parse(d.URL)
	switch {
	case err != nil:
		return 0, fmt.Errorf("%w: the URL does not parse", ErrNotDelivered)
	case u.Scheme != "https" || u.Host == "" || u.User != nil:
		return 0, fmt.Errorf("%w: only https:// URLs without credentials are delivered to", ErrNotDelivered)
	case len(d.Body) > MaxBody:
		return 0, fmt.Errorf("%w: the event is larger than %d bytes", ErrNotDelivered, MaxBody)
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(string(d.Body)))
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrNotDelivered, err)
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "rpmgr-webhook")
	req.Header.Set(HeaderEventID, d.EventID)
	req.Header.Set(HeaderEventType, d.EventType)
	keys := make([]string, len(d.Secrets))
	for i, k := range d.Secrets {
		keys[i] = k.Reveal()
	}
	req.Header.Set(HeaderSignature, Sign(now(), d.Body, keys...))
	var proxy *url.URL
	if s.Proxy != nil {
		if proxy, err = s.Proxy(req); err != nil {
			return 0, fmt.Errorf("%w: %w", ErrNotDelivered, err)
		}
	}
	tr := &http.Transport{
		DialContext:         func(ctx context.Context, _, addr string) (net.Conn, error) { return s.dial(ctx, addr, d.Policy, proxy) },
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: s.RootCAs},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: Timeout,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		// The URL, which may hold a token of the receiver's, stays out of the error.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, fmt.Errorf("%w: %w", ErrNotDelivered, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxAnswer))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("%w: the receiver answered %d", ErrNotDelivered, resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// dial connects to addr, a host and port of the receiver: it resolves the host and dials each
// address the policy admits, checked once more as it is dialled, directly or through the proxy,
// which is asked to connect to the checked address.
func (s *Sender) dial(ctx context.Context, addr string, p egress.Policy, proxy *url.URL) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else if s.Lookup != nil {
		addrs, err = s.Lookup(ctx, host)
		if err != nil {
			return nil, err
		}
	} else if addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, err
	}
	var first error
	for _, a := range addrs {
		if err := p.Check(a); err != nil {
			first = cmp(first, err)
			continue
		}
		target := net.JoinHostPort(a.Unmap().String(), port)
		var conn net.Conn
		actx, cancel := context.WithTimeout(ctx, DialTimeout)
		if proxy == nil {
			conn, err = (&net.Dialer{Control: p.Control}).DialContext(actx, "tcp", target)
		} else {
			conn, err = connect(actx, proxy, target)
		}
		cancel()
		if err == nil {
			return conn, nil
		}
		first = cmp(first, err)
	}
	if first == nil {
		first = fmt.Errorf("%s has no address", host)
	}
	return nil, first
}

func cmp(first, err error) error {
	if first != nil {
		return first
	}
	return err
}

// connect asks an http:// or https:// proxy to connect to target, a checked address.
func connect(ctx context.Context, proxy *url.URL, target string) (net.Conn, error) {
	if proxy.Scheme != "http" && proxy.Scheme != "https" {
		return nil, fmt.Errorf("webhook deliveries go through http:// and https:// proxies, not %s://", proxy.Scheme)
	}
	host := proxy.Host
	if proxy.Port() == "" {
		host = net.JoinHostPort(proxy.Hostname(), map[string]string{"http": "80", "https": "443"}[proxy.Scheme])
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	if proxy.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: proxy.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = tc
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: http.Header{}}
	if u := proxy.User; u != nil {
		pw, _ := u.Password()
		req.SetBasicAuth(u.Username(), pw)
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("the proxy answered %s", resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// Describe is the text of a failed delivery for the endpoint's owners: a refused address is named
// by its reason and the range that would admit it, never itself, and no text names the URL.
func Describe(err error) string {
	var re *egress.RefusedError
	if errors.As(err, &re) {
		s := "the egress guard refused the receiver's address: " + re.Reason
		if re.Range.IsValid() {
			s += "; listing " + re.Range.String() + " in webhook_private_ranges admits it"
		}
		return s
	}
	s := strings.TrimPrefix(err.Error(), ErrNotDelivered.Error()+": ")
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
