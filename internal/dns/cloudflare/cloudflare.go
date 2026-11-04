// SPDX-License-Identifier: Apache-2.0

// Package cloudflare is rpmgr's Cloudflare v4 API client, the dns.Provider of Cloudflare
// (docs/15-dns.md, "Cloudflare specifics"). It uses net/http and a handful of endpoints.
//
// The API base URL is compiled in: no setting, environment variable or option of a production
// build changes it, so no one can point rpmgr at a server that collects tokens. Tests use an
// unexported constructor, and other packages' tests the one behind the build tag rpmgrtest (D60).
// The token is a secret.Value and appears in no error, log line or formatted value.
package cloudflare

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/proxyenv"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// BaseURL is the Cloudflare API, compiled in.
const BaseURL = "https://api.cloudflare.com/client/v4"

// The limits of the Cloudflare Free plan, which the client enforces before it sends anything; the
// values and their sources are in docs/15-dns.md, "Cloudflare specifics" and "Timers and limits".
const (
	MaxBatchOps   = 200
	MaxCommentLen = 100
	perPage       = 50 // the largest page of GET /zones
	maxPages      = 10000
	maxBody       = 4 << 20
	timeout       = 30 * time.Second
	defaultBlock  = 5 * time.Minute // a 429 without Retry-After: Cloudflare blocks for 5 minutes
)

// Config names the credential. An empty AccountID is a user token, checked at
// /user/tokens/verify; otherwise an account-owned token of that account.
type Config struct {
	Token     secret.Value
	AccountID string
}

// Client is a Cloudflare provider account.
type Client struct {
	base    string
	token   secret.Value
	account string
	hc      *http.Client
	now     func() time.Time
}

var _ dns.Provider = (*Client)(nil)

// New returns a client for the compiled-in API, through the proxy the environment names
// (proxyenv), over TLS 1.2 or later against the system roots, as for other third-party servers
// (docs/04-security.md).
func New(cfg Config) (*Client, error) {
	return newClient(cfg, BaseURL, nil)
}

// newClient is the constructor tests use: base is the API URL and tr the transport, nil for the
// production one.
func newClient(cfg Config, base string, tr *http.Transport) (*Client, error) {
	if cfg.Token.IsZero() {
		return nil, errors.New("cloudflare: no token")
	}
	if tr == nil {
		tr = &http.Transport{
			Proxy:               proxyenv.FromEnvironment,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: timeout,
			ForceAttemptHTTP2:   true,
		}
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// A redirect would carry the token to another place; the answer is mapped as it is.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Client{base: base, token: cfg.Token, account: cfg.AccountID, hc: hc, now: time.Now}, nil
}

// String and GoString name the client and nothing else.
func (c *Client) String() string   { return "cloudflare.Client" }
func (c *Client) GoString() string { return "cloudflare.Client" }

// Caps returns what Cloudflare offers.
func (c *Client) Caps() dns.Capabilities {
	return dns.Capabilities{Comments: true, Proxy: true, Batch: true, ApexCNAME: true}
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []apiMessage    `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type apiMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// do sends one request and decodes the result into out (nil: ignored). It returns the number of
// pages the answer announces.
func (c *Client) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, c.scrub(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token.Reveal())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "rpmgr")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, c.scrub(fmt.Errorf("cloudflare: %s %s: %w", method, strings.SplitN(path, "?", 2)[0], err))
	}
	defer func() { _ = resp.Body.Close() }()
	var env envelope
	derr := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&env)
	if resp.StatusCode/100 != 2 || (derr == nil && !env.Success) {
		return 0, c.failure(resp, env)
	}
	if derr != nil {
		return 0, fmt.Errorf("cloudflare: HTTP %d: malformed response: %s", resp.StatusCode, c.redact(derr.Error()))
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return 0, fmt.Errorf("cloudflare: malformed result: %s", c.redact(err.Error()))
		}
	}
	if env.ResultInfo != nil {
		return env.ResultInfo.TotalPages, nil
	}
	return 1, nil
}

// failure maps an unsuccessful answer to a dns.ProviderError.
func (c *Client) failure(resp *http.Response, env envelope) error {
	e := &dns.ProviderError{Status: resp.StatusCode}
	for _, m := range env.Errors {
		e.Messages = append(e.Messages, c.redact(fmt.Sprintf("%d %s", m.Code, m.Message)))
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		e.Err = dns.ErrUnauthorized
	case http.StatusForbidden:
		e.Err = dns.ErrForbidden
	case http.StatusNotFound:
		e.Err = dns.ErrNotFound
	case http.StatusTooManyRequests:
		e.Err = dns.RateLimited{Until: c.retryUntil(resp.Header.Get("Retry-After"))}
	}
	return e
}

// retryUntil reads Retry-After, seconds or an HTTP date; a missing or unreadable one is the
// default block.
func (c *Client) retryUntil(h string) time.Time {
	now := c.now()
	if s, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && s >= 0 {
		return now.Add(time.Duration(s) * time.Second)
	}
	if t, err := http.ParseTime(h); err == nil {
		return t
	}
	return now.Add(defaultBlock)
}

// redact removes the token from a message; it should never be in one, and this is the net.
func (c *Client) redact(s string) string {
	if t := c.token.Reveal(); t != "" {
		s = strings.ReplaceAll(s, t, "[redacted]")
	}
	return s
}

func (c *Client) scrub(err error) error { return errors.New(c.redact(err.Error())) }

type tokenResult struct {
	ID        string     `json:"id"`
	Status    string     `json:"status"`
	ExpiresOn *time.Time `json:"expires_on"`
}

// validID reports whether s is a Cloudflare identifier, 32 lowercase hex characters [V VB-26]; one
// that is not never reaches a URL path, where "." and ".." would walk out of it.
func validID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func badID(what string) error {
	return fmt.Errorf("%w: the %s is not a 32-character lower-case hex identifier", dns.ErrInvalid, what)
}

// Verify checks the token: GET /user/tokens/verify, or /accounts/{id}/tokens/verify for an
// account-owned token. A token that is expired or disabled comes back with that Status.
func (c *Client) Verify(ctx context.Context) (dns.TokenInfo, error) {
	path := "/user/tokens/verify"
	if c.account != "" {
		if !validID(c.account) {
			return dns.TokenInfo{}, badID("account id")
		}
		path = "/accounts/" + url.PathEscape(c.account) + "/tokens/verify"
	}
	var r tokenResult
	if _, err := c.do(ctx, http.MethodGet, path, nil, &r); err != nil {
		return dns.TokenInfo{}, err
	}
	info := dns.TokenInfo{ID: r.ID, Status: r.Status}
	if r.ExpiresOn != nil {
		info.ExpiresAt = *r.ExpiresOn
	}
	return info, nil
}

type zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Type   string `json:"type"`
}

// ListZones returns every zone of the token, page by page.
func (c *Client) ListZones(ctx context.Context) ([]dns.Zone, error) {
	var all []dns.Zone
	err := c.pages(ctx, "/zones?", func(raw json.RawMessage) (int, error) {
		var zs []zone
		if err := json.Unmarshal(raw, &zs); err != nil {
			return 0, err
		}
		for _, z := range zs {
			all = append(all, dns.Zone{ID: z.ID, Name: strings.ToLower(z.Name), Status: z.Status, Type: z.Type})
		}
		return len(zs), nil
	})
	return all, err
}

type record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
}

func toRecord(r dns.Record) record { return record(r) }

// ListRecords returns every record of a zone, page by page.
func (c *Client) ListRecords(ctx context.Context, zoneID string) ([]dns.Record, error) {
	if !validID(zoneID) {
		return nil, badID("zone id")
	}
	var all []dns.Record
	err := c.pages(ctx, "/zones/"+url.PathEscape(zoneID)+"/dns_records?", func(raw json.RawMessage) (int, error) {
		var rs []record
		if err := json.Unmarshal(raw, &rs); err != nil {
			return 0, err
		}
		for _, r := range rs {
			all = append(all, dns.Record(r))
		}
		return len(rs), nil
	})
	return all, err
}

// pages fetches page after page of a listing until the announced last one, or an empty page.
func (c *Client) pages(ctx context.Context, path string, add func(json.RawMessage) (int, error)) error {
	for page := 1; page <= maxPages; page++ {
		var raw json.RawMessage
		total, err := c.do(ctx, http.MethodGet, path+"page="+strconv.Itoa(page)+"&per_page="+strconv.Itoa(perPage), nil, &raw)
		if err != nil {
			return err
		}
		n, err := add(raw)
		if err != nil {
			return fmt.Errorf("cloudflare: malformed result: %s", c.redact(err.Error()))
		}
		if page >= total || n == 0 {
			return nil
		}
	}
	return errors.New("cloudflare: a listing has too many pages")
}

// Apply sends the batch to POST /zones/{id}/dns_records/batch, which Cloudflare applies
// all-or-nothing. A batch of more than MaxBatchOps operations, or a record whose comment is longer
// than MaxCommentLen characters or has a line break, is refused (dns.ErrInvalid) before anything is
// sent. An empty batch sends nothing.
func (c *Client) Apply(ctx context.Context, zoneID string, b dns.Batch) error {
	if !validID(zoneID) {
		return badID("zone id")
	}
	if b.Len() == 0 {
		return nil
	}
	ids := slices.Clone(b.Deletes)
	for _, g := range [][]dns.Record{b.Patches, b.Puts} {
		for _, r := range g {
			ids = append(ids, r.ID)
		}
	}
	if slices.ContainsFunc(ids, func(id string) bool { return !validID(id) }) {
		return badID("record id")
	}
	if b.Len() > MaxBatchOps {
		return fmt.Errorf("%w: a batch has %d operations, at most %d", dns.ErrInvalid, b.Len(), MaxBatchOps)
	}
	body := struct {
		Deletes []struct {
			ID string `json:"id"`
		} `json:"deletes,omitempty"`
		Patches []record `json:"patches,omitempty"`
		Puts    []record `json:"puts,omitempty"`
		Posts   []record `json:"posts,omitempty"`
	}{}
	for _, id := range b.Deletes {
		body.Deletes = append(body.Deletes, struct {
			ID string `json:"id"`
		}{id})
	}
	for _, g := range []struct {
		from []dns.Record
		to   *[]record
	}{{b.Patches, &body.Patches}, {b.Puts, &body.Puts}, {b.Posts, &body.Posts}} {
		for _, r := range g.from {
			if utf8.RuneCountInString(r.Comment) > MaxCommentLen || strings.ContainsAny(r.Comment, "\r\n") {
				return fmt.Errorf("%w: the comment of %s is longer than %d characters or has a line break",
					dns.ErrInvalid, r.Name, MaxCommentLen)
			}
			*g.to = append(*g.to, toRecord(r))
		}
	}
	_, err := c.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records/batch", body, nil)
	return err
}
