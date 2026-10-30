// SPDX-License-Identifier: Apache-2.0

// Package objstore is a small client of S3-compatible object stores: SigV4 signing, PUT with a
// conditional create, GET, LIST and Object Lock headers. It is the client of the audit sink
// (docs/04, "External sinks") and of the revocation log. Timeouts and sizes are in docs/03.
package objstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits, as docs/03 states them for the object store.
const (
	// DefaultTimeout bounds one request, its body included.
	DefaultTimeout = 30 * time.Second
	// MaxObject is the largest object Get reads.
	MaxObject = 16 << 20
	// MaxKey is the longest key S3 accepts, in bytes.
	MaxKey = 1024
	// MaxListPage is the most keys one List call asks for.
	MaxListPage = 1000

	maxAnswer = 1 << 20 // an error or list answer read at most
)

// Errors a caller tells apart with errors.Is.
var (
	// ErrExists is the answer to a conditional create of a key that is taken (412).
	ErrExists = errors.New("objstore: the object exists")
	// ErrNotFound is the answer to a key or bucket that does not exist (404).
	ErrNotFound = errors.New("objstore: no such object")
)

// Error is an answer of the store other than success. Message is the store's own text; it holds
// no credentials.
type Error struct {
	Op      string
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	s := fmt.Sprintf("objstore %s: status %d", e.Op, e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// Is maps 404 and 412 to the sentinel errors.
func (e *Error) Is(target error) bool {
	return (target == ErrNotFound && e.Status == http.StatusNotFound) ||
		(target == ErrExists && e.Status == http.StatusPreconditionFailed)
}

// Refused reports whether the store answered with a client error (4xx) other than a request that
// may succeed when sent again. Object Lock refusals are this: AWS answers 403, SILO 400.
func Refused(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status >= 400 && e.Status < 500 && !Retryable(err)
}

// Retryable reports whether sending the request again later may succeed: a transport failure, a
// timeout, 5xx, 408, 429 and a concurrent conditional write (409).
func Retryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Status >= 500 || e.Status == http.StatusRequestTimeout ||
			e.Status == http.StatusTooManyRequests || e.Status == http.StatusConflict
	}
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) || errors.Is(err, io.ErrUnexpectedEOF)
}

// Config describes one bucket of one store.
type Config struct {
	// Endpoint is the store's base URL: https, or http for a loopback address only. It holds no
	// user name, path, query or fragment.
	Endpoint    string
	Region      string
	Bucket      string
	Credentials Credentials
	// VirtualHost addresses the bucket as bucket.host; the default is the path style, which
	// self-hosted stores take without DNS for each bucket.
	VirtualHost bool
	// RootCAs verifies the store's certificate; nil means the system's roots.
	RootCAs *x509.CertPool
	// Proxy chooses the proxy of a request; nil means HTTP_PROXY, HTTPS_PROXY and NO_PROXY.
	Proxy func(*http.Request) (*url.URL, error)
	// Timeout bounds one request; zero means DefaultTimeout.
	Timeout time.Duration
	// Now is the clock of the signature; nil means time.Now.
	Now func() time.Time
}

// Client talks to one bucket. It is safe for concurrent use.
type Client struct {
	base   *url.URL
	cfg    Config
	http   *http.Client
	bucket string
}

// New checks cfg and builds the client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("objstore: the endpoint is not a URL with a host")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("objstore: the endpoint must be a scheme and a host, nothing else")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip == nil || !ip.IsLoopback()) && u.Hostname() != "localhost" {
			return nil, errors.New("objstore: an http endpoint is allowed on a loopback address only")
		}
	default:
		return nil, errors.New("objstore: the endpoint scheme must be https")
	}
	if cfg.Region == "" || !printable(cfg.Region) || strings.ContainsAny(cfg.Region, "/") {
		return nil, errors.New("objstore: the region is empty or not a plain name")
	}
	if !validBucket(cfg.Bucket) {
		return nil, errors.New("objstore: the bucket name is not valid")
	}
	if err := cfg.Credentials.check(); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	proxy := cfg.Proxy
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}
	tr := &http.Transport{
		Proxy:               proxy,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
	}
	return &Client{base: u, cfg: cfg, bucket: cfg.Bucket, http: &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
		// A redirect would carry the signature to another host; the store's answer is an error.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Close drops idle connections.
func (c *Client) Close() { c.http.CloseIdleConnections() }

func validBucket(b string) bool {
	if len(b) < 3 || len(b) > 63 {
		return false
	}
	for i := 0; i < len(b); i++ {
		ch := b[i]
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' && ch != '.' {
			return false
		}
	}
	return b[0] != '-' && b[0] != '.' && b[len(b)-1] != '-' && b[len(b)-1] != '.'
}

func validKey(k string) error {
	if k == "" || len(k) > MaxKey || !utf8.ValidString(k) || strings.HasPrefix(k, "/") {
		return errors.New("objstore: the key is empty, too long, not UTF-8 or starts with a slash")
	}
	return nil
}

// PutOptions are the headers of a PUT.
type PutOptions struct {
	// IfNoneMatch makes the PUT a conditional create: a taken key answers ErrExists.
	IfNoneMatch bool
	// LockMode is "COMPLIANCE" or "GOVERNANCE" with RetainUntil, or empty for no lock.
	LockMode    string
	RetainUntil time.Time
	ContentType string
}

// Put writes body under key and returns the version ID the store assigned, empty in a bucket
// without versioning.
func (c *Client) Put(ctx context.Context, key string, body []byte, o PutOptions) (string, error) {
	if err := validKey(key); err != nil {
		return "", err
	}
	h := http.Header{}
	if o.IfNoneMatch {
		h.Set("If-None-Match", "*")
	}
	switch o.LockMode {
	case "":
		if !o.RetainUntil.IsZero() {
			return "", errors.New("objstore: a retain-until date needs a lock mode")
		}
	case "COMPLIANCE", "GOVERNANCE":
		if o.RetainUntil.IsZero() {
			return "", errors.New("objstore: a lock mode needs a retain-until date")
		}
		h.Set("X-Amz-Object-Lock-Mode", o.LockMode)
		h.Set("X-Amz-Object-Lock-Retain-Until-Date", o.RetainUntil.UTC().Format("2006-01-02T15:04:05.000Z"))
	default:
		return "", errors.New("objstore: the lock mode is COMPLIANCE or GOVERNANCE")
	}
	if o.ContentType != "" {
		h.Set("Content-Type", o.ContentType)
	}
	resp, err := c.do(ctx, "put", http.MethodPut, key, nil, h, body)
	if err != nil {
		return "", err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAnswer))
	_ = resp.Body.Close()
	return resp.Header.Get("X-Amz-Version-Id"), nil
}

// Get reads the object under key, at most MaxObject bytes; a larger object is an error.
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, "get", http.MethodGet, key, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxObject+1))
	if err != nil {
		return nil, fmt.Errorf("objstore get: %w", err)
	}
	if len(b) > MaxObject {
		return nil, fmt.Errorf("objstore get: the object is larger than %d bytes", MaxObject)
	}
	return b, nil
}

// Delete removes key, or one version of it; a locked version is refused (see Refused).
func (c *Client) Delete(ctx context.Context, key, versionID string) error {
	if err := validKey(key); err != nil {
		return err
	}
	q := url.Values{}
	if versionID != "" {
		q.Set("versionId", versionID)
	}
	resp, err := c.do(ctx, "delete", http.MethodDelete, key, q, nil, nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// Object is one entry of a listing.
type Object struct {
	Key  string
	Size int64
}

// Page is one answer of List. Next is empty after the last page.
type Page struct {
	Objects []Object
	Next    string
}

// List returns up to max keys (at most MaxListPage) that start with prefix, in key order, from
// the continuation token of an earlier page.
func (c *Client) List(ctx context.Context, prefix, token string, max int) (Page, error) {
	if max <= 0 || max > MaxListPage {
		max = MaxListPage
	}
	q := url.Values{"list-type": {"2"}, "max-keys": {strconv.Itoa(max)}}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	if token != "" {
		q.Set("continuation-token", token)
	}
	resp, err := c.do(ctx, "list", http.MethodGet, "", q, nil, nil)
	if err != nil {
		return Page{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var v struct {
		Truncated bool   `xml:"IsTruncated"`
		Next      string `xml:"NextContinuationToken"`
		Contents  []struct {
			Key  string `xml:"Key"`
			Size int64  `xml:"Size"`
		} `xml:"Contents"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, maxAnswer)).Decode(&v); err != nil {
		return Page{}, errors.New("objstore list: the answer is not a ListBucketResult")
	}
	p := Page{}
	for _, o := range v.Contents {
		p.Objects = append(p.Objects, Object{Key: o.Key, Size: o.Size})
	}
	if v.Truncated {
		if v.Next == "" {
			return Page{}, errors.New("objstore list: a truncated answer without a continuation token")
		}
		p.Next = v.Next
	}
	return p, nil
}

// do signs and sends one request; a non-2xx answer is an *Error and its body is consumed.
func (c *Client) do(ctx context.Context, op, method, key string, q url.Values, h http.Header, body []byte) (*http.Response, error) {
	u := *c.base
	path := "/"
	if c.cfg.VirtualHost {
		u.Host = c.bucket + "." + u.Host
	} else {
		path = "/" + c.bucket + "/"
	}
	path += key
	u.Path = path
	u.RawPath = escape(path, false)
	u.RawQuery = canonicalQuery(q)
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, fmt.Errorf("objstore %s: %w", op, err)
	}
	for k, v := range h {
		req.Header[k] = v
	}
	sign(req, hexSHA256(body), c.cfg.Credentials, c.cfg.Region, c.cfg.Now())
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is in the message already
		}
		return nil, fmt.Errorf("objstore %s: %w", op, err)
	}
	if resp.StatusCode/100 == 2 {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	e := &Error{Op: op, Status: resp.StatusCode}
	if method != http.MethodHead {
		var x struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		}
		if xml.NewDecoder(io.LimitReader(resp.Body, maxAnswer)).Decode(&x) == nil {
			e.Code, e.Message = clip(x.Code), clip(x.Message)
		}
	}
	return nil, e
}

// clip keeps a store's text short and printable, as it ends up in logs.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 200 {
		s = strings.ToValidUTF8(s[:200], "") + "..."
	}
	return s
}
