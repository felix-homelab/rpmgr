// SPDX-License-Identifier: Apache-2.0

// Package kms is rpmgr's own client for the Transit secrets engine of HashiCorp Vault and OpenBao.
// It wraps and unwraps data keys so that the KEK never reaches the controller ("KEK in Vault or
// OpenBao Transit" in docs/04-security.md). It needs net/http and encoding/json only.
package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// Limits and schedule of the client. The values are the single source in
// docs/03-connections.md ("Timeouts, keepalive and backoff"), Transit request.
const (
	requestTimeout = 10 * time.Second
	maxResponse    = 64 << 10
	maxRetries     = 3
	maxRetryAfter  = 5 * time.Second
	maxFile        = 64 << 10
	maxErrMessage  = 200
	defaultMount   = "transit"
)

var retryBackoff = [maxRetries]time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}

var (
	// ErrUnavailable means Transit could not be asked or answered with a failure that may pass: a
	// connection error, a timeout, a 429 or a 5xx that outlasted the retries.
	ErrUnavailable = errors.New("kms: transit unavailable")
	// ErrPermissionDenied means Transit refused the credential or the policy refuses the call.
	ErrPermissionDenied = errors.New("kms: transit permission denied")

	mountRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)
	keyRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// Config configures a Client.
type Config struct {
	// Address is the base URL of Vault or OpenBao; https only.
	Address string
	// Mount of the Transit engine; "transit" when empty.
	Mount string
	// Key is the name of the Transit key.
	Key string
	// CAFile holds PEM certificates to verify the server against; the system roots when empty.
	CAFile string
	// TokenFile holds a token, mode 0600 or 0400. It is read at first use and again at the first 403.
	TokenFile string
	// Logger receives debug and warning lines without any credential; nil logs nothing.
	Logger *slog.Logger
}

// Client is a Transit client for one key. It implements secret.Wrapper. It is safe for concurrent
// use.
type Client struct {
	base   *url.URL
	mount  string
	key    string
	cfg    Config
	http   *http.Client
	log    *slog.Logger
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
	reqTTL time.Duration

	latest atomic.Int64 // highest key version seen

	mu    sync.Mutex
	token secret.Value
	sum   [sha256.Size]byte // of the token read from the file, to tell a replaced one
	gen   uint64            // changes with every new token
}

// New returns a Client. It reads the CA file and checks the configuration but makes no call; Check
// asks Transit about the key.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Address)
	if err != nil || u.Host == "" {
		return nil, errors.New("kms: the address is not a URL")
	}
	if u.Scheme != "https" {
		return nil, errors.New("kms: the address must be an https URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("kms: the address holds credentials, a query or a fragment")
	}
	mount := strings.Trim(cfg.Mount, "/")
	if mount == "" {
		mount = defaultMount
	}
	if !validMount(mount) {
		return nil, errors.New("kms: the mount is not a valid Transit mount path")
	}
	if !keyRe.MatchString(cfg.Key) || cfg.Key == "." || cfg.Key == ".." {
		return nil, errors.New("kms: the key is not a valid Transit key name")
	}
	if cfg.TokenFile == "" {
		return nil, errors.New("kms: a token file is needed")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pool, err := loadCA(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = pool
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Client{
		base: u, mount: mount, key: cfg.Key, cfg: cfg, log: log, now: time.Now, sleep: sleepCtx,
		reqTTL: requestTimeout,
		http: &http.Client{
			Transport: &http.Transport{
				Proxy:               nil, // no proxy from the environment for Transit
				TLSClientConfig:     tlsCfg,
				ForceAttemptHTTP2:   true,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
			},
			// A redirect is not followed: it would send the token somewhere that was not configured.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// validMount accepts a path of segments of letters, digits, underscore, dot and hyphen, none of
// which is "." or "..".
func validMount(m string) bool {
	if !mountRe.MatchString(m) {
		return false
	}
	for seg := range strings.SplitSeq(m, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// loadCA reads a PEM bundle that holds certificates and nothing else: every block must be a
// certificate that parses, and nothing may stand between or after the blocks.
func loadCA(path string) (*x509.CertPool, error) {
	data, err := readFile(path, "CA file", false)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	n := 0
	rest := bytes.TrimSpace(data)
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("kms: CA file %s holds something other than PEM blocks", path)
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("kms: CA file %s holds a PEM block that is not a plain certificate", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("kms: CA file %s holds a certificate that does not parse", path)
		}
		pool.AddCert(cert)
		n++
		rest = bytes.TrimSpace(rest)
	}
	if n == 0 {
		return nil, fmt.Errorf("kms: CA file %s holds no certificate in PEM form", path)
	}
	return pool, nil
}

// readFile reads a regular file of at most maxFile bytes; a credential file must not be readable
// by group or others.
func readFile(path, what string, private bool) ([]byte, error) {
	// A FIFO or a device would block the open; a symbolic link to a file is followed.
	if pre, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("kms: %s: %w", what, err)
	} else if !pre.Mode().IsRegular() {
		return nil, fmt.Errorf("kms: %s %s: not a regular file", what, path)
	}
	f, err := os.Open(path) //nolint:gosec // G304: the path is the operator's boot configuration
	if err != nil {
		return nil, fmt.Errorf("kms: %s: %w", what, err)
	}
	defer func() { _ = f.Close() }() // read-only; a close error loses nothing
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("kms: %s: %w", what, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("kms: %s %s: not a regular file", what, path)
	}
	if perm := fi.Mode().Perm(); private && perm&0o077 != 0 {
		return nil, fmt.Errorf("kms: %s %s: mode %04o lets other users read it; use 0600 or 0400", what, path, perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, fmt.Errorf("kms: %s: %w", what, err)
	}
	if len(data) > maxFile {
		return nil, fmt.Errorf("kms: %s %s: more than %d bytes", what, path, maxFile)
	}
	return data, nil
}

// readCredential reads a credential file and returns its content without surrounding white space,
// and a digest of it to tell a replaced credential.
func readCredential(path, what string) (secret.Value, [sha256.Size]byte, error) {
	data, err := readFile(path, what, true)
	if err != nil {
		return secret.Value{}, [sha256.Size]byte{}, err
	}
	v := bytes.TrimSpace(data)
	if len(v) == 0 {
		return secret.Value{}, [sha256.Size]byte{}, fmt.Errorf("kms: %s %s is empty", what, path)
	}
	return secret.FromBytes(v), sha256.Sum256(v), nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ---- authentication ----

// currentToken returns the token to use and its generation. The first call reads the token file.
func (c *Client) currentToken() (secret.Value, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token.IsZero() {
		if err := c.readTokenLocked(); err != nil {
			return secret.Value{}, 0, err
		}
	}
	return c.token, c.gen, nil
}

// readTokenLocked reads the token file. A file that holds the token already in use changes nothing.
func (c *Client) readTokenLocked() error {
	tok, sum, err := readCredential(c.cfg.TokenFile, "token file")
	if err != nil {
		return err
	}
	if !c.token.IsZero() && c.sum == sum {
		return nil
	}
	c.token, c.sum = tok, sum
	c.gen++
	return nil
}

// reauth is called at the first 403 of a request made with the token of generation gen: it reads
// the token file again, so that a token an operator replaced is picked up without a restart. It
// reports whether a different token is now in use; the same token again is not tried twice.
func (c *Client) reauth(gen uint64) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen == gen {
		if err := c.readTokenLocked(); err != nil {
			return false, err
		}
	}
	return c.gen != gen, nil
}

// ---- requests ----

// Error is Transit's answer to a call that failed. It holds the status and the first message of
// the errors list, redacted and cut to 200 bytes; never a body, a token or a ciphertext.
type Error struct {
	Status  int
	Message string
	kind    error
}

// Error implements error.
func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("kms: transit answered %d", e.Status)
	}
	return fmt.Sprintf("kms: transit answered %d: %s", e.Status, e.Message)
}

// Is makes a 403 match ErrPermissionDenied and a 429 or 5xx match ErrUnavailable.
func (e *Error) Is(target error) bool { return e.kind != nil && target == e.kind }

// Call is the answer of one request.
type reply struct {
	status int
	body   []byte
}

// do runs an authenticated request with the token of the client. At the first 403 it takes a new
// token, if there is one, and repeats once. redact are values, such as a data key, that must not
// appear in any message.
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any, redact ...secret.Value) error {
	tok, gen, err := c.currentToken()
	if err != nil {
		return err
	}
	err = c.send(ctx, method, path, body, tok, out, redact...)
	var te *Error
	if errors.As(err, &te) && te.Status == http.StatusForbidden {
		c.log.Debug("kms: 403, reading the token file again")
		changed, rerr := c.reauth(gen)
		if rerr != nil {
			return fmt.Errorf("%w (and the credential could not be read again: %s)", err, errText(rerr))
		}
		if changed {
			c.mu.Lock()
			tok = c.token
			c.mu.Unlock()
			err = c.send(ctx, method, path, body, tok, out, redact...)
		}
	}
	return err
}

// send makes one request with the retries of docs/03: a connection error, a 429 or a 5xx is tried
// again at most three times. secrets are values to redact from any message.
func (c *Client) send(ctx context.Context, method, path string, body []byte, token secret.Value, out any, secrets ...secret.Value) error {
	redact := append([]secret.Value{token}, secrets...)
	var last error
	for attempt := 0; ; attempt++ {
		rep, wait, err := c.once(ctx, method, path, body, token, redact)
		if err == nil {
			if out == nil || len(rep.body) == 0 {
				return nil
			}
			if jerr := json.Unmarshal(rep.body, out); jerr != nil {
				return fmt.Errorf("%w: the answer is not the expected JSON", ErrUnavailable)
			}
			return nil
		}
		last = err
		var te *Error
		var tr *transportError
		retry := errors.As(err, &tr) && tr.retry && ctx.Err() == nil ||
			errors.As(err, &te) && (te.Status == http.StatusTooManyRequests || te.Status >= 500)
		if !retry || attempt >= maxRetries {
			return last
		}
		d := retryBackoff[attempt]
		if wait > 0 {
			d = min(wait, maxRetryAfter)
		}
		c.log.Warn("kms: transit call failed, trying again", "path", path, "attempt", attempt+1, "in", d)
		if serr := c.sleep(ctx, d); serr != nil {
			return fmt.Errorf("%w: %s", ErrUnavailable, errText(serr))
		}
	}
}

// once makes one HTTP request. A non-2xx answer is an *Error; a transport failure wraps
// ErrUnavailable. wait is the Retry-After of the answer.
func (c *Client) once(ctx context.Context, method, path string, body []byte, token secret.Value, redact []secret.Value) (reply, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, c.reqTTL)
	defer cancel()
	u := c.base.JoinPath("v1", path)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return reply{}, 0, fmt.Errorf("kms: %s", errText(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if !token.IsZero() {
		req.Header.Set("X-Vault-Token", token.Reveal())
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return reply{}, 0, newTransportError(err)
	}
	defer func() { _ = resp.Body.Close() }() // the body has been read or is abandoned
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return reply{}, 0, newTransportError(err)
	}
	if len(data) > maxResponse {
		return reply{}, 0, fmt.Errorf("%w: the answer is longer than %d bytes", ErrUnavailable, maxResponse)
	}
	c.log.Debug("kms: transit answered", "method", method, "path", path, "status", resp.StatusCode)
	if resp.StatusCode/100 == 2 {
		return reply{status: resp.StatusCode, body: data}, 0, nil
	}
	e := &Error{Status: resp.StatusCode, Message: errorMessage(data, redact)}
	switch {
	case resp.StatusCode == http.StatusForbidden:
		e.kind = ErrPermissionDenied
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		e.kind = ErrUnavailable
	}
	var wait time.Duration
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		wait = time.Duration(s) * time.Second
	}
	return reply{status: resp.StatusCode, body: data}, wait, e
}

// errorMessage returns the first message of the errors list of an answer, with every known
// credential and any ciphertext removed, control characters replaced and at most 200 bytes.
func errorMessage(body []byte, redact []secret.Value) string {
	var v struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &v) != nil || len(v.Errors) == 0 {
		return ""
	}
	return clean(v.Errors[0], redact)
}

var cipherRe = regexp.MustCompile(`vault:v[0-9]+:[A-Za-z0-9+/=_-]+`)

func clean(msg string, redact []secret.Value) string {
	for _, s := range redact {
		if r := s.Reveal(); r != "" {
			msg = strings.ReplaceAll(msg, r, secret.Redacted)
		}
	}
	msg = cipherRe.ReplaceAllString(msg, secret.Redacted)
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return ' '
		}
		return r
	}, msg)
	if len(msg) > maxErrMessage {
		msg = msg[:maxErrMessage]
		for !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
	}
	return msg
}

// transportError is a failure before an answer was complete. It matches ErrUnavailable; a failure
// to verify the server's certificate is not tried again, since it does not pass.
type transportError struct {
	msg   string
	retry bool
}

func newTransportError(err error) *transportError {
	var cv *tls.CertificateVerificationError
	return &transportError{msg: transportText(err), retry: !errors.As(err, &cv)}
}

func (e *transportError) Error() string        { return ErrUnavailable.Error() + ": " + e.msg }
func (e *transportError) Is(target error) bool { return target == ErrUnavailable }

// transportText describes a transport failure without the request: the URL and headers stay out.
func transportText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	return clean(err.Error(), nil)
}

// errText is the text of an error, cleaned and cut.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return clean(err.Error(), nil)
}
