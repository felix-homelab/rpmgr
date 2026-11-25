// SPDX-License-Identifier: Apache-2.0

// Package kms is rpmgr's own client for the Transit secrets engine of HashiCorp Vault and OpenBao.
// It wraps and unwraps data keys so that the KEK never reaches the controller ("KEK in Vault or
// OpenBao Transit" in docs/04-security.md). It needs net/http and encoding/json only.
package kms

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	defaultAppRole = "approle"
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

// AppRole holds the files of an AppRole login.
type AppRole struct {
	// Mount of the auth method; "approle" when empty.
	Mount string
	// RoleIDFile and SecretIDFile hold the role ID and the secret ID. The secret ID is read again at
	// each login.
	RoleIDFile, SecretIDFile string
}

// Config configures a Client. Exactly one of TokenFile and AppRole is set.
type Config struct {
	// Address is the base URL of Vault or OpenBao; https only.
	Address string
	// Mount of the Transit engine; "transit" when empty.
	Mount string
	// Key is the name of the Transit key.
	Key string
	// CAFile holds PEM certificates to verify the server against; the system roots when empty.
	CAFile string
	// TokenFile holds a token, mode 0600 or 0400.
	TokenFile string
	AppRole   *AppRole
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

	creds     atomic.Pointer[[]secret.Value] // role and secret ID of the last login, to redact
	mu        sync.Mutex
	token     secret.Value
	renewable bool
	renewAt   time.Time // zero: the token is never renewed
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
	if !mountRe.MatchString(mount) || strings.Contains(mount, "..") {
		return nil, errors.New("kms: the mount is not a valid Transit mount path")
	}
	if !keyRe.MatchString(cfg.Key) || cfg.Key == "." || cfg.Key == ".." {
		return nil, errors.New("kms: the key is not a valid Transit key name")
	}
	switch {
	case cfg.TokenFile != "" && cfg.AppRole != nil:
		return nil, errors.New("kms: use a token file or AppRole, not both")
	case cfg.TokenFile == "" && cfg.AppRole == nil:
		return nil, errors.New("kms: a token file or AppRole is needed")
	case cfg.AppRole != nil && (cfg.AppRole.RoleIDFile == "" || cfg.AppRole.SecretIDFile == ""):
		return nil, errors.New("kms: AppRole needs role_id_file and secret_id_file")
	}
	if cfg.AppRole != nil && cfg.AppRole.Mount != "" {
		m := strings.Trim(cfg.AppRole.Mount, "/")
		if !mountRe.MatchString(m) || strings.Contains(m, "..") {
			return nil, errors.New("kms: the AppRole mount is not a valid path")
		}
		a := *cfg.AppRole
		a.Mount = m
		cfg.AppRole = &a
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

// loadCA reads a PEM bundle that holds certificates and nothing else.
func loadCA(path string) (*x509.CertPool, error) {
	data, err := readFile(path, "CA file", false)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("kms: CA file %s holds no certificate in PEM form", path)
	}
	rest := bytes.TrimSpace(data)
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("kms: CA file %s holds something other than certificates", path)
		}
		end := bytes.Index(rest, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return nil, fmt.Errorf("kms: CA file %s holds a certificate that does not end", path)
		}
		rest = bytes.TrimSpace(rest[end+len("-----END CERTIFICATE-----"):])
	}
	return pool, nil
}

// readFile reads a regular file of at most maxFile bytes; a credential file must not be readable
// by group or others.
func readFile(path, what string, private bool) ([]byte, error) {
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

// readCredential reads a credential file and returns its content without surrounding white space.
func readCredential(path, what string) (secret.Value, error) {
	data, err := readFile(path, what, true)
	if err != nil {
		return secret.Value{}, err
	}
	v := bytes.TrimSpace(data)
	if len(v) == 0 {
		return secret.Value{}, fmt.Errorf("kms: %s %s is empty", what, path)
	}
	return secret.FromBytes(v), nil
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

// authInfo is the auth block of a login or renewal answer.
type authInfo struct {
	ClientToken   string `json:"client_token"`
	LeaseDuration int64  `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
}

// currentToken returns a token that is valid now: it loads one at first use and renews or
// replaces one that has reached half its lease.
func (c *Client) currentToken(ctx context.Context) (secret.Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token.IsZero() {
		if err := c.acquireLocked(ctx); err != nil {
			return secret.Value{}, err
		}
	}
	if !c.renewAt.IsZero() && !c.now().Before(c.renewAt) {
		c.refreshLocked(ctx)
	}
	return c.token, nil
}

// acquireLocked reads the token file or logs in.
func (c *Client) acquireLocked(ctx context.Context) error {
	if c.cfg.TokenFile != "" {
		tok, err := readCredential(c.cfg.TokenFile, "token file")
		if err != nil {
			return err
		}
		c.token, c.renewable, c.renewAt = tok, false, time.Time{}
		c.probeLocked(ctx)
		return nil
	}
	return c.loginLocked(ctx)
}

// probeLocked asks a token from a file about its lease by renewing it once. A token that cannot be
// renewed, as a root token or a non-renewable one, is used as it is until it fails.
func (c *Client) probeLocked(ctx context.Context) {
	a, err := c.authCall(ctx, "auth/token/renew-self", nil, c.token)
	if err != nil || !a.Renewable || a.LeaseDuration <= 0 {
		c.log.Debug("kms: token is not renewable", "renewed", err == nil)
		return
	}
	c.renewable = true
	c.renewAt = c.now().Add(time.Duration(a.LeaseDuration) * time.Second / 2)
}

// refreshLocked renews the token at half its lease; when it cannot, or when it is not renewable,
// it logs in again or reads the file again. A failure keeps the old token for the next request,
// which fails with the answer of Transit if the token is no longer valid.
func (c *Client) refreshLocked(ctx context.Context) {
	if c.renewable {
		a, err := c.authCall(ctx, "auth/token/renew-self", nil, c.token)
		if err == nil && a.LeaseDuration > 0 {
			c.renewAt = c.now().Add(time.Duration(a.LeaseDuration) * time.Second / 2)
			c.log.Debug("kms: token renewed", "lease_s", a.LeaseDuration)
			return
		}
		c.log.Warn("kms: token renewal failed", "error", errText(err))
	}
	if err := c.acquireLocked(ctx); err != nil {
		c.log.Warn("kms: new token not obtained", "error", errText(err))
		c.renewAt = c.now().Add(30 * time.Second) // try again later, not at every request
	}
}

// loginLocked logs in with AppRole. The secret ID file is read again each time.
func (c *Client) loginLocked(ctx context.Context) error {
	ar := c.cfg.AppRole
	roleID, err := readCredential(ar.RoleIDFile, "role ID file")
	if err != nil {
		return err
	}
	secretID, err := readCredential(ar.SecretIDFile, "secret ID file")
	if err != nil {
		return err
	}
	c.creds.Store(&[]secret.Value{roleID, secretID})
	mount := ar.Mount
	if mount == "" {
		mount = defaultAppRole
	}
	body, err := json.Marshal(map[string]string{"role_id": roleID.Reveal(), "secret_id": secretID.Reveal()})
	if err != nil {
		return err
	}
	a, err := c.authCall(ctx, "auth/"+mount+"/login", body, secret.Value{}, roleID, secretID)
	if err != nil {
		return fmt.Errorf("kms: AppRole login: %w", err)
	}
	if a.ClientToken == "" {
		return errors.New("kms: AppRole login: the answer holds no token")
	}
	c.token, c.renewable = secret.New(a.ClientToken), a.Renewable
	c.renewAt = time.Time{}
	if a.LeaseDuration > 0 {
		c.renewAt = c.now().Add(time.Duration(a.LeaseDuration) * time.Second / 2)
	}
	c.log.Debug("kms: logged in with AppRole", "lease_s", a.LeaseDuration, "renewable", a.Renewable)
	return nil
}

// authCall posts to an auth path and returns its auth block. A nil body is an empty object.
func (c *Client) authCall(ctx context.Context, path string, body []byte, token secret.Value, extra ...secret.Value) (authInfo, error) {
	if body == nil {
		body = []byte("{}")
	}
	var out struct {
		Auth authInfo `json:"auth"`
	}
	if err := c.send(ctx, http.MethodPost, path, body, token, &out, extra...); err != nil {
		return authInfo{}, err
	}
	return out.Auth, nil
}

// reauth is called at the first 403 of a request: it reads the token file again or logs in again.
// It reports whether the token changed.
func (c *Client) reauth(ctx context.Context, old secret.Value) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token.Reveal() != old.Reveal() {
		return true, nil // another request has already replaced it
	}
	if err := c.acquireLocked(ctx); err != nil {
		return false, err
	}
	return c.token.Reveal() != old.Reveal() || c.cfg.AppRole != nil, nil
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
// token and repeats once.
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	tok, err := c.currentToken(ctx)
	if err != nil {
		return err
	}
	err = c.send(ctx, method, path, body, tok, out)
	var te *Error
	if errors.As(err, &te) && te.Status == http.StatusForbidden {
		c.log.Debug("kms: 403, taking the credential again")
		changed, rerr := c.reauth(ctx, tok)
		if rerr != nil {
			return fmt.Errorf("%w (and the credential could not be read again: %s)", err, errText(rerr))
		}
		if changed {
			c.mu.Lock()
			tok = c.token
			c.mu.Unlock()
			err = c.send(ctx, method, path, body, tok, out)
		}
	}
	return err
}

// send makes one request with the retries of docs/03: a connection error, a 429 or a 5xx is tried
// again at most three times. secrets are values to redact from any message.
func (c *Client) send(ctx context.Context, method, path string, body []byte, token secret.Value, out any, secrets ...secret.Value) error {
	redact := append([]secret.Value{token}, secrets...)
	if known := c.creds.Load(); known != nil {
		redact = append(redact, *known...)
	}
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
		return reply{}, 0, fmt.Errorf("kms: the answer is longer than %d bytes", maxResponse)
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
