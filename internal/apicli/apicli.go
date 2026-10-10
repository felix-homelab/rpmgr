// SPDX-License-Identifier: Apache-2.0

// Package apicli is the command line's side of the public API (docs/16-cli.md): the credentials
// `rpmgr login` stores, and the HTTP client that sends them.
package apicli

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// Credentials are what `rpmgr login` stores: the controller, the org and a personal API token of
// that org.
type Credentials struct {
	Controller string       `yaml:"controller"`
	Org        string       `yaml:"org"`
	Token      secret.Value `yaml:"-"`
	// CAFile verifies the controller's certificate instead of the system's roots.
	CAFile string `yaml:"ca_file,omitempty"`
}

// stored is the file's form of Credentials: the token in plain text, as the file holds it.
type stored struct {
	Controller string `yaml:"controller"`
	Org        string `yaml:"org"`
	Token      string `yaml:"token"`
	CAFile     string `yaml:"ca_file,omitempty"`
}

// ErrNotLoggedIn is returned when there are no stored credentials.
var ErrNotLoggedIn = errors.New("not logged in: run rpmgr login")

// Path is where the credentials are: $RPMGR_CREDENTIALS, else credentials.yaml in rpmgr's
// directory of the user's configuration directory.
func Path(getenv func(string) string) (string, error) {
	if p := getenv("RPMGR_CREDENTIALS"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rpmgr", "credentials.yaml"), nil
}

// Load reads the credentials at path. A file other users may read or write is refused, as it
// holds a token.
func Load(path string) (*Credentials, error) {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("the credentials file %s is open to other users (mode %04o); make it 0600", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the user's own credentials file
	if err != nil {
		return nil, err
	}
	var s stored
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("the credentials file %s: %w", path, err)
	}
	if s.Controller == "" || s.Org == "" || s.Token == "" {
		return nil, fmt.Errorf("the credentials file %s lacks the controller, org or token; run rpmgr login", path)
	}
	return &Credentials{Controller: s.Controller, Org: s.Org, Token: secret.FromBytes([]byte(s.Token)), CAFile: s.CAFile}, nil
}

// Save writes the credentials to path, readable by the user only, replacing any file there at
// once.
func Save(path string, c *Credentials) error {
	b, err := yaml.Marshal(stored{Controller: c.Controller, Org: c.Org, Token: c.Token.Reveal(), CAFile: c.CAFile})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credentials-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ControllerURL checks a controller's URL: https, with a host and nothing after it but a path.
func ControllerURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("the controller %q is not an https URL", raw)
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

// Client is an HTTP client for the controller's API: it trusts the CA file, if one is set, rather
// than the system's roots, and sends the token as a Bearer header, never in a URL.
func Client(c *Credentials) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the CA file %s holds no PEM certificate", c.CAFile)
		}
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: time.Minute, Transport: &bearer{token: c.Token, next: base}}, nil
}

// bearer adds the token to every request.
type bearer struct {
	token secret.Value
	next  http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (b *bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token.Reveal())
	return b.next.RoundTrip(r)
}
