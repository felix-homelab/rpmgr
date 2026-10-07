// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// maxBundle bounds the trust-bundle download.
const maxBundle = 1 << 20

// EnrollOptions are the inputs of `rpmgr enroll` (docs/16-cli.md).
type EnrollOptions struct {
	Controller  string // https://<host>[:<port>]
	Pin         string // --ca-pin
	Token       string
	IdentityDir string
	Replace     bool
	Bundle      []byte       // a PEM trust bundle; nil downloads it from the controller
	HTTPClient  *http.Client // for the download; nil uses the system roots and proxy variables
	Host        *agentv1.HostFacts
	Version     string
	Now         func() time.Time
}

// Enroll enrolls this host (docs/03-connections.md, "Enrollment"; docs/04-security.md, "Join
// command"): it keeps the one root of the trust bundle that matches the pin and reads the trust
// domain from it, generates a P-256 key, sends a CSR bound to its TLS connection to
// controller.<td> while trusting only that root, checks the response against the root and its own
// key, and writes the identity directory. Nothing is written unless enrollment succeeded.
func Enroll(ctx context.Context, o EnrollOptions) (Identity, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if !pki.ValidPin(o.Pin) {
		return Identity{}, errors.New("agent: --ca-pin must be sha256:<base64 of 32 bytes>")
	}
	if k, err := token.Parse(o.Token); err != nil || k != token.Enrollment {
		return Identity{}, errors.New("agent: the enrollment token is malformed or mistyped (rpmgr_enr_…)")
	}
	ctl, err := url.Parse(o.Controller)
	if err != nil || ctl.Scheme != "https" || ctl.Hostname() == "" {
		return Identity{}, fmt.Errorf("agent: --controller %q: want https://<host>[:<port>]", o.Controller)
	}
	if err := checkDir(o.IdentityDir, o.Replace); err != nil {
		return Identity{}, err
	}
	bundle := o.Bundle
	if bundle == nil {
		if bundle, err = download(ctx, o.HTTPClient, ctl.JoinPath("/.well-known/rpmgr/trust-bundle").String()); err != nil {
			return Identity{}, err
		}
	}
	certs, err := parseCerts(bundle)
	if err != nil {
		return Identity{}, err
	}
	root, td, err := pki.SelectPinnedRoot(certs, o.Pin)
	if err != nil {
		return Identity{}, err
	}
	key, err := pki.NewKey()
	if err != nil {
		return Identity{}, err
	}
	resp, err := enroll(ctx, o, root, td, hostPort(ctl), key)
	if err != nil {
		return Identity{}, err
	}
	chain, id, err := checkChain(resp.GetChain(), root, td, key, o.Now())
	if err != nil {
		return Identity{}, err
	}
	signing, err := parseDER(resp.GetSigningCertificates())
	if err != nil || len(signing) == 0 {
		return Identity{}, errors.New("agent: the response has no signing certificate")
	}
	if err := pki.VerifySigner(signing[0], signing[1:], root, pki.PurposeConfigSigning, o.Now()); err != nil {
		return Identity{}, fmt.Errorf("agent: the controller's signing certificate: %w", err)
	}
	offered, err := parseDER(resp.GetTrustBundle())
	if err != nil {
		return Identity{}, err
	}
	ident := Identity{AgentID: id.ID, Kind: string(id.Kind), TrustDomain: td, Endpoints: resp.GetControllerEndpoints(),
		Ephemeral: resp.GetEphemeral(), EnrolledAt: o.Now().UTC()}
	if resp.GetAgentId() != id.ID {
		return Identity{}, errors.New("agent: the response's agent ID is not the certificate's")
	}
	if err := writeIdentity(o.IdentityDir, key, chain, acceptRoots(root, offered), signing, ident); err != nil {
		return Identity{}, err
	}
	return ident, nil
}

// enroll calls Enrollment.Enroll with a CSR bound to the connection it is sent on. If grpc-go
// replaced the connection between the binding and the call, the controller refuses the CSR, and
// enroll builds a new one once.
func enroll(ctx context.Context, o EnrollOptions, root *x509.Certificate, td, addr string, key *ecdsa.PrivateKey) (*agentv1.EnrollResponse, error) {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	cfg := pki.ClientConfig(tls.Certificate{}, roots, "controller."+td,
		pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}}, o.Now, nil)
	cfg.Certificates = nil // an enrolling agent has no certificate yet
	creds := &bindingCreds{TransportCredentials: credentials.NewTLS(cfg)}
	cc, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer func() { _ = cc.Close() }()
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		state, err := connected(ctx, cc, creds)
		if err != nil {
			return nil, fmt.Errorf("agent: connect to controller.%s at %s: %w", td, addr, err)
		}
		csr, err := pki.NewBoundCSR(key, state)
		if err != nil {
			return nil, err
		}
		resp, err := agentv1.NewEnrollmentClient(cc).Enroll(ctx, &agentv1.EnrollRequest{
			Token: o.Token, Csr: csr.Raw, Host: o.Host, Version: o.Version})
		if err == nil {
			return resp, nil
		}
		last = err
		if status.Code(err) != codes.PermissionDenied { // the binding is the only reason Enroll gives it
			break
		}
	}
	return nil, fmt.Errorf("agent: enroll: %w", last)
}

// connected waits until cc is ready and returns the TLS state of its connection.
func connected(ctx context.Context, cc *grpc.ClientConn, creds *bindingCreds) (tls.ConnectionState, error) {
	cc.Connect()
	for {
		s := cc.GetState()
		if s == connectivity.Ready {
			if st, ok := creds.current(); ok {
				return st, nil
			}
		}
		if s == connectivity.TransientFailure {
			return tls.ConnectionState{}, creds.lastError()
		}
		if !cc.WaitForStateChange(ctx, s) {
			return tls.ConnectionState{}, ctx.Err()
		}
	}
}

// checkChain verifies the issued chain against the pinned root and the agent's own key, and
// returns it with the identity it carries.
func checkChain(der [][]byte, root *x509.Certificate, td string, key *ecdsa.PrivateKey, now time.Time) ([]*x509.Certificate, pki.Identity, error) {
	chain, err := parseDER(der)
	if err != nil || len(chain) == 0 {
		return nil, pki.Identity{}, errors.New("agent: the response has no certificate")
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, c := range chain[1:] {
		inters.AddCert(c)
	}
	leaf := chain[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, pki.Identity{}, fmt.Errorf("agent: the issued certificate: %w", err)
	}
	if !key.PublicKey.Equal(leaf.PublicKey) || len(leaf.URIs) != 1 {
		return nil, pki.Identity{}, errors.New("agent: the issued certificate is not for this host's key")
	}
	id, err := pki.ParseSPIFFE(leaf.URIs[0], td)
	if err != nil {
		return nil, pki.Identity{}, err
	}
	return chain, id, nil
}

// acceptRoots keeps the pinned root, and of the roots the authenticated response offers only those
// the pinned root cross-signed (docs/04-security.md, "Join command").
func acceptRoots(pinned *x509.Certificate, offered []*x509.Certificate) []*x509.Certificate {
	out := []*x509.Certificate{pinned}
	for _, c := range offered {
		if c.Equal(pinned) || !c.IsCA || c.CheckSignatureFrom(pinned) != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}

func parseDER(ders [][]byte) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(ders))
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, fmt.Errorf("agent: a certificate of the response: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

// download fetches the unauthenticated trust bundle; the pin, not the channel, authenticates it.
func download(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent: download the trust bundle: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: download the trust bundle: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBundle))
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// bindingCreds remembers the TLS state of the connection grpc-go opens, so the CSR can be bound
// to it.
type bindingCreds struct {
	credentials.TransportCredentials
	mu    sync.Mutex
	state *tls.ConnectionState
	err   error
}

// ClientHandshake runs the TLS handshake and records its state.
func (c *bindingCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
	if err == nil {
		st := info.(credentials.TLSInfo).State
		c.state = &st
	}
	return conn, info, err
}

func (c *bindingCreds) current() (tls.ConnectionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil {
		return tls.ConnectionState{}, false
	}
	return *c.state, true
}

func (c *bindingCreds) lastError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return errors.New("the connection failed")
}

// ReadToken returns the enrollment token from, in this order, the file at path, $RPMGR_ENROLL_TOKEN,
// or a prompt on the terminal; never from the command line (docs/04-security.md, "Join command").
// A token file open to other users is read, and warn reports it.
func ReadToken(path string, getenv func(string) string, prompt func() (string, error), warn func(string)) (string, error) {
	switch {
	case path != "":
		st, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if st.Mode().Perm()&0o077 != 0 && warn != nil {
			warn(fmt.Sprintf("the token file %s is open to other users (mode %04o); use 0600 and delete it after enrollment", path, st.Mode().Perm()))
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: the operator's --token-file
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	case getenv("RPMGR_ENROLL_TOKEN") != "":
		return strings.TrimSpace(getenv("RPMGR_ENROLL_TOKEN")), nil
	case prompt != nil:
		t, err := prompt()
		return strings.TrimSpace(t), err
	}
	return "", errors.New("agent: no enrollment token: use --token-file, RPMGR_ENROLL_TOKEN or a terminal")
}
