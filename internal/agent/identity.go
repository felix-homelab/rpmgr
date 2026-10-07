// SPDX-License-Identifier: Apache-2.0

// Package agent is what gateways and connectors share: their identity on disk, enrollment, and
// (with later slices) the control session.
package agent

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The files of an identity directory (docs/10-operations.md, "Filesystem layout").
const (
	KeyFile     = "key.pem"     // the agent's private key, 0600
	ChainFile   = "chain.pem"   // its certificate and the intermediates
	RootsFile   = "roots.pem"   // the trusted roots: the pinned root, and roots it cross-signed
	SigningFile = "signing.pem" // the config-signing certificates and their intermediates
	AgentFile   = "agent.json"  // the agent's ID, trust domain and controller endpoints
)

// ErrAlreadyEnrolled is returned when the identity directory holds an identity and the caller did
// not ask to replace it.
var ErrAlreadyEnrolled = errors.New("agent: this host is already enrolled; use --replace to enroll it again")

// Identity is what agent.json records.
type Identity struct {
	AgentID     string    `json:"agent_id"`
	Kind        string    `json:"kind"`
	TrustDomain string    `json:"trust_domain"`
	Endpoints   []string  `json:"controller_endpoints"`
	Ephemeral   bool      `json:"ephemeral"`
	EnrolledAt  time.Time `json:"enrolled_at"`
}

// checkDir makes sure dir can take a new identity: it is created with mode 0700 if missing, it
// must not be open to the group or other users, and it must not hold an identity unless replace
// is set.
func checkDir(dir string, replace bool) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("agent: identity directory %q: want an absolute path", dir)
	}
	st, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(dir, 0o700)
	case err != nil:
		return err
	case !st.IsDir():
		return fmt.Errorf("agent: %s is not a directory", dir)
	case st.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("agent: identity directory %s has mode %04o; it must be closed to the group and other users (0700)", dir, st.Mode().Perm())
	}
	if _, err := os.Lstat(filepath.Join(dir, ChainFile)); err == nil && !replace {
		return ErrAlreadyEnrolled
	}
	return nil
}

// writeIdentity writes the identity files, each atomically, the key last-but-one and agent.json
// last, so an interrupted write leaves either the old identity or files that load incompletely
// and are rewritten by the next enrollment.
func writeIdentity(dir string, key *ecdsa.PrivateKey, chain, roots, signing []*x509.Certificate, id Identity) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	defer clear(keyPEM)
	agentJSON, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{ChainFile, certsPEM(chain), 0o644},
		{RootsFile, certsPEM(roots), 0o644},
		{SigningFile, certsPEM(signing), 0o644},
		{KeyFile, keyPEM, 0o600},
		{AgentFile, append(agentJSON, '\n'), 0o644},
	} {
		if err := writeAtomic(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

func certsPEM(certs []*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// writeAtomic writes data to a temporary file in path's directory with mode, syncs it and renames
// it over path.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op after the rename
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// parseCerts reads every CERTIFICATE block of a PEM bundle.
func parseCerts(bundle []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, bundle = pem.Decode(bundle)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("agent: trust bundle: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("agent: the trust bundle holds no certificate")
	}
	return out, nil
}

// Loaded is an identity read from its directory.
type Loaded struct {
	Identity
	Dir         string
	Certificate tls.Certificate
	Roots       *x509.CertPool
	Root        *x509.Certificate   // the pinned root, the first of roots.pem
	Signing     []*x509.Certificate // the config-signing certificates and their intermediates
}

// SPIFFE returns the agent's SPIFFE ID, from its certificate.
func (l Loaded) SPIFFE() string {
	if l.Certificate.Leaf == nil || len(l.Certificate.Leaf.URIs) != 1 {
		return ""
	}
	return l.Certificate.Leaf.URIs[0].String()
}

// Load reads the identity in dir. The key file must be closed to the group and other users.
func Load(dir string) (Loaded, error) {
	l := Loaded{Dir: dir}
	b, err := os.ReadFile(filepath.Join(dir, AgentFile)) //nolint:gosec // G304: the configured identity directory
	if err != nil {
		return l, err
	}
	if err := json.Unmarshal(b, &l.Identity); err != nil {
		return l, fmt.Errorf("agent: %s: %w", AgentFile, err)
	}
	keyPath := filepath.Join(dir, KeyFile)
	st, err := os.Stat(keyPath)
	if err != nil {
		return l, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return l, fmt.Errorf("agent: %s has mode %04o; it must be 0600", keyPath, st.Mode().Perm())
	}
	if l.Certificate, err = tls.LoadX509KeyPair(filepath.Join(dir, ChainFile), keyPath); err != nil {
		return l, err
	}
	rootsPEM, err := os.ReadFile(filepath.Join(dir, RootsFile)) //nolint:gosec // G304: the configured identity directory
	if err != nil {
		return l, err
	}
	roots, err := parseCerts(rootsPEM)
	if err != nil {
		return l, err
	}
	l.Roots, l.Root = x509.NewCertPool(), roots[0]
	for _, r := range roots {
		l.Roots.AddCert(r)
	}
	signingPEM, err := os.ReadFile(filepath.Join(dir, SigningFile)) //nolint:gosec // G304: the configured identity directory
	if err != nil {
		return l, err
	}
	if l.Signing, err = parseCerts(signingPEM); err != nil {
		return l, fmt.Errorf("agent: %s: %w", SigningFile, err)
	}
	return l, nil
}
