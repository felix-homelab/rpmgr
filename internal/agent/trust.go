// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/pki"
)

// checkRootLimits applies the limits of docs/03-connections.md ("Trust roots in Welcome and
// snapshots") to roots as they came off the wire, before anything is parsed.
func checkRootLimits(der [][]byte) error {
	if len(der) > pki.MaxTrustCerts {
		return fmt.Errorf("agent: %d trust certificates offered, at most %d", len(der), pki.MaxTrustCerts)
	}
	for _, d := range der {
		if len(d) > pki.MaxTrustCertBytes {
			return fmt.Errorf("agent: a trust certificate of %d bytes offered, at most %d", len(d), pki.MaxTrustCertBytes)
		}
	}
	return nil
}

// parseOffered checks the limits and then parses the offered certificates.
func parseOffered(der [][]byte) ([]*x509.Certificate, error) {
	if err := checkRootLimits(der); err != nil {
		return nil, err
	}
	return parseDER(der)
}

// acceptRoots returns the roots an agent that trusts trusted (the pinned root first) in trust domain
// td keeps after being offered offered (docs/04-security.md, "Root rotation", "What an agent
// keeps"). An offered self-signed CA certificate is added only when the offer holds a
// cross-certificate for the same public key, Subject and SubjectKeyId whose signature verifies
// under a root already trusted, so a root in transit gains an attacker nothing. The agent trusts
// the self-signed certificate, never the cross-certificate. Everything else is ignored. A root
// that a cross-certificate of another new root vouches for is taken in the same call.
func acceptRoots(trusted []*x509.Certificate, td string, offered []*x509.Certificate, now time.Time) []*x509.Certificate {
	out := slices.Clone(trusted)
	for changed := true; changed; {
		changed = false
		for _, r := range offered {
			// One root per public key, the first one held: a later certificate for a key does not
			// replace it, and variants of one root cannot fill the slots.
			if len(out) >= pki.MaxTrustRoots || slices.ContainsFunc(out, func(h *x509.Certificate) bool {
				return bytes.Equal(h.RawSubjectPublicKeyInfo, r.RawSubjectPublicKeyInfo)
			}) {
				continue
			}
			if !validRoot(r, td, now) {
				continue
			}
			if !slices.ContainsFunc(offered, func(x *x509.Certificate) bool { return vouches(out, x, r, now) }) {
				continue
			}
			out = append(out, r)
			changed = true
		}
	}
	return out
}

// validRoot reports whether r is a CA certificate that signed itself, is valid at now and has the
// URI SAN spiffe://td and no other name.
func validRoot(r *x509.Certificate, td string, now time.Time) bool {
	return r.BasicConstraintsValid && r.IsCA && bytes.Equal(r.RawSubject, r.RawIssuer) && r.CheckSignatureFrom(r) == nil &&
		!now.Before(r.NotBefore) && !now.After(r.NotAfter) &&
		len(r.URIs) == 1 && r.URIs[0].String() == "spiffe://"+td &&
		len(r.DNSNames) == 0 && len(r.EmailAddresses) == 0 && len(r.IPAddresses) == 0
}

// vouches reports whether x is a cross-certificate for the root r that a root of trusted, valid at now, signed:
// the same public key, Subject and SubjectKeyId byte for byte, a CA with a path length of at least
// 1, valid at now.
func vouches(trusted []*x509.Certificate, x, r *x509.Certificate, now time.Time) bool {
	if x.Equal(r) || !x.BasicConstraintsValid || !x.IsCA || now.Before(x.NotBefore) || now.After(x.NotAfter) ||
		!bytes.Equal(x.RawSubjectPublicKeyInfo, r.RawSubjectPublicKeyInfo) || !bytes.Equal(x.RawSubject, r.RawSubject) ||
		len(r.SubjectKeyId) == 0 || !bytes.Equal(x.SubjectKeyId, r.SubjectKeyId) {
		return false
	}
	if x.MaxPathLen == 0 { // a path length of 0, set or not, cannot hold an intermediate
		return false
	}
	return slices.ContainsFunc(trusted, func(t *x509.Certificate) bool {
		return !now.Before(t.NotBefore) && !now.After(t.NotAfter) && bytes.Equal(x.RawIssuer, t.RawSubject) &&
			x.CheckSignatureFrom(t) == nil
	})
}

// trustSet is the roots an agent trusts: roots.pem, kept in step with it.
type trustSet struct {
	dir string
	td  string
	now func() time.Time
	log *slog.Logger

	mu    sync.Mutex
	certs []*x509.Certificate // the pinned root first
	pool  *x509.CertPool
}

func newTrustSet(l Loaded, now func() time.Time, log *slog.Logger) *trustSet {
	if now == nil {
		now = time.Now
	}
	return &trustSet{dir: l.Dir, td: l.TrustDomain, now: now, log: log, certs: slices.Clone(l.RootCerts), pool: l.Roots}
}

// Certs returns the certificates of roots.pem as the agent holds them.
func (t *trustSet) Certs() []*x509.Certificate {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.certs)
}

// Pool returns the roots as a pool; a later offer makes a new pool, so one in use stays unchanged.
func (t *trustSet) Pool() *x509.CertPool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pool
}

// Digest is the roots digest of Hello, of the roots as they are now.
func (t *trustSet) Digest() []byte { return pki.RootsDigest(t.Certs()) }

// Offer takes the trust roots of an authenticated Welcome or snapshot. Roots that fail the rule,
// and an offer past the limits, are logged and ignored; the caller never rejects its message for
// them. It reports whether the set grew.
func (t *trustSet) Offer(source string, der [][]byte) bool {
	if len(der) == 0 {
		return false
	}
	offered, err := parseOffered(der)
	if err != nil {
		t.log.Warn("ignoring the trust roots of "+source, "error", err)
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	next := acceptRoots(t.certs, t.td, offered, t.now())
	if len(next) == len(t.certs) {
		// Warn only of a certificate that signed itself and is not held: a cross-certificate and a
		// root held are the steady state of a rotation.
		for _, c := range offered {
			if !holdsKey(t.certs, c) && bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
				t.log.Warn("ignoring a root without a valid cross-certificate from a trusted root", "source", source)
				break
			}
		}
		return false
	}
	renamed, err := writeRoots(t.dir, next)
	switch {
	case err != nil && !renamed:
		t.log.Error("cannot store the trust roots; keeping the old ones", "error", err)
		return false
	case err != nil: // the file is the new one; the agent uses it now rather than disagree with it
		t.log.Warn("the new trust roots are stored but may not survive a power loss", "error", err)
	}
	pool := x509.NewCertPool()
	for _, c := range next {
		pool.AddCert(c)
	}
	t.certs, t.pool = next, pool
	t.log.Info("trusting a new root", "source", source, "roots", len(next))
	return true
}

func holdsKey(held []*x509.Certificate, c *x509.Certificate) bool {
	return slices.ContainsFunc(held, func(h *x509.Certificate) bool {
		return bytes.Equal(h.RawSubjectPublicKeyInfo, c.RawSubjectPublicKeyInfo)
	})
}

// writeRoots replaces roots.pem: a temporary file, fsync, rename, fsync of the directory, so that a
// crash leaves the old file or the new one. renamed reports whether the new file is in place, also
// when the final fsync failed.
func writeRoots(dir string, certs []*x509.Certificate) (renamed bool, err error) {
	if dir == "" {
		return false, errors.New("agent: no identity directory")
	}
	path := filepath.Join(dir, RootsFile)
	if err := writeAtomic(path, certsPEM(certs), 0o644, func() error { return rootsFault("before-rename") }); err != nil {
		return false, err
	}
	if err := rootsFault("after-rename"); err != nil {
		return true, err
	}
	return true, syncDir(dir)
}
