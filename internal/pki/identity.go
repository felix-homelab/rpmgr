// SPDX-License-Identifier: Apache-2.0

// Package pki is rpmgr's internal CA (docs/04-security.md, "PKI and identity"): the trust domain,
// the identities in certificates, the root and the name-constrained issuing intermediate, leaf
// certificates for agents and controller nodes, and certificates for the controller's signing
// keys.
package pki

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/ids"
)

// Kind is the role part of an identity.
type Kind string

// The roles that hold certificates.
const (
	KindConnector  Kind = "connector"
	KindGateway    Kind = "gateway"
	KindController Kind = "controller"
)

// idPrefix is the ID prefix of each kind (docs/06-data-model.md, "Identifiers").
var idPrefix = map[Kind]string{KindConnector: "con", KindGateway: "gw", KindController: "ctn"}

// Identity is a principal of one trust domain (docs/04-security.md, "Trust domain and identities").
type Identity struct {
	TrustDomain string
	Org         string // empty for controller nodes
	Kind        Kind
	ID          string
}

// SPIFFE returns the identity's SPIFFE ID, the certificate's single URI SAN.
func (id Identity) SPIFFE() *url.URL {
	path := "/controller/" + id.ID
	if id.Kind != KindController {
		path = "/org/" + id.Org + "/" + string(id.Kind) + "/" + id.ID
	}
	return &url.URL{Scheme: "spiffe", Host: id.TrustDomain, Path: path}
}

// DNSName returns the DNS SAN derived from the identity, which TLS clients use as ServerName.
func (id Identity) DNSName() string {
	return id.ID + "." + string(id.Kind) + "." + id.TrustDomain
}

// DNSNames returns every DNS SAN of the identity's certificate. Controller nodes also carry the
// shared names controller.<td> and reauth.controller.<td>.
func (id Identity) DNSNames() []string {
	if id.Kind == KindController {
		return []string{id.DNSName(), "controller." + id.TrustDomain, "reauth.controller." + id.TrustDomain}
	}
	return []string{id.DNSName()}
}

func (id Identity) String() string { return id.SPIFFE().String() }

// Validate checks the trust domain and that the org and the ID are rpmgr IDs of the right kind.
func (id Identity) Validate() error {
	if !ValidTrustDomain(id.TrustDomain) {
		return fmt.Errorf("pki: %q is not a trust domain", id.TrustDomain)
	}
	prefix, ok := idPrefix[id.Kind]
	switch {
	case !ok:
		return fmt.Errorf("pki: unknown kind %q", id.Kind)
	case !ids.Valid(prefix, id.ID):
		return fmt.Errorf("pki: %q is not a %s ID", id.ID, id.Kind)
	case id.Kind == KindController && id.Org != "":
		return errors.New("pki: a controller node belongs to no org")
	case id.Kind != KindController && !ids.Valid("org", id.Org):
		return fmt.Errorf("pki: %q is not an org ID", id.Org)
	}
	return nil
}

// ErrNotIdentity is returned for a URI that is not an rpmgr identity of the trust domain.
var ErrNotIdentity = errors.New("pki: not an rpmgr identity")

// ParseSPIFFE parses a URI SAN strictly: scheme spiffe, host exactly the trust domain (the name
// constraints also admit sub-domains and other case, so this check is needed), no user info,
// port, query or fragment, one of the identity paths, and IDs of the right kinds. A signing
// certificate's URI is not an identity.
func ParseSPIFFE(u *url.URL, td string) (Identity, error) {
	if u == nil || u.Scheme != "spiffe" || u.Host != td || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return Identity{}, fmt.Errorf("%w: %v", ErrNotIdentity, u)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	var id Identity
	switch {
	case len(parts) == 2 && parts[0] == "controller":
		id = Identity{TrustDomain: td, Kind: KindController, ID: parts[1]}
	case len(parts) == 4 && parts[0] == "org" && (parts[2] == string(KindConnector) || parts[2] == string(KindGateway)):
		id = Identity{TrustDomain: td, Org: parts[1], Kind: Kind(parts[2]), ID: parts[3]}
	default:
		return Identity{}, fmt.Errorf("%w: path %q", ErrNotIdentity, u.Path)
	}
	if err := id.Validate(); err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrNotIdentity, err)
	}
	return id, nil
}

// trustDomainRe is `rpmgr-` and 8 base32 characters (docs/04-security.md, "Trust domain and
// identities").
var trustDomainRe = regexp.MustCompile(`^rpmgr-[a-z2-7]{8}$`)

// ValidTrustDomain reports whether td has the form of a trust domain.
func ValidTrustDomain(td string) bool { return trustDomainRe.MatchString(td) }

// NewTrustDomain returns a new random trust domain, `rpmgr-` and 8 base32 characters (40 bits).
func NewTrustDomain() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[b[i]&31] // 256 is a multiple of 32, so every character is equally likely
	}
	return "rpmgr-" + string(b), nil
}
