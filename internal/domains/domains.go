// SPDX-License-Identifier: Apache-2.0

// Package domains keeps the orgs' domain claims and decides which verified domain covers a
// hostname (docs/04-security.md, "Route and hostname ownership"; docs/06-data-model.md,
// "Routes"). Verification itself (DNS TXT at the authoritative nameservers, the HTTP token) comes
// with the domain API.
package domains

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/dnsname"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
)

// Errors of the package.
var (
	ErrInvalid  = dnsname.ErrInvalid
	ErrTaken    = errors.New("domains: the name is already claimed in this instance")
	ErrNotOwned = errors.New("domains: no verified domain of the org covers the hostname")
)

// Normalize returns name in the one form the store keeps; see dnsname.Normalize.
func Normalize(name string, wildcard bool) (string, error) {
	return dnsname.Normalize(name, wildcard)
}

// Covers reports whether a domain covers a normalised hostname: exactly its name, or with
// wildcard also every name below it, at any depth. A wildcard hostname "*.x" counts as the names
// below x. Labels are never matched partly: example.com does not cover badexample.com.
func Covers(fqdn string, wildcard bool, hostname string) bool {
	name := strings.TrimPrefix(hostname, "*.")
	starred := name != hostname
	if !starred && name == fqdn {
		return true
	}
	return wildcard && (name == fqdn && starred || strings.HasSuffix(name, "."+fqdn))
}

// challenge returns a new random challenge value: 32 lower-case base32 characters (160 bits).
func challenge() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// Claim records org's claim on fqdn, pending verification, with a new challenge value. A name
// claimed by any org, in any status, is ErrTaken.
func Claim(ctx context.Context, tx *ent.Tx, org, fqdn string, wildcard bool) (*ent.Domain, error) {
	name, err := Normalize(fqdn, false)
	if err != nil {
		return nil, err
	}
	value, err := challenge()
	if err != nil {
		return nil, err
	}
	d, err := tx.Domain.Create().SetOrgID(org).SetFqdn(name).SetWildcard(wildcard).SetChallengeValue(value).Save(ctx)
	if store.IsUniqueViolation(err) {
		return nil, ErrTaken
	}
	return d, err
}

// Covering returns the verified domain of org that covers hostname, the most specific one when
// several do: an exact claim before a wildcard, a longer name before a shorter one.
func Covering(ctx context.Context, tx *ent.Tx, org, hostname string) (*ent.Domain, error) {
	name, err := Normalize(hostname, true)
	if err != nil {
		return nil, err
	}
	// The candidates are the name itself and every parent of it: a few rows at most.
	bare := strings.TrimPrefix(name, "*.")
	labels := strings.Split(bare, ".")
	var candidates []string
	for i := 0; i < len(labels)-1; i++ {
		candidates = append(candidates, strings.Join(labels[i:], "."))
	}
	ds, err := tx.Domain.Query().Where(domain.OrgID(org), domain.StatusEQ(domain.StatusVerified), domain.FqdnIn(candidates...)).All(ctx)
	if err != nil {
		return nil, err
	}
	var best *ent.Domain
	for _, d := range ds {
		if !Covers(d.Fqdn, d.Wildcard, name) {
			continue
		}
		if best == nil || len(d.Fqdn) > len(best.Fqdn) || (len(d.Fqdn) == len(best.Fqdn) && !d.Wildcard) {
			best = d
		}
	}
	if best == nil {
		return nil, ErrNotOwned
	}
	return best, nil
}
