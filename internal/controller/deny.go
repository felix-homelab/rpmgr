// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// denyState is the controller's current deny-list (docs/04-security.md, "Revocation"): the sets
// its TLS layer checks, and the signed message agents get.
type denyState struct {
	serials, identities map[string]bool
	digest              []byte
	signed              *agentv1.Signed
}

func (d *denyState) denies(cert *x509.Certificate) bool {
	if d.serials[pki.SerialHex(cert.SerialNumber)] {
		return true
	}
	return len(cert.URIs) == 1 && d.identities[cert.URIs[0].String()]
}

// Denied reports whether cert is on the deny-list; it is pki.Expect.Denied for the agent
// endpoint. Before the first deny-list was loaded it asks the database, and refuses the
// certificate if the database does not answer.
func (s *Sessions) Denied(cert *x509.Certificate) bool {
	if d := s.deny.Load(); d != nil {
		return d.denies(cert)
	}
	switch err := pki.CheckRenewable(s.sys, s.db.Client(), cert); {
	case err == nil, errors.Is(err, pki.ErrNotIssued), errors.Is(err, pki.ErrSuperseded):
		return false
	default: // revoked, or the database did not answer
		return true
	}
}

// refreshDeny loads the deny-list from the database and signs it; changed reports whether it
// differs from the one before.
func (s *Sessions) refreshDeny() (changed bool, err error) {
	entries, err := pki.DenyList(s.sys, s.db.Client(), s.now())
	if err != nil {
		return false, err
	}
	signer := s.ca.ConfigSigner()
	digest := pki.DenyDigest(entries, snapshot.KeyID(signer.Cert))
	old := s.deny.Load()
	if old != nil && bytes.Equal(old.digest, digest) {
		return false, nil
	}
	var epoch string
	if err := store.ReadTx(s.sys, s.db, func(_ *ent.Tx, rev store.Revision) error {
		epoch = rev.DBEpoch
		return nil
	}); err != nil {
		return false, err
	}
	signed, err := snapshot.Sign(signer, &agentv1.DenyList{Full: true, Entries: entries,
		Version: &agentv1.Revision{DbEpoch: epoch, Seq: uint64(s.now().UnixMilli())}}) //nolint:gosec // G115: a time after 1970
	if err != nil {
		return false, err
	}
	d := &denyState{serials: map[string]bool{}, identities: map[string]bool{}, digest: digest, signed: signed}
	for _, e := range entries {
		if e.GetSerial() != "" {
			d.serials[e.GetSerial()] = true
		} else {
			d.identities[e.GetIdentity()] = true
		}
	}
	s.deny.Store(d)
	return true, nil
}

// denyLoop reloads the deny-list at every revision check, so that a revocation another process
// wrote is enforced too, and applies a changed one.
func (s *Sessions) denyLoop(ctx context.Context) {
	t := time.NewTicker(s.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.applyDeny()
		}
	}
}

// ApplyDenyList applies a revocation written in another transaction at once, rather than at the
// next revision check.
func (s *Sessions) ApplyDenyList() { s.applyDeny() }

// applyDeny reloads the deny-list and, if it changed, sends it to every session and ends the
// sessions of agents it now denies with Goodbye{revoked}.
func (s *Sessions) applyDeny() {
	changed, err := s.refreshDeny()
	if err != nil {
		s.log.Error("cannot load the deny-list", "error", err)
		return
	}
	if !changed {
		return
	}
	d := s.deny.Load()
	s.mu.Lock()
	sessions := make([]*session, 0, len(s.active))
	for _, sess := range s.active {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		if d.denies(sess.agent.Certificate) {
			sess.end(agentv1.GoodbyeReason_GOODBYE_REASON_REVOKED, 0)
			continue
		}
		select {
		case sess.out <- &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_DenyList{DenyList: d.signed}}:
		default:
			sess.cancel() // a full queue: the agent reconnects and gets the list after Hello
		}
	}
}

// logSuperseded appends superseded certificates to the revocation log. The supersession is
// committed whether or not the log takes it; a failure is reported.
func (s *Sessions) logSuperseded(rows []*ent.IssuedCertificate, actor string) {
	for _, r := range rows {
		appendLog(s.revlog, s.log, revlog.Entry{Kind: revlog.CertificateSuperseded, Org: deref(r.OrgID), Subject: r.ID,
			NotAfter: &r.NotAfter, Actor: actor})
	}
}

func appendLog(l *revlog.Log, log interface{ Error(string, ...any) }, e revlog.Entry) {
	if l == nil {
		return
	}
	if _, err := l.Append(e); err != nil {
		log.Error("cannot append to the revocation log", "kind", e.Kind, "subject", e.Subject, "error", err)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Revoker revokes certificates and identities (docs/04-security.md, "Revocation"): in the
// database with an audit record, in the revocation log, and at once on the sessions of this
// controller. Other replicas pick a revocation up at their next revision check.
type Revoker struct {
	Sessions *Sessions
	Log      *revlog.Log
}

// Actor is who revokes, for the audit log and the revocation log.
type Actor struct {
	Type audit.ActorType
	ID   string
}

// RevokeCertificate revokes the certificate with serial. ctx carries the caller's scope.
func (r Revoker) RevokeCertificate(ctx context.Context, serial, reason string, actor Actor) error {
	s := r.Sessions
	err := store.WriteTx(ctx, s.db, func(tx *ent.Tx) error {
		row, changed, err := pki.RevokeCertificate(ctx, tx, serial, reason, s.now())
		if err != nil || !changed {
			return err
		}
		appendLog(r.Log, s.log, revlog.Entry{Kind: revlog.CertificateRevoked, Org: deref(row.OrgID), Subject: serial,
			Detail: reason, NotAfter: &row.NotAfter, Actor: actor.ID})
		_, err = audit.Append(ctx, tx, audit.Entry{OrgID: deref(row.OrgID), ActorType: actor.Type, ActorID: actor.ID,
			Action: "certificate.revoke", TargetType: "certificate", TargetID: serial, Result: audit.Success, Reason: reason})
		return err
	})
	if err != nil {
		return err
	}
	s.applyDeny()
	return nil
}

// RevokeIdentity revokes id and every certificate of it. ctx carries the caller's scope.
func (r Revoker) RevokeIdentity(ctx context.Context, id pki.Identity, reason string, actor Actor) error {
	s := r.Sessions
	err := store.WriteTx(ctx, s.db, func(tx *ent.Tx) error {
		row, changed, err := pki.RevokeIdentity(ctx, tx, id, reason, s.now())
		if err != nil || !changed {
			return err
		}
		appendLog(r.Log, s.log, revlog.Entry{Kind: revlog.IdentityRevoked, Org: id.Org, Subject: id.String(),
			Detail: reason, NotAfter: &row.NotAfter, Actor: actor.ID})
		_, err = audit.Append(ctx, tx, audit.Entry{OrgID: id.Org, ActorType: actor.Type, ActorID: actor.ID,
			Action: "identity.revoke", TargetType: string(id.Kind), TargetID: id.ID, Result: audit.Success, Reason: reason})
		return err
	})
	if err != nil {
		return err
	}
	s.applyDeny()
	return nil
}
