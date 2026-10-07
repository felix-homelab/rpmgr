// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

var admin = controller.Actor{Type: audit.ActorUser, ID: "usr_admin"}

// revokeEnv is a session env with a revocation log at logPath and a fast revision check.
type revokeEnv struct {
	*sessionEnv
	logPath string
	r       controller.Revoker
}

func startRevokeEnv(t *testing.T, db *store.DB) *revokeEnv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revocations.log")
	rl, err := revlog.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := startSessionsWith(t, db, func(o *controller.SessionsOptions) {
		o.Version, o.RevLog, o.RevisionCheck = "0.1.0", rl, 20*time.Millisecond
	})
	return &revokeEnv{sessionEnv: e, logPath: path, r: controller.Revoker{Sessions: e.sessions, Log: rl}}
}

func (e *revokeEnv) logged(t *testing.T) []revlog.Entry {
	t.Helper()
	es, err := revlog.Read(e.logPath)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// verifyDenyList checks a deny-list message as an agent does and returns its entries.
func (e *sessionEnv) verifyDenyList(t *testing.T, m *agentv1.ControllerMessage) []*agentv1.DenyEntry {
	t.Helper()
	signed := m.GetDenyList()
	if signed == nil {
		t.Fatalf("got %v, want a deny-list", m)
	}
	payload, err := snapshot.Verify(signed, []*x509.Certificate{e.ca.ConfigSigner().Cert, e.ca.Intermediate()}, e.ca.Root(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	list := &agentv1.DenyList{}
	if err := proto.Unmarshal(payload, list); err != nil || !list.GetFull() || list.GetVersion().GetDbEpoch() != e.dbEpoch {
		t.Fatalf("deny-list %v: %v", list, err)
	}
	return list.GetEntries()
}

// refused checks that a control session with cert fails at the TLS layer.
func (e *sessionEnv) refused(t *testing.T, cert tls.Certificate) {
	t.Helper()
	cc, _ := e.dial(t, cert, "controller."+e.ca.TrustDomain(), false)
	st, err := agentv1.NewControlClient(cc).Session(testCtx(t))
	if err == nil {
		_, err = st.Recv()
	}
	if code(err) != codes.Unavailable {
		t.Fatalf("a session with a denied certificate: %v", err)
	}
}

func welcomed(t *testing.T, st controlStream) {
	t.Helper()
	if recv(t, st).GetWelcome() == nil {
		t.Fatal("no Welcome")
	}
}

// TestRevoke_Certificate: revoking a certificate ends its agent's session with Goodbye{revoked},
// sends the signed deny-list to every other session, refuses the certificate at the TLS layer from
// then on, and is recorded once in the revocation log and the audit log.
func TestRevoke_Certificate(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := startRevokeEnv(t, db)
		certA, _ := e.agentCert(t)
		certB, _ := e.agentCert(t)
		stA := e.open(t, testCtx(t), certA, hello("0.1.0"))
		stB := e.open(t, testCtx(t), certB, hello("0.1.0"))
		welcomed(t, stA)
		welcomed(t, stB)

		serial := pki.SerialHex(certA.Leaf.SerialNumber)
		if err := e.r.RevokeCertificate(e.sys, serial, "key lost", admin); err != nil {
			t.Fatal(err)
		}
		if g := recv(t, stA).GetGoodbye(); g.GetReason() != agentv1.GoodbyeReason_GOODBYE_REASON_REVOKED {
			t.Fatalf("the revoked agent got %v", g)
		}
		entries := e.verifyDenyList(t, recv(t, stB))
		if len(entries) != 1 || entries[0].GetSerial() != serial || !entries[0].GetNotAfter().AsTime().Equal(certA.Leaf.NotAfter) {
			t.Fatalf("deny-list entries %v", entries)
		}
		e.refused(t, certA)

		if err := e.r.RevokeCertificate(e.sys, serial, "again", admin); err != nil {
			t.Fatal(err)
		}
		es := e.logged(t)
		if len(es) != 1 || es[0].Kind != revlog.CertificateRevoked || es[0].Subject != serial || es[0].Actor != admin.ID ||
			es[0].Detail != "key lost" || es[0].Org != e.org || !es[0].NotAfter.Equal(certA.Leaf.NotAfter) {
			t.Fatalf("revocation log %+v", es)
		}
		if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("certificate.revoke"), auditentry.TargetID(serial)).CountX(e.sys); n != 1 {
			t.Fatalf("%d audit records", n)
		}
		if err := e.r.RevokeCertificate(e.sys, "ffff", "unknown", admin); err == nil {
			t.Fatal("an unknown serial was revoked")
		}
	})
}

// TestRevoke_Identity: revoking an identity ends its session and refuses every certificate of it,
// also one that was never used.
func TestRevoke_Identity(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := startRevokeEnv(t, db)
		id := e.newIdentity()
		first := e.certAt(t, id, time.Now().Add(-time.Hour))
		second := e.certAt(t, id, time.Now())
		st := e.open(t, testCtx(t), second, hello("0.1.0"))
		welcomed(t, st)
		if err := e.r.RevokeIdentity(e.sys, id, "decommissioned", admin); err != nil {
			t.Fatal(err)
		}
		if g := recv(t, st).GetGoodbye(); g.GetReason() != agentv1.GoodbyeReason_GOODBYE_REASON_REVOKED {
			t.Fatalf("the revoked agent got %v", g)
		}
		e.refused(t, first)
		e.refused(t, second)
		es := e.logged(t)
		if es[len(es)-1].Kind != revlog.IdentityRevoked || es[len(es)-1].Subject != id.String() {
			t.Fatalf("revocation log %+v", es)
		}
	})
}

// TestDenyList_HelloDigest: an agent whose Hello names the current deny-list gets none after
// Welcome; one with another digest gets the list at once.
func TestDenyList_HelloDigest(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startRevokeEnv(t, db)
	revoked, _ := e.agentCert(t)
	if err := e.r.RevokeCertificate(e.sys, pki.SerialHex(revoked.Leaf.SerialNumber), "test", admin); err != nil {
		t.Fatal(err)
	}
	cert, _ := e.agentCert(t)
	stale := e.open(t, testCtx(t), cert, hello("0.1.0"))
	welcomed(t, stale)
	entries := e.verifyDenyList(t, recv(t, stale))

	current := hello("0.1.0")
	current.DenyListDigest = pki.DenyDigest(entries)
	inSync := e.open(t, testCtx(t), cert, current)
	welcomed(t, inSync)
	expectQuiet(t, inSync, 200*time.Millisecond)
}

// TestDenyList_RevokedElsewhere: a revocation that another process committed is enforced at the
// next revision check.
func TestDenyList_RevokedElsewhere(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startRevokeEnv(t, db)
	cert, _ := e.agentCert(t)
	st := e.open(t, testCtx(t), cert, hello("0.1.0"))
	welcomed(t, st)
	if err := store.WriteTx(e.sys, db, func(tx *ent.Tx) error {
		_, _, err := pki.RevokeCertificate(e.sys, tx, pki.SerialHex(cert.Leaf.SerialNumber), "elsewhere", time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if g := recv(t, st).GetGoodbye(); g.GetReason() != agentv1.GoodbyeReason_GOODBYE_REASON_REVOKED {
		t.Fatalf("got %v, want Goodbye{revoked}", g)
	}
}

// TestSuperseded_Logged: a certificate superseded by a newer one in a session is recorded in the
// revocation log.
func TestSuperseded_Logged(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startRevokeEnv(t, db)
	id := e.newIdentity()
	old := e.certAt(t, id, time.Now().Add(-time.Hour))
	current := e.certAt(t, id, time.Now())
	welcomed(t, e.open(t, testCtx(t), current, hello("0.1.0")))
	es := e.logged(t)
	if len(es) != 1 || es[0].Kind != revlog.CertificateSuperseded || es[0].Subject != pki.SerialHex(old.Leaf.SerialNumber) ||
		es[0].Actor != id.String() {
		t.Fatalf("revocation log %+v", es)
	}
}
