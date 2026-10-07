// SPDX-License-Identifier: Apache-2.0

package enroll_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/token"
)

const td = "rpmgr-teststor"

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// env is an initialised database with a CA and an org.
type env struct {
	db    *store.DB
	ca    *pki.CA
	org   string
	sys   context.Context
	clock time.Time
}

func setup(t *testing.T, f func(t *testing.T, e *env)) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		kek, err := secret.NewKEK(raw)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := secret.NewSealer(kek)
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error { return pki.InitCA(sys, tx, s, td, t0) }); err != nil {
			t.Fatal(err)
		}
		e := &env{db: db, org: storetest.Org(t, db, "org-a"), sys: sys, clock: t0}
		if e.ca, err = pki.LoadCA(sys, db, s, func() time.Time { return e.clock }); err != nil {
			t.Fatal(err)
		}
		f(t, e)
	})
}

// mint creates an enrollment token and returns its plaintext.
func (e *env) mint(t *testing.T, edit func(*ent.EnrollmentTokenCreate)) string {
	t.Helper()
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	c := e.db.Client().EnrollmentToken.Create().SetOrgID(e.org).SetTokenHash(token.Hash(tok)).
		SetRole("connector").SetExpiresAt(t0.Add(time.Hour)).SetCreatedBy("usr_admin")
	if edit != nil {
		edit(c)
	}
	c.ExecX(e.sys)
	return tok
}

// issue is the Issue of a connector enrollment: a new connector identity in the grant's org.
func (e *env) issue(ctx context.Context, tx *ent.Tx, g enroll.Grant) (*x509.Certificate, error) {
	id := pki.Identity{TrustDomain: td, Org: g.OrgID, Kind: pki.KindConnector, ID: ids.New("con")}
	csr := ctx.Value(csrKey{}).(*x509.CertificateRequest)
	return e.ca.IssueEnrolled(ctx, tx, csr, id, pki.DefaultLeafLifetime, g.TokenID)
}

type csrKey struct{}

func (e *env) redeem(tok string, csr *x509.CertificateRequest) (*x509.Certificate, enroll.Grant, bool, error) {
	ctx := context.WithValue(e.sys, csrKey{}, csr)
	return enroll.Redeem(ctx, e.db, tok, csr, "198.51.100.7", e.clock, e.issue)
}

func newCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	k, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func (e *env) uses(t *testing.T, tok string) int {
	t.Helper()
	return e.db.Client().EnrollmentToken.Query().Where(enrollmenttoken.TokenHash(token.Hash(tok))).OnlyX(e.sys).UseCount
}

// TestRedeem_RetryGetsTheSameCertificate: a retry with the same key within the window gets the
// same certificate and consumes nothing; another key, or the same key later, is refused.
func TestRedeem_RetryGetsTheSameCertificate(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		tok := e.mint(t, nil)
		csr := newCSR(t)
		first, g, retry, err := e.redeem(tok, csr)
		if err != nil || retry || g.OrgID != e.org || g.Role != "connector" {
			t.Fatalf("first redeem: %v, %+v, retry %v", err, g, retry)
		}
		row := e.db.Client().EnrollmentToken.Query().Where(enrollmenttoken.TokenHash(token.Hash(tok))).OnlyX(e.sys)
		if row.UseCount != 1 || row.LastUsedIP != "198.51.100.7" || row.LastUsedAt == nil {
			t.Errorf("token after use: %+v", row)
		}
		e.clock = t0.Add(enroll.RetryWindow - time.Second)
		again, g2, retry, err := e.redeem(tok, csr)
		if err != nil || !retry || !bytes.Equal(again.Raw, first.Raw) || g2.TokenID != g.TokenID {
			t.Fatalf("retry within the window: %v, retry %v, same %v", err, retry, again != nil && bytes.Equal(again.Raw, first.Raw))
		}
		if n := e.uses(t, tok); n != 1 {
			t.Errorf("a retry consumed the token: %d uses", n)
		}
		if _, _, _, err := e.redeem(tok, newCSR(t)); !errors.Is(err, enroll.ErrInvalidToken) {
			t.Errorf("another key: %v, want ErrInvalidToken", err)
		}
		e.clock = t0.Add(enroll.RetryWindow + time.Second)
		if _, _, _, err := e.redeem(tok, csr); !errors.Is(err, enroll.ErrInvalidToken) {
			t.Errorf("the same key after the window: %v, want ErrInvalidToken", err)
		}
	})
}

// TestRedeem_ConcurrentUseHasOneWinner: a single-use token redeemed by eight hosts at once enrolls
// exactly one.
func TestRedeem_ConcurrentUseHasOneWinner(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		tok := e.mint(t, nil)
		var won atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, _, err := e.redeem(tok, newCSR(t))
				switch {
				case err == nil:
					won.Add(1)
				case !errors.Is(err, enroll.ErrInvalidToken):
					t.Errorf("redeem: %v", err)
				}
			}()
		}
		wg.Wait()
		if won.Load() != 1 || e.uses(t, tok) != 1 {
			t.Fatalf("%d hosts enrolled with a single-use token (%d uses)", won.Load(), e.uses(t, tok))
		}
	})
}

func TestRedeem_Refused(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		expired := e.mint(t, func(c *ent.EnrollmentTokenCreate) { c.SetExpiresAt(t0.Add(-time.Second)) })
		revoked := e.mint(t, func(c *ent.EnrollmentTokenCreate) { c.SetRevokedAt(t0) })
		typo := []byte(e.mint(t, nil))
		typo[20] ^= 1
		pat, _ := token.New(token.PersonalAPI)
		unknown, _ := token.New(token.Enrollment)
		for name, tok := range map[string]string{
			"expired": expired, "revoked": revoked, "mistyped": string(typo), "an API token": pat,
			"unknown": unknown, "empty": "",
		} {
			if _, _, _, err := e.redeem(tok, newCSR(t)); !errors.Is(err, enroll.ErrInvalidToken) {
				t.Errorf("%s token: %v, want ErrInvalidToken", name, err)
			}
		}
		three := e.mint(t, func(c *ent.EnrollmentTokenCreate) { c.SetMaxUses(3).SetEphemeral(true) })
		for i := 1; i <= 4; i++ {
			_, _, _, err := e.redeem(three, newCSR(t))
			if (i <= 3) != (err == nil) {
				t.Errorf("use %d of a 3-use token: %v", i, err)
			}
		}
		unlimited := e.mint(t, func(c *ent.EnrollmentTokenCreate) { c.SetMaxUses(0).SetEphemeral(true) })
		for i := 0; i < 5; i++ {
			if _, g, _, err := e.redeem(unlimited, newCSR(t)); err != nil || !g.Ephemeral {
				t.Fatalf("use %d of an unlimited ephemeral token: %v", i+1, err)
			}
		}
		if err := e.db.Client().EnrollmentToken.Create().SetOrgID(e.org).SetTokenHash([]byte("x")).
			SetRole("connector").SetMaxUses(0).SetExpiresAt(t0).SetCreatedBy("u").Exec(e.sys); err == nil {
			t.Error("an unlimited token that is not ephemeral")
		}
	})
}

// TestRedeem_FailureDoesNotBurnTheToken: a malformed CSR, or an issuance that fails, leaves the
// single-use token unused.
func TestRedeem_FailureDoesNotBurnTheToken(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		tok := e.mint(t, nil)
		broken := newCSR(t)
		broken.Signature = bytes.Clone(broken.Signature)
		broken.Signature[len(broken.Signature)-1] ^= 1
		if _, _, _, err := e.redeem(tok, broken); !errors.Is(err, pki.ErrBadCSR) {
			t.Fatalf("broken CSR: %v, want ErrBadCSR", err)
		}
		boom := errors.New("issuance failed")
		ctx := context.WithValue(e.sys, csrKey{}, newCSR(t))
		_, _, _, err := enroll.Redeem(ctx, e.db, tok, newCSR(t), "", e.clock,
			func(context.Context, *ent.Tx, enroll.Grant) (*x509.Certificate, error) { return nil, boom })
		if !errors.Is(err, boom) {
			t.Fatalf("failing issuance: %v", err)
		}
		if n := e.uses(t, tok); n != 0 {
			t.Fatalf("the failures burned the token: %d uses", n)
		}
		if _, _, _, err := e.redeem(tok, newCSR(t)); err != nil {
			t.Fatalf("the token after the failures: %v", err)
		}
	})
}

func TestRedeem_NeedsAScope(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		tok := e.mint(t, nil)
		csr := newCSR(t)
		ctx := context.WithValue(context.Background(), csrKey{}, csr)
		if _, _, _, err := enroll.Redeem(ctx, e.db, tok, csr, "", e.clock, e.issue); err == nil {
			t.Fatal("redeemed without a scope")
		}
		if n := e.uses(t, tok); n != 0 {
			t.Fatalf("%d uses after a refused redeem", n)
		}
	})
}
