// SPDX-License-Identifier: Apache-2.0

package accounts_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/totp"
)

func newMFA(t *testing.T) (*env, *accounts.MFA, string, string) {
	t.Helper()
	e := newEnv(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	kek, _ := secret.NewKEK(key)
	sealer, _ := secret.NewSealer(kek)
	log := filepath.Join(t.TempDir(), "revocations.log")
	rl, err := revlog.Open(log, func() time.Time { return e.clock })
	if err != nil {
		t.Fatal(err)
	}
	link, _ := e.acc.FirstUserLink("local-cli")
	u, err := e.acc.CompleteReset(context.Background(), link, pw, "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	return e, &accounts.MFA{Accounts: e.acc, Sealer: sealer, RevLog: rl}, u.ID, log
}

// TestMFA_Enroll: a new authenticator counts once its first code is confirmed, which returns ten
// recovery codes; until then enrolling again replaces it; once confirmed it must be removed before
// another; the seed is stored sealed.
func TestMFA_Enroll(t *testing.T) {
	e, m, ada, _ := newMFA(t)
	first, uri, err := m.EnrollTOTP(ada, "rpmgr panel.example.com")
	if err != nil || len(first) != totp.SecretSize || !strings.Contains(uri, "secret="+totp.Encode(first)) {
		t.Fatalf("%q %v", uri, err)
	}
	seed, _, err := m.EnrollTOTP(ada, "rpmgr panel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ConfirmTOTP(ada, totp.Code(first, totp.StepOf(e.clock))); !errors.Is(err, accounts.ErrSecondFactor) {
		t.Fatalf("the replaced secret's code: %v", err)
	}
	if ok, _ := m.HasMFA(ada); ok {
		t.Fatal("MFA before confirmation")
	}
	if _, err := m.ConfirmTOTP(ada, "000000"); !errors.Is(err, accounts.ErrSecondFactor) {
		t.Fatalf("a wrong code: %v", err)
	}
	codes, err := m.ConfirmTOTP(ada, totp.Code(seed, totp.StepOf(e.clock)))
	if err != nil || len(codes) != accounts.RecoveryCodes {
		t.Fatalf("confirm: %v %v", codes, err)
	}
	if ok, _ := m.HasMFA(ada); !ok {
		t.Fatal("no MFA after confirmation")
	}
	if _, _, err := m.EnrollTOTP(ada, "x"); !errors.Is(err, accounts.ErrMFAEnrolled) {
		t.Fatalf("enroll over a confirmed one: %v", err)
	}
	if _, err := m.ConfirmTOTP(ada, totp.Code(seed, totp.StepOf(e.clock)+1)); !errors.Is(err, accounts.ErrMFAEnrolled) {
		t.Fatalf("confirm twice: %v", err)
	}
	row := e.db.Client().TOTPCredential.Query().OnlyX(e.sys)
	if bytes.Contains(row.SeedEnc, seed) {
		t.Fatal("the seed is stored in plain")
	}
}

// TestMFA_SecondFactor: an authenticator code works once and no older one after it; a recovery
// code works once, whatever its case and dashes; another user's code and unknown codes fail; of
// one code tried twice at once, one attempt passes.
func TestMFA_SecondFactor(t *testing.T) {
	e, m, ada, _ := newMFA(t)
	seed, _, _ := m.EnrollTOTP(ada, "x")
	codes, err := m.ConfirmTOTP(ada, totp.Code(seed, totp.StepOf(e.clock)))
	if err != nil {
		t.Fatal(err)
	}
	// The confirming code is used; the next step's works, once.
	if _, err := m.VerifySecondFactor(ada, totp.Code(seed, totp.StepOf(e.clock))); !errors.Is(err, accounts.ErrSecondFactor) {
		t.Fatalf("the confirming code again: %v", err)
	}
	e.clock = e.clock.Add(totp.Step)
	next := totp.Code(seed, totp.StepOf(e.clock))
	if how, err := m.VerifySecondFactor(ada, next); err != nil || how != "otp" {
		t.Fatalf("the next code: %q %v", how, err)
	}
	if _, err := m.VerifySecondFactor(ada, next); !errors.Is(err, accounts.ErrSecondFactor) {
		t.Fatalf("a replayed code: %v", err)
	}
	if how, err := m.VerifySecondFactor(ada, strings.ToUpper(strings.ReplaceAll(codes[0], "-", ""))); err != nil || how != "recovery" {
		t.Fatalf("a recovery code: %q %v", how, err)
	}
	if _, err := m.VerifySecondFactor(ada, codes[0]); !errors.Is(err, accounts.ErrSecondFactor) {
		t.Fatalf("a recovery code twice: %v", err)
	}
	for _, bad := range []string{"", "nonsense-code", "123456"} {
		if _, err := m.VerifySecondFactor(ada, bad); !errors.Is(err, accounts.ErrSecondFactor) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := m.VerifySecondFactor("usr_other", codes[1]); !errors.Is(err, accounts.ErrSecondFactor) {
		t.Fatalf("another user's recovery code: %v", err)
	}

	e.clock = e.clock.Add(totp.Step)
	code := totp.Code(seed, totp.StepOf(e.clock))
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range results {
		wg.Go(func() { _, results[i] = m.VerifySecondFactor(ada, code) })
	}
	wg.Wait()
	if (results[0] == nil) == (results[1] == nil) {
		t.Fatalf("one code at once: %v / %v", results[0], results[1])
	}
}

// TestMFA_ChangeAndRemove: new recovery codes replace the old ones; removing the authenticator
// removes the codes too and leaves no second factor; every change is in the revocation log.
func TestMFA_ChangeAndRemove(t *testing.T) {
	e, m, ada, log := newMFA(t)
	seed, _, _ := m.EnrollTOTP(ada, "x")
	old, _ := m.ConfirmTOTP(ada, totp.Code(seed, totp.StepOf(e.clock)))
	fresh, err := m.RegenerateRecoveryCodes(ada)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifySecondFactor(ada, old[0]); !errors.Is(err, accounts.ErrSecondFactor) {
		t.Fatal("an old recovery code works")
	}
	if _, err := m.VerifySecondFactor(ada, fresh[0]); err != nil {
		t.Fatalf("a new recovery code: %v", err)
	}
	if err := m.RemoveTOTP(ada, ada); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.HasMFA(ada); ok {
		t.Fatal("MFA after removal")
	}
	if _, err := m.VerifySecondFactor(ada, fresh[1]); !errors.Is(err, accounts.ErrSecondFactor) {
		t.Fatal("a recovery code after removal")
	}
	if err := m.RemoveTOTP(ada, ada); !errors.Is(err, accounts.ErrNoMFA) {
		t.Fatalf("removed twice: %v", err)
	}
	if _, err := m.RegenerateRecoveryCodes(ada); !errors.Is(err, accounts.ErrNoMFA) {
		t.Fatalf("codes without MFA: %v", err)
	}
	entries, err := revlog.Read(log)
	if err != nil || len(entries) != 3 {
		t.Fatalf("revocation log: %v %v", entries, err)
	}
	for _, e := range entries {
		if e.Kind != revlog.CredentialSuperseded || e.Subject != ada {
			t.Errorf("entry %+v", e)
		}
	}
	if n := len(e.actions(t, "user.mfa_enroll")) + len(e.actions(t, "user.recovery_codes")) + len(e.actions(t, "user.mfa_remove")); n != 3 {
		t.Fatalf("%d audit entries", n)
	}
}
