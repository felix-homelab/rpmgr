// SPDX-License-Identifier: Apache-2.0

package accounts_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
)

// TestResetLink_EndedByAPasswordChange: completing one reset link ends the user's other unused
// links, and so does changing the password oneself; a link of another user stays; the audit entry
// says how many links ended (docs/04-security.md, "Human authentication and sessions").
func TestResetLink_EndedByAPasswordChange(t *testing.T) {
	e, m, ada, _ := newMFA(t)
	ctx := context.Background()
	bob := e.db.Client().User.Create().SetEmail("bob@example.com").SetDisplayName("Bob").SaveX(e.sys).ID
	early, _ := e.acc.ResetLink(ada, "local-cli")
	other, _ := e.acc.ResetLink(ada, "email-request")
	bobs, _ := e.acc.ResetLink(bob, "local-cli")

	const next = "an entirely new passphrase"
	if _, err := e.acc.CompleteReset(ctx, other, next, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.acc.CompleteReset(ctx, early, "the attacker's passphrase", "", ""); !errors.Is(err, accounts.ErrLink) {
		t.Fatalf("an earlier link after a completed reset: %v", err)
	}
	if _, err := e.acc.Authenticate(ctx, "ada@example.com", next); err != nil {
		t.Fatalf("the reset's password no longer signs in: %v", err)
	}
	if es := e.actions(t, "user.password_reset"); len(es) != 1 || !strings.Contains(es[0].Reason, "1 other reset links ended") {
		t.Fatalf("audit of the reset: %+v", es)
	}

	// A link made after the reset is ended by the user's own password change.
	late, _ := e.acc.ResetLink(ada, "local-cli")
	if err := m.ChangePassword(ctx, ada, next, pw); err != nil {
		t.Fatal(err)
	}
	if _, err := e.acc.CompleteReset(ctx, late, "the attacker's passphrase", "", ""); !errors.Is(err, accounts.ErrLink) {
		t.Fatalf("an earlier link after a password change: %v", err)
	}
	if es := e.actions(t, "user.password_change"); len(es) != 1 || !strings.Contains(es[0].Reason, "1 other reset links ended") {
		t.Fatalf("audit of the change: %+v", es)
	}

	// A change without unused links says nothing about links; another user's link still works.
	if err := m.ChangePassword(ctx, ada, pw, next); err != nil {
		t.Fatal(err)
	}
	if es := e.actions(t, "user.password_change"); len(es) != 2 || es[1].Reason != "password changed" {
		t.Fatalf("audit of a change without links: %+v", es)
	}
	if _, err := e.acc.CompleteReset(ctx, bobs, next, "", ""); err != nil {
		t.Fatalf("another user's link: %v", err)
	}
}

// TestResetLink_ConcurrentLinksSetOnePassword: two links of one user completed at once set the
// password once; the other is refused, whichever wins.
func TestResetLink_ConcurrentLinksSetOnePassword(t *testing.T) {
	e, _, ada, _ := newMFA(t)
	ctx := context.Background()
	a, _ := e.acc.ResetLink(ada, "local-cli")
	b, _ := e.acc.ResetLink(ada, "local-cli")
	pws := map[string]string{a: "the first new passphrase", b: "the second new passphrase"}
	var wg sync.WaitGroup
	errs := map[string]error{}
	var mu sync.Mutex
	for tok, p := range pws {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.acc.CompleteReset(ctx, tok, p, "", "")
			mu.Lock()
			errs[tok] = err
			mu.Unlock()
		}()
	}
	wg.Wait()
	won := ""
	for tok, err := range errs {
		switch {
		case err == nil && won == "":
			won = tok
		case err == nil:
			t.Fatal("both links set the password")
		case !errors.Is(err, accounts.ErrLink):
			t.Fatalf("the losing link: %v", err)
		}
	}
	if won == "" {
		t.Fatal("neither link set the password")
	}
	if _, err := e.acc.Authenticate(ctx, "ada@example.com", pws[won]); err != nil {
		t.Fatalf("the winning link's password: %v", err)
	}
	for tok := range pws {
		if _, err := e.acc.CompleteReset(ctx, tok, "yet another passphrase", "", ""); !errors.Is(err, accounts.ErrLink) {
			t.Fatalf("a link after the race: %v", err)
		}
	}
}

// TestResetLink_DisabledUserRefused: a link of a disabled user sets no password, so the user
// cannot sign in with one once enabled again; the link is not used up by the refusal.
func TestResetLink_DisabledUserRefused(t *testing.T) {
	e, _, ada, _ := newMFA(t)
	ctx := context.Background()
	link, _ := e.acc.ResetLink(ada, "local-cli")
	e.db.Client().User.UpdateOneID(ada).SetStatus(user.StatusDisabled).ExecX(e.sys)
	if _, err := e.acc.CompleteReset(ctx, link, "an entirely new passphrase", "", ""); !errors.Is(err, accounts.ErrLink) {
		t.Fatalf("a disabled user's link: %v", err)
	}
	e.db.Client().User.UpdateOneID(ada).SetStatus(user.StatusActive).ExecX(e.sys)
	if _, err := e.acc.Authenticate(ctx, "ada@example.com", pw); err != nil {
		t.Fatalf("the old password after the refused link: %v", err)
	}
	if len(e.actions(t, "user.password_reset")) != 0 {
		t.Fatal("a refused link was audited as a reset")
	}
}
