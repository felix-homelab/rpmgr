// SPDX-License-Identifier: Apache-2.0

package accounts_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
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
// password once, on both dialects; the other is refused with ErrLink, never a database error such
// as a deadlock, whichever wins. Repeated, as a lock-order fault shows only in some interleavings.
func TestResetLink_ConcurrentLinksSetOnePassword(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e, _, ada, _ := newMFAOn(t, newEnvOn(t, db))
		ctx := context.Background()
		for round := range 10 {
			a, _ := e.acc.ResetLink(ada, "local-cli")
			b, _ := e.acc.ResetLink(ada, "local-cli")
			toks := []string{a, b}
			pws := []string{fmt.Sprintf("first new passphrase %d", round), fmt.Sprintf("second new passphrase %d", round)}
			errs := race(len(toks), func(i int) error {
				_, err := e.acc.CompleteReset(ctx, toks[i], pws[i], "", "")
				return err
			})
			won := -1
			for i, err := range errs {
				switch {
				case err == nil && won < 0:
					won = i
				case err == nil:
					t.Fatalf("round %d: both links set the password", round)
				case !errors.Is(err, accounts.ErrLink):
					t.Fatalf("round %d: the losing link: %v", round, err)
				}
			}
			if won < 0 {
				t.Fatalf("round %d: neither link set the password", round)
			}
			if _, err := e.acc.Authenticate(ctx, "ada@example.com", pws[won]); err != nil {
				t.Fatalf("round %d: the winning link's password: %v", round, err)
			}
			for _, tok := range toks {
				if _, err := e.acc.CompleteReset(ctx, tok, "yet another passphrase", "", ""); !errors.Is(err, accounts.ErrLink) {
					t.Fatalf("round %d: a link after the race: %v", round, err)
				}
			}
		}
	})
}

// TestResetLink_ConcurrentWithPasswordChange: a link completed while the user changes the password
// either sets the password before the change, or is refused with ErrLink; the change always
// succeeds, and no database error such as a deadlock reaches either caller.
func TestResetLink_ConcurrentWithPasswordChange(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e, m, ada, _ := newMFAOn(t, newEnvOn(t, db))
		ctx := context.Background()
		current := pw
		for round := range 10 {
			link, _ := e.acc.ResetLink(ada, "local-cli")
			// A second unused link makes the change's endLinks lock another row too.
			spare, _ := e.acc.ResetLink(ada, "local-cli")
			next := fmt.Sprintf("the owner's passphrase %d", round)
			errs := race(2, func(i int) error {
				if i == 0 {
					return m.ChangePassword(ctx, ada, current, next)
				}
				_, err := e.acc.CompleteReset(ctx, link, fmt.Sprintf("the link's passphrase %d", round), "", "")
				return err
			})
			switch {
			case errs[0] != nil && !errors.Is(errs[0], accounts.ErrCredentials):
				t.Fatalf("round %d: the change: %v", round, errs[0])
			case errs[1] != nil && !errors.Is(errs[1], accounts.ErrLink):
				t.Fatalf("round %d: the link: %v", round, errs[1])
			}
			// The change may lose only by checking the current password after the reset replaced it.
			if errs[0] == nil {
				current = next
			} else {
				current = fmt.Sprintf("the link's passphrase %d", round)
			}
			if _, err := e.acc.Authenticate(ctx, "ada@example.com", current); err != nil {
				t.Fatalf("round %d: the password that won no longer signs in: %v", round, err)
			}
			for _, tok := range []string{link, spare} {
				if _, err := e.acc.CompleteReset(ctx, tok, "yet another passphrase", "", ""); !errors.Is(err, accounts.ErrLink) {
					t.Fatalf("round %d: a link after the race: %v", round, err)
				}
			}
		}
	})
}

// race runs f(0) … f(n-1) at once and returns their errors by index.
func race(n int, f func(i int) error) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = f(i)
		}()
	}
	close(start)
	wg.Wait()
	return errs
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
