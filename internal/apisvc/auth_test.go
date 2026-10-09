// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestAuth_CompletePasswordReset: the errors of a reset reach the client with the codes of
// docs/07-api.md: input that is not valid and unusable links are INVALID_ARGUMENT, a first-user
// link once a user exists FAILED_PRECONDITION.
func TestAuth_CompletePasswordReset(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	acc := accounts.New(db, storetest.SystemCtx(t), nil)
	auth := &apisvc.Auth{Accounts: acc}
	first, _ := acc.FirstUserLink("local-cli")
	spare, _ := acc.FirstUserLink("local-cli")
	call := func(tok, pw, email, name string) connect.Code {
		_, err := auth.CompletePasswordReset(context.Background(), connect.NewRequest(&rpmgrv1.CompletePasswordResetRequest{
			Token: tok, NewPassword: pw, Email: email, DisplayName: name}))
		if err == nil {
			return 0
		}
		return connect.CodeOf(err)
	}
	const pw = "correct horse battery staple"
	for name, c := range map[string][4]string{
		"bad e-mail":       {first, pw, "nobody", "Ada"},
		"no display name":  {first, pw, "ada@example.com", ""},
		"short password":   {first, "short", "ada@example.com", "Ada"},
		"not a link token": {"rpmgr_prs_x", pw, "ada@example.com", "Ada"},
	} {
		if code := call(c[0], c[1], c[2], c[3]); code != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, code)
		}
	}
	if code := call(first, pw, "ada@example.com", "Ada"); code != 0 {
		t.Fatalf("the first user: %v", code)
	}
	if code := call(spare, pw, "eve@example.com", "Eve"); code != connect.CodeFailedPrecondition {
		t.Errorf("a spare first-user link: %v", code)
	}
}
