// SPDX-License-Identifier: Apache-2.0

package accounts_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
)

// TestTokens: a token lasts 90 days by default and at most a year; an Operator's
// connectors.write scope follows the org setting; a token records its use at most once a minute;
// a removed member's token keeps no role; a disabled owner's token is refused.
func TestTokens(t *testing.T) {
	x := newMembers(t)
	tokens := &accounts.Tokens{Accounts: x.acc}
	ctx := context.Background()
	op := x.join(t, "op@example.com", authz.RoleOperator)
	_, row, err := tokens.Create(ctx, x.org, op, "ci", []string{authz.PermOrgRead}, 0, false)
	if err != nil || !row.ExpiresAt.Equal(row.CreatedAt.Add(accounts.DefaultTokenTTL)) {
		t.Fatalf("the default lifetime: %+v %v", row, err)
	}
	for _, ttl := range []time.Duration{accounts.MaxTokenTTL + time.Second, -time.Second} {
		if _, _, err := tokens.Create(ctx, x.org, op, "ci", []string{authz.PermOrgRead}, ttl, false); !errors.Is(err, accounts.ErrTokenTTL) {
			t.Errorf("%v: %v", ttl, err)
		}
	}
	if _, _, err := tokens.Create(ctx, x.org, op, "ci", []string{authz.PermConnectorsWrite}, 0, false); !errors.Is(err, accounts.ErrScope) {
		t.Fatalf("connectors.write without the org setting: %v", err)
	}
	if _, err := settings.UpdateOrg(x.sys, x.db, x.org, &rpmgrv1.OrgSettings{OperatorsMayEnroll: proto.Bool(true)},
		&fieldmaskpb.FieldMask{Paths: []string{"operators_may_enroll"}}, 0); err != nil {
		t.Fatal(err)
	}
	tok, _, err := tokens.Create(ctx, x.org, op, "ci", []string{authz.PermConnectorsWrite}, 0, false)
	if err != nil {
		t.Fatalf("connectors.write with the org setting: %v", err)
	}
	if _, _, err := tokens.Create(ctx, "org_none", op, "ci", []string{authz.PermOrgRead}, 0, false); !errors.Is(err, accounts.ErrScope) {
		t.Fatalf("a token in an org the user is not in: %v", err)
	}

	first, err := tokens.Authenticate(tok, "192.0.2.1")
	if err != nil || first.Role != authz.RoleOperator || first.User.ID != op {
		t.Fatalf("%+v %v", first, err)
	}
	x.clock = x.clock.Add(30 * time.Second)
	if _, err := tokens.Authenticate(tok, "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	if r := x.db.Client().APIToken.GetX(x.sys, first.Token.ID); r.LastUsedIP != "192.0.2.1" {
		t.Fatalf("written twice within a minute: %s", r.LastUsedIP)
	}
	if err := x.m.Remove(ctx, x.org, op, x.owner, authz.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if o, err := tokens.Authenticate(tok, ""); err != nil || o.Role != "" {
		t.Fatalf("a removed member's token: %+v %v", o, err)
	}
	x.db.Client().User.UpdateOneID(op).SetStatus(user.StatusDisabled).ExecX(x.sys)
	if _, err := tokens.Authenticate(tok, ""); !errors.Is(err, accounts.ErrToken) {
		t.Fatalf("a disabled owner's token: %v", err)
	}
	if _, err := tokens.Authenticate("rpmgr_pat_forged", ""); !errors.Is(err, accounts.ErrToken) {
		t.Fatalf("a forged token: %v", err)
	}
}
