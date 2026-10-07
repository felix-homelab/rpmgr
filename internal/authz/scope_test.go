// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"testing"
)

func TestForOrg(t *testing.T) {
	p := Principal{UserID: "usr_1", Memberships: map[string]string{"org_a": "viewer"}}
	if _, err := ForOrg(context.Background(), p, "org_b"); !errors.Is(err, ErrNotMember) {
		t.Errorf("non-member: %v", err)
	}
	if _, err := ForOrg(context.Background(), Principal{}, "org_a"); !errors.Is(err, ErrNotMember) {
		t.Errorf("empty principal: %v", err)
	}
	if _, err := ForOrg(context.Background(), p, ""); !errors.Is(err, ErrNotMember) {
		t.Errorf("empty org: %v", err)
	}
	ctx, err := ForOrg(context.Background(), p, "org_a")
	if err != nil {
		t.Fatal(err)
	}
	s, ok := FromContext(ctx)
	if !ok || s.OrgID() != "org_a" || s.System() || s.Actor() != "usr_1" {
		t.Errorf("scope: %+v %v", s, ok)
	}
}

func TestScopeCannotBeForged(t *testing.T) {
	type fakeKey struct{}
	if _, ok := FromContext(context.WithValue(context.Background(), fakeKey{}, OrgScope{orgID: "org_a"})); ok {
		t.Error("a scope under another key was accepted")
	}
	if _, ok := FromContext(context.WithValue(context.Background(), scopeKey{}, OrgScope{})); ok {
		t.Error("the zero scope was accepted")
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Error("a context without scope returned one")
	}
}

func TestSystem(t *testing.T) {
	var got []string
	audit := func(_ context.Context, job, reason string) error {
		got = append(got, job+"/"+reason)
		return nil
	}
	ctx, err := System(context.Background(), "purge", "purge ephemeral connectors", audit)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := FromContext(ctx); !ok || !s.System() || s.OrgID() != "" || s.Actor() != "purge" || s.Reason() != "purge ephemeral connectors" {
		t.Errorf("system scope: %+v %v", s, ok)
	}
	if len(got) != 1 {
		t.Errorf("audit calls: %v", got)
	}
	if _, err := System(context.Background(), "job", "reason", nil); !errors.Is(err, ErrNoAudit) {
		t.Errorf("without audit: %v", err)
	}
	if _, err := System(context.Background(), "", "reason", audit); err == nil {
		t.Error("granted without a job name")
	}
	if _, err := System(context.Background(), "job", "", audit); err == nil {
		t.Error("granted without a reason")
	}
	failing := func(context.Context, string, string) error { return errors.New("sink down") }
	if _, err := System(context.Background(), "job", "reason", failing); err == nil {
		t.Error("granted although the audit record failed")
	}
}
