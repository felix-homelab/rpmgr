// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func createName(b *browser, org, fqdn, group string, ttl int32) (*rpmgrv1.DnsName, error) {
	r, err := b.dnsn.CreateDnsName(context.Background(), connect.NewRequest(&rpmgrv1.CreateDnsNameRequest{OrgId: org,
		DnsName: &rpmgrv1.DnsName{Fqdn: fqdn, GatewayGroupId: group, Ttl: ttl}}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetDnsName(), nil
}

func updateName(b *browser, n *rpmgrv1.DnsName, etag string, paths ...string) (*rpmgrv1.DnsName, error) {
	r, err := b.dnsn.UpdateDnsName(context.Background(), connect.NewRequest(&rpmgrv1.UpdateDnsNameRequest{DnsName: n, Etag: etag,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetDnsName(), nil
}

func deleteName(b *browser, id, etag string) error {
	_, err := b.dnsn.DeleteDnsName(context.Background(), connect.NewRequest(&rpmgrv1.DeleteDnsNameRequest{DnsNameId: id, Etag: etag}))
	return err
}

func nameCount(e *env) int { return e.db.Client().DNSName.Query().CountX(e.sys) }

// TestDnsNames_Create: a name for one of the org's gateway groups under a verified domain is
// created, normalised and unique in the instance; a wildcard name needs a domain with the wildcard;
// a name outside every verified domain, a bad name, a bad TTL and a group that is not the org's
// are refused, and nothing is stored for them.
func TestDnsNames_Create(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	e.verified(t, org, "flat.test", false)
	if _, err := claim(ada, org, "pending.test", true, 0); err != nil { // pending: not enough
		t.Fatal(err)
	}

	n, err := createName(ada, org, "SSH.Example.com.", group, 0)
	if err != nil || n.GetFqdn() != "ssh.example.com" || !strings.HasPrefix(n.GetId(), "dnn_") || n.GetGatewayGroupId() != group || n.GetTtl() != 0 || n.GetEtag() != "1" {
		t.Fatalf("created: %v %v", n, err)
	}
	if w, err := createName(ada, org, "*.apps.example.com", group, 300); err != nil || w.GetFqdn() != "*.apps.example.com" || w.GetTtl() != 300 {
		t.Fatalf("a wildcard name: %v %v", w, err)
	}
	// The apex itself, a name at any depth and a wildcard of the apex are covered by example.com.
	for _, fqdn := range []string{"example.com", "a.b.c.example.com", "*.example.com"} {
		if _, err := createName(ada, org, fqdn, group, 60); err != nil {
			t.Errorf("%s: %v", fqdn, err)
		}
	}
	// A claim without the wildcard covers its name only.
	if _, err := createName(ada, org, "flat.test", group, 0); err != nil {
		t.Errorf("flat.test: %v", err)
	}
	before := nameCount(e)

	for name, c := range map[string]struct {
		fqdn  string
		group string
		ttl   int32
		want  connect.Code
		why   string
	}{
		"exists":                    {"ssh.example.com", group, 0, connect.CodeAlreadyExists, ""},
		"exists in another case":    {"SSH.EXAMPLE.COM", group, 0, connect.CodeAlreadyExists, ""},
		"no domain":                 {"www.other.test", group, 0, connect.CodeFailedPrecondition, apisvc.ReasonDomainNotVerified},
		"pending domain":            {"www.pending.test", group, 0, connect.CodeFailedPrecondition, apisvc.ReasonDomainNotVerified},
		"badexample.com":            {"www.badexample.com", group, 0, connect.CodeFailedPrecondition, apisvc.ReasonDomainNotVerified},
		"below a flat claim":        {"www.flat.test", group, 0, connect.CodeFailedPrecondition, apisvc.ReasonDomainNotVerified},
		"wildcard of a flat claim":  {"*.flat.test", group, 0, connect.CodeFailedPrecondition, apisvc.ReasonDomainNotVerified},
		"a parent of the domain":    {"com", group, 0, connect.CodeInvalidArgument, ""},
		"empty":                     {"", group, 0, connect.CodeInvalidArgument, ""},
		"a wildcard in the middle":  {"a.*.example.com", group, 0, connect.CodeInvalidArgument, ""},
		"a wildcard inside a label": {"w*.example.com", group, 0, connect.CodeInvalidArgument, ""},
		"an address":                {"192.0.2.1", group, 0, connect.CodeInvalidArgument, ""},
		"bad characters":            {"a b.example.com", group, 0, connect.CodeInvalidArgument, ""},
		"too long":                  {strings.Repeat("a.", 130) + "example.com", group, 0, connect.CodeInvalidArgument, ""},
		"ttl too low":               {"t1.example.com", group, 59, connect.CodeInvalidArgument, ""},
		"ttl too high":              {"t2.example.com", group, 86401, connect.CodeInvalidArgument, ""},
		"negative ttl":              {"t3.example.com", group, -1, connect.CodeInvalidArgument, ""},
		"unknown group":             {"g1.example.com", "gwg_missing", 0, connect.CodeNotFound, ""},
		"no group":                  {"g2.example.com", "", 0, connect.CodeInvalidArgument, ""},
	} {
		_, err := createName(ada, org, c.fqdn, c.group, c.ttl)
		if code(err) != c.want || (c.why != "" && reason(err) != c.why) {
			t.Errorf("%s: %v (reason %q)", name, err, reason(err))
		}
	}
	if nameCount(e) != before {
		t.Errorf("a refused name was stored: %d names, want %d", nameCount(e), before)
	}
	// The same name with a retry key is created once.
	r1, err := ada.dnsn.CreateDnsName(ctx, connect.NewRequest(&rpmgrv1.CreateDnsNameRequest{OrgId: org, RequestId: "once",
		DnsName: &rpmgrv1.DnsName{Fqdn: "retry.example.com", GatewayGroupId: group}}))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := ada.dnsn.CreateDnsName(ctx, connect.NewRequest(&rpmgrv1.CreateDnsNameRequest{OrgId: org, RequestId: "once",
		DnsName: &rpmgrv1.DnsName{Fqdn: "retry.example.com", GatewayGroupId: group}}))
	if err != nil || r1.Msg.GetDnsName().GetId() != r2.Msg.GetDnsName().GetId() || nameCount(e) != before+1 {
		t.Errorf("a retry: %v %v", r2, err)
	}
}

// TestDnsNames_OtherOrgsGroupRefused: a name points at the org's own gateway groups only. Another
// org's group, which is not found by the org's scope as a shared group no grant covers would not
// be, cannot be used at creation or by an update, and a name of another org's domain is refused.
func TestDnsNames_OtherOrgsGroupRefused(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	e.verified(t, org, "example.com", true)
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	e.verified(t, orgB, "bob.test", true)
	theirs, err := bob.gw.CreateGatewayGroup(context.Background(), connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: orgB,
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "b"}}))
	if err != nil {
		t.Fatal(err)
	}
	other := theirs.Msg.GetGatewayGroup().GetId()
	if _, err := createName(ada, org, "ssh.example.com", other, 0); code(err) != connect.CodeNotFound {
		t.Errorf("another org's group: %v", err)
	}
	mine, err := createName(ada, org, "ssh.example.com", group, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := updateName(ada, &rpmgrv1.DnsName{Id: mine.GetId(), GatewayGroupId: other}, "", "gateway_group_id"); code(err) != connect.CodeNotFound {
		t.Errorf("an update to another org's group: %v", err)
	}
	// Bob's group, Bob's name: not Ada's domain, not Ada's group.
	if _, err := createName(bob, orgB, "ssh.example.com", other, 0); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonDomainNotVerified {
		t.Errorf("another org's domain: %v", err)
	}
	if _, err := createName(bob, orgB, "x.bob.test", group, 0); code(err) != connect.CodeNotFound {
		t.Errorf("Bob with Ada's group: %v", err)
	}
	if _, err := createName(bob, org, "y.example.com", group, 0); code(err) != connect.CodeNotFound {
		t.Errorf("Bob in Ada's org: %v", err)
	}
	if got := e.db.Client().DNSName.GetX(e.sys, mine.GetId()); got.GatewayGroupID != group || got.Version != 1 {
		t.Error("a refused update changed the name")
	}
}

// TestDnsNames_OtherOrg: another org's name, and an org the caller is not in, are NOT_FOUND to
// every method, and nothing changes. A name in another org's name space is not an oracle: the
// same name is not offered to another org's domains.
func TestDnsNames_OtherOrg(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	n, err := createName(ada, org, "ssh.example.com", group, 0)
	if err != nil {
		t.Fatal(err)
	}
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	for name, call := range map[string]func() error{
		"get": func() error {
			_, err := bob.dnsn.GetDnsName(ctx, connect.NewRequest(&rpmgrv1.GetDnsNameRequest{DnsNameId: n.GetId()}))
			return err
		},
		"update": func() error {
			_, err := updateName(bob, &rpmgrv1.DnsName{Id: n.GetId(), Ttl: 120}, "", "ttl")
			return err
		},
		"delete": func() error { return deleteName(bob, n.GetId(), "") },
		"list org a": func() error {
			_, err := bob.dnsn.ListDnsNames(ctx, connect.NewRequest(&rpmgrv1.ListDnsNamesRequest{OrgId: org}))
			return err
		},
		"create in org a": func() error { _, err := createName(bob, org, "z.example.com", group, 0); return err },
	} {
		if got := code(call()); got != connect.CodeNotFound {
			t.Errorf("%s: %v", name, got)
		}
	}
	if l, err := bob.dnsn.ListDnsNames(ctx, connect.NewRequest(&rpmgrv1.ListDnsNamesRequest{OrgId: orgB})); err != nil || len(l.Msg.GetDnsNames()) != 0 {
		t.Errorf("Bob lists %v %v", l, err)
	}
	if row := e.db.Client().DNSName.GetX(e.sys, n.GetId()); row.TTL != 0 || row.Version != 1 {
		t.Error("another org's call changed the name")
	}
}

// TestDnsNames_Roles: everyone in the org reads names; Owners and Admins change them; an Operator
// and a Viewer cannot.
func TestDnsNames_Roles(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	n, err := createName(ada, org, "ssh.example.com", group, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ada.stepUp(pw, ""); err != nil { // granting Admin needs one
		t.Fatal(err)
	}
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	if _, err := createName(adm, org, "by-admin.example.com", group, 0); err != nil {
		t.Errorf("an Admin creates: %v", err)
	}
	for _, role := range []string{"operator", "viewer"} {
		u, _ := e.join(t, ada, org, role+"@example.com", role)
		if g, err := u.dnsn.GetDnsName(ctx, connect.NewRequest(&rpmgrv1.GetDnsNameRequest{DnsNameId: n.GetId()})); err != nil || g.Msg.GetDnsName().GetFqdn() != "ssh.example.com" {
			t.Errorf("a %s reads: %v", role, err)
		}
		if l, err := u.dnsn.ListDnsNames(ctx, connect.NewRequest(&rpmgrv1.ListDnsNamesRequest{OrgId: org})); err != nil || len(l.Msg.GetDnsNames()) != 2 {
			t.Errorf("a %s lists: %v %v", role, l, err)
		}
		for name, call := range map[string]func() error{
			"create": func() error { _, err := createName(u, org, role+".example.com", group, 0); return err },
			"update": func() error {
				_, err := updateName(u, &rpmgrv1.DnsName{Id: n.GetId(), Ttl: 120}, "", "ttl")
				return err
			},
			"delete": func() error { return deleteName(u, n.GetId(), "") },
		} {
			if c := code(call()); c != connect.CodePermissionDenied {
				t.Errorf("a %s calls %s: %v", role, name, c)
			}
		}
	}
	if nameCount(e) != 2 {
		t.Errorf("%d names, want the 2 of the Owner and the Admin", nameCount(e))
	}
}

// TestDnsNames_UpdateDelete: the group and the TTL change as the mask says and the name does not;
// a stale etag, a bad TTL and a path that is not allowed are refused; a deleted name can be made
// again; the domain that covers a name and the group it points at stay while it exists.
func TestDnsNames_UpdateDelete(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	domainID := e.verified(t, org, "example.com", true)
	g2, err := ada.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org, GatewayGroup: &rpmgrv1.GatewayGroup{Name: "us"}}))
	if err != nil {
		t.Fatal(err)
	}
	second := g2.Msg.GetGatewayGroup().GetId()
	n, err := createName(ada, org, "ssh.example.com", group, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := updateName(ada, &rpmgrv1.DnsName{Id: n.GetId(), GatewayGroupId: second, Ttl: 600}, "1", "gateway_group_id", "ttl")
	if err != nil || got.GetGatewayGroupId() != second || got.GetTtl() != 600 || got.GetEtag() != "2" || got.GetFqdn() != "ssh.example.com" {
		t.Fatalf("updated: %v %v", got, err)
	}
	if got, err := updateName(ada, &rpmgrv1.DnsName{Id: n.GetId(), Ttl: 0}, "", "ttl"); err != nil || got.GetTtl() != 0 || got.GetGatewayGroupId() != second {
		t.Errorf("one field: %v %v", got, err)
	}
	for name, c := range map[string]struct {
		n     *rpmgrv1.DnsName
		etag  string
		paths []string
		want  connect.Code
	}{
		"the name":     {&rpmgrv1.DnsName{Id: n.GetId(), Fqdn: "other.example.com"}, "", []string{"fqdn"}, connect.CodeInvalidArgument},
		"the id":       {&rpmgrv1.DnsName{Id: n.GetId()}, "", []string{"id"}, connect.CodeInvalidArgument},
		"no mask":      {&rpmgrv1.DnsName{Id: n.GetId(), Ttl: 100}, "", nil, connect.CodeInvalidArgument},
		"ttl too low":  {&rpmgrv1.DnsName{Id: n.GetId(), Ttl: 10}, "", []string{"ttl"}, connect.CodeInvalidArgument},
		"ttl too high": {&rpmgrv1.DnsName{Id: n.GetId(), Ttl: 100000}, "", []string{"ttl"}, connect.CodeInvalidArgument},
		"empty group":  {&rpmgrv1.DnsName{Id: n.GetId()}, "", []string{"gateway_group_id"}, connect.CodeNotFound},
		"stale etag":   {&rpmgrv1.DnsName{Id: n.GetId(), Ttl: 100}, "1", []string{"ttl"}, connect.CodeFailedPrecondition},
		"missing":      {&rpmgrv1.DnsName{Id: "dnn_missing", Ttl: 100}, "", []string{"ttl"}, connect.CodeNotFound},
	} {
		if _, err := updateName(ada, c.n, c.etag, c.paths...); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The domain and the group are not deleted from under a name.
	if _, err := ada.dom.DeleteDomain(ctx, connect.NewRequest(&rpmgrv1.DeleteDomainRequest{DomainId: domainID})); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonDependantsExist {
		t.Errorf("deleting the domain of a name: %v", err)
	}
	if _, err := ada.gw.DeleteGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.DeleteGatewayGroupRequest{GatewayGroupId: second})); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonDependantsExist {
		t.Errorf("deleting the group of a name: %v", err)
	}

	if err := deleteName(ada, n.GetId(), "1"); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a stale etag on delete: %v", err)
	}
	if nameCount(e) != 1 {
		t.Fatal("a refused delete removed the name")
	}
	if err := deleteName(ada, n.GetId(), "3"); err != nil {
		t.Fatal(err)
	}
	if err := deleteName(ada, n.GetId(), ""); code(err) != connect.CodeNotFound {
		t.Errorf("a second delete: %v", err)
	}
	if _, err := createName(ada, org, "ssh.example.com", group, 0); err != nil {
		t.Errorf("the name after its deletion: %v", err)
	}
	if _, err := ada.gw.DeleteGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.DeleteGatewayGroupRequest{GatewayGroupId: second})); err != nil {
		t.Errorf("a group without names: %v", err)
	}
}

// TestDnsNames_ListPages: names come by ID, page by page, with a token that only fits the same
// request.
func TestDnsNames_ListPages(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	for i := range 3 {
		if _, err := createName(ada, org, fmt.Sprintf("n%d.example.com", i), group, 0); err != nil {
			t.Fatal(err)
		}
	}
	p1, err := ada.dnsn.ListDnsNames(ctx, connect.NewRequest(&rpmgrv1.ListDnsNamesRequest{OrgId: org, PageSize: 2}))
	if err != nil || len(p1.Msg.GetDnsNames()) != 2 || p1.Msg.GetNextPageToken() == "" {
		t.Fatalf("page 1: %v %v", p1, err)
	}
	p2, err := ada.dnsn.ListDnsNames(ctx, connect.NewRequest(&rpmgrv1.ListDnsNamesRequest{OrgId: org, PageSize: 2, PageToken: p1.Msg.GetNextPageToken()}))
	if err != nil || len(p2.Msg.GetDnsNames()) != 1 || p2.Msg.GetNextPageToken() != "" {
		t.Fatalf("page 2: %v %v", p2, err)
	}
	if _, err := ada.dnsn.ListDnsNames(ctx, connect.NewRequest(&rpmgrv1.ListDnsNamesRequest{OrgId: org, PageToken: "forged"})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a forged page token: %v", err)
	}
	if _, err := ada.dnsn.ListDnsNames(ctx, connect.NewRequest(&rpmgrv1.ListDnsNamesRequest{OrgId: org, PageSize: -1})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a negative page size: %v", err)
	}
}
