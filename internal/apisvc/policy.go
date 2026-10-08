// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/accesspolicy"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routepolicy"
)

// Policies is PolicyService. Its methods run in the org scope the interceptor gives them.
type Policies struct {
	rpmgrv1connect.UnimplementedPolicyServiceHandler
	DB  *store.DB
	API *api.Server
	// Sys is the controller's system scope, for the instance's password hash profile.
	Sys context.Context
}

// CreateAccessPolicy implements PolicyService.
func (p *Policies) CreateAccessPolicy(ctx context.Context, req *connect.Request[rpmgrv1.CreateAccessPolicyRequest]) (
	*connect.Response[rpmgrv1.CreateAccessPolicyResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, p.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateAccessPolicyResponse, error) {
		in := m.GetAccessPolicy()
		hashes, err := p.hashRules(ctx, in.GetRules())
		if err != nil {
			return nil, err
		}
		var row *ent.AccessPolicy
		rev, err := store.ConfigTx(ctx, p.DB, func(tx *ent.Tx) ([]string, error) {
			var err error
			row, err = tx.AccessPolicy.Create().SetOrgID(m.GetOrgId()).SetName(in.GetName()).SetDescription(in.GetDescription()).Save(ctx)
			if err != nil {
				return nil, err
			}
			return []string{row.ID}, storeRules(ctx, tx, row, in.GetRules(), hashes)
		})
		if err != nil {
			return nil, storeError(err)
		}
		out, err := policyOf(ctx, p.DB.ReadClient(), row)
		if err != nil {
			return nil, storeError(err)
		}
		return &rpmgrv1.CreateAccessPolicyResponse{AccessPolicy: out, Revision: revisionOf(rev)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// GetAccessPolicy implements PolicyService.
func (p *Policies) GetAccessPolicy(ctx context.Context, req *connect.Request[rpmgrv1.GetAccessPolicyRequest]) (
	*connect.Response[rpmgrv1.GetAccessPolicyResponse], error) {
	c := p.DB.ReadClient()
	row, err := c.AccessPolicy.Get(ctx, req.Msg.GetAccessPolicyId())
	if err != nil {
		return nil, storeError(err)
	}
	out, err := policyOf(ctx, c, row)
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetAccessPolicyResponse{AccessPolicy: out}), nil
}

// ListAccessPolicies implements PolicyService.
func (p *Policies) ListAccessPolicies(ctx context.Context, req *connect.Request[rpmgrv1.ListAccessPoliciesRequest]) (
	*connect.Response[rpmgrv1.ListAccessPoliciesResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := p.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	c := p.DB.ReadClient()
	q := c.AccessPolicy.Query().Where(accesspolicy.OrgID(m.GetOrgId())).Order(ent.Asc(accesspolicy.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(accesspolicy.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListAccessPoliciesResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = p.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		ap, err := policyOf(ctx, c, r)
		if err != nil {
			return nil, storeError(err)
		}
		out.AccessPolicies = append(out.AccessPolicies, ap)
	}
	return connect.NewResponse(out), nil
}

// hashRules checks rules and hashes the passwords they give, under the instance's profile, a few
// at once. It runs outside a transaction, which the hashes would hold for long.
func (p *Policies) hashRules(ctx context.Context, rules []*rpmgrv1.AccessRule) (map[*rpmgrv1.BasicAuthCredential]string, error) {
	var users []*rpmgrv1.BasicAuthCredential
	for i, r := range rules {
		invalid := func(format string, args ...any) error {
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: rule %d: "+format, append([]any{i + 1}, args...)...))
		}
		for _, c := range ipRuleOf(r).GetCidrs() {
			if _, err := netip.ParsePrefix(c); err != nil {
				return nil, invalid("%q is not a CIDR", c)
			}
		}
		names := map[string]bool{}
		for _, u := range r.GetBasicAuth().GetUsers() {
			if names[u.GetName()] {
				return nil, invalid("user %q twice", u.GetName())
			}
			names[u.GetName()] = true
			if u.GetPassword() == "" {
				continue
			}
			if err := password.CheckLength(u.GetPassword()); err != nil {
				return nil, invalid("user %q: %v", u.GetName(), err)
			}
			users = append(users, u)
		}
	}
	if len(users) == 0 {
		return nil, nil
	}
	inst, _, err := settings.Instance(p.Sys, p.DB.ReadClient())
	if err != nil {
		return nil, err
	}
	params := password.ParamsOf(inst.GetPasswordHashProfile())
	hashes, errs := make([]string, len(users)), make([]error, len(users))
	var wg sync.WaitGroup
	for i, u := range users {
		wg.Go(func() { hashes[i], errs[i] = password.Hash(ctx, u.GetPassword(), params) })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	out := make(map[*rpmgrv1.BasicAuthCredential]string, len(users))
	for i, u := range users {
		out[u] = hashes[i]
	}
	return out, nil
}

// ipRuleOf is an IP rule's parameters; nil for another kind.
func ipRuleOf(r *rpmgrv1.AccessRule) *rpmgrv1.IPRuleParams {
	if r.GetIpAllow() != nil {
		return r.GetIpAllow()
	}
	return r.GetIpDeny()
}

// storeRules adds a policy's rules in order: CIDRs in their masked form, basic_auth users with the
// hash of their password.
func storeRules(ctx context.Context, tx *ent.Tx, policy *ent.AccessPolicy, rules []*rpmgrv1.AccessRule,
	hashes map[*rpmgrv1.BasicAuthCredential]string) error {
	for i, r := range rules {
		params := &rpmgrv1.PolicyRuleParams{}
		var kind policyrule.Kind
		switch {
		case r.GetBasicAuth() != nil:
			kind = policyrule.KindBasicAuth
			ba := &rpmgrv1.BasicAuthParams{}
			for _, u := range r.GetBasicAuth().GetUsers() {
				h, ok := hashes[u]
				if !ok {
					return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: rule %d: user %q needs a password", i+1, u.GetName()))
				}
				ba.Users = append(ba.Users, &rpmgrv1.BasicAuthUser{Name: u.GetName(), PasswordHash: h})
			}
			params.Params = &rpmgrv1.PolicyRuleParams_BasicAuth{BasicAuth: ba}
		default:
			kind = policyrule.KindIPDeny
			if r.GetIpAllow() != nil {
				kind = policyrule.KindIPAllow
			}
			ip := &rpmgrv1.IPRuleParams{}
			for _, c := range ipRuleOf(r).GetCidrs() {
				ip.Cidrs = append(ip.Cidrs, netip.MustParsePrefix(c).Masked().String())
			}
			params.Params = &rpmgrv1.PolicyRuleParams_Ip{Ip: ip}
		}
		b, err := proto.Marshal(params)
		if err != nil {
			return err
		}
		if err := tx.PolicyRule.Create().SetOrgID(policy.OrgID).SetPolicyID(policy.ID).SetPosition(i).SetKind(kind).SetParams(b).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// policyOf is an access policy as the API shows it: its rules in order, basic_auth users by name
// only, and the routes that apply it.
func policyOf(ctx context.Context, c *ent.Client, row *ent.AccessPolicy) (*rpmgrv1.AccessPolicy, error) {
	out := &rpmgrv1.AccessPolicy{Id: row.ID, Name: row.Name, Description: row.Description, Etag: etagOf(row.Version)}
	rules, err := c.PolicyRule.Query().Where(policyrule.PolicyID(row.ID)).Order(ent.Asc(policyrule.FieldPosition)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		var params rpmgrv1.PolicyRuleParams
		if err := proto.Unmarshal(r.Params, &params); err != nil {
			return nil, err
		}
		switch r.Kind {
		case policyrule.KindIPAllow:
			out.Rules = append(out.Rules, &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_IpAllow{IpAllow: params.GetIp()}})
		case policyrule.KindIPDeny:
			out.Rules = append(out.Rules, &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_IpDeny{IpDeny: params.GetIp()}})
		case policyrule.KindBasicAuth:
			ba := &rpmgrv1.BasicAuthRule{}
			for _, u := range params.GetBasicAuth().GetUsers() {
				ba.Users = append(ba.Users, &rpmgrv1.BasicAuthCredential{Name: u.GetName()})
			}
			out.Rules = append(out.Rules, &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_BasicAuth{BasicAuth: ba}})
		}
	}
	if out.RouteIds, err = c.RoutePolicy.Query().Where(routepolicy.PolicyID(row.ID)).Order(ent.Asc(routepolicy.FieldRouteID)).
		Select(routepolicy.FieldRouteID).Strings(ctx); err != nil {
		return nil, err
	}
	return out, nil
}
