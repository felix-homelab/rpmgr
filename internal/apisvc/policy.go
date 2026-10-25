// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"net/textproto"
	"slices"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"golang.org/x/net/http/httpguts"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/accesspolicy"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routepolicy"
)

// ReasonBasicAuthNotHTTP: a basic_auth rule would apply to a route that is not an http route,
// where no client could pass it (docs/03-connections.md, "Access policies").
const ReasonBasicAuthNotHTTP = "BASIC_AUTH_NOT_HTTP"

// ReasonRequireHeaderNotHTTP: a require_header rule would apply to a route that is not an http
// route, where no client could pass it (docs/03-connections.md, "Access policies").
const ReasonRequireHeaderNotHTTP = "REQUIRE_HEADER_NOT_HTTP"

// minHeaderValue is the shortest require_header value: a shared secret of this length is not
// guessable, so the controller keeps only its SHA-256 (docs/04-security.md, "Route edge rules").
const minHeaderValue = 32

// Limits of a require_header rule that the proto also states, checked here as well so that no
// path around the request validation stores more.
const (
	maxHeaderName  = 128
	maxHeaderValue = 1024
	// minDistinct is the fewest distinct characters a value needs: the gateways hold unsalted
	// SHA-256, so a value must be random, and one such as "aaaa…" or "12341234…" is refused.
	minDistinct = 8
)

// distinct counts the distinct bytes of s.
func distinct(s string) int {
	var seen [256]bool
	n := 0
	for i := range len(s) {
		if !seen[s[i]] {
			seen[s[i]], n = true, n+1
		}
	}
	return n
}

// Policies is PolicyService. Its methods run in the org scope the interceptor gives them.
type Policies struct {
	rpmgrv1connect.UnimplementedPolicyServiceHandler
	DB  *store.DB
	API *api.Server
	// Sys is the controller's system scope, for the instance's password hash profile.
	Sys context.Context
}

// policyFields are the fields of an access policy a client may change.
var policyFields = []string{"name", "description", "rules"}

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
			return []string{row.ID}, storeRules(ctx, tx, row, in.GetRules(), hashes, keptSecrets{})
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

// UpdateAccessPolicy implements PolicyService. New rules replace the old ones; a basic_auth user
// without a password keeps the hash of the old rules' user of that name.
func (p *Policies) UpdateAccessPolicy(ctx context.Context, req *connect.Request[rpmgrv1.UpdateAccessPolicyRequest]) (
	*connect.Response[rpmgrv1.UpdateAccessPolicyResponse], error) {
	m := req.Msg
	in := m.GetAccessPolicy()
	replace := slices.Contains(m.GetUpdateMask().GetPaths(), "rules")
	var hashes map[*rpmgrv1.BasicAuthCredential]string
	if replace {
		var err error
		if hashes, err = p.hashRules(ctx, in.GetRules()); err != nil {
			return nil, err
		}
	}
	var row *ent.AccessPolicy
	rev, err := store.ConfigTx(ctx, p.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.AccessPolicy.Get(ctx, in.GetId())
		if err != nil {
			return nil, err
		}
		shown, err := policyOf(ctx, tx.Client(), cur)
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(m.GetEtag(), cur.Version, shown); err != nil {
			return nil, err
		}
		next := proto.Clone(shown).(*rpmgrv1.AccessPolicy)
		if err := api.ApplyMask(next, in, m.GetUpdateMask(), policyFields...); err != nil {
			return nil, err
		}
		if row, err = tx.AccessPolicy.UpdateOneID(cur.ID).Where(accesspolicy.Version(cur.Version)).SetName(next.GetName()).
			SetDescription(next.GetDescription()).Save(ctx); err != nil {
			return nil, err
		}
		if replace {
			kept, err := keptHashes(ctx, tx, cur.ID)
			if err != nil {
				return nil, err
			}
			if _, err := tx.PolicyRule.Delete().Where(policyrule.PolicyID(cur.ID)).Exec(ctx); err != nil {
				return nil, err
			}
			if err := storeRules(ctx, tx, row, in.GetRules(), hashes, kept); err != nil {
				return nil, err
			}
		}
		return append([]string{cur.ID}, shown.GetRouteIds()...), nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	out, err := policyOf(ctx, p.DB.ReadClient(), row)
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateAccessPolicyResponse{AccessPolicy: out, Revision: revisionOf(rev)}), nil
}

// DeleteAccessPolicy implements PolicyService.
func (p *Policies) DeleteAccessPolicy(ctx context.Context, req *connect.Request[rpmgrv1.DeleteAccessPolicyRequest]) (
	*connect.Response[rpmgrv1.DeleteAccessPolicyResponse], error) {
	rev, err := store.ConfigTx(ctx, p.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.AccessPolicy.Get(ctx, req.Msg.GetAccessPolicyId())
		if err != nil {
			return nil, err
		}
		shown, err := policyOf(ctx, tx.Client(), cur)
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, shown); err != nil {
			return nil, err
		}
		if n := len(shown.GetRouteIds()); n > 0 {
			return nil, dependants(fmt.Sprintf("%d routes apply the policy", n))
		}
		if _, err := tx.PolicyRule.Delete().Where(policyrule.PolicyID(cur.ID)).Exec(ctx); err != nil {
			return nil, err
		}
		return []string{cur.ID}, tx.AccessPolicy.DeleteOneID(cur.ID).Where(accesspolicy.Version(cur.Version)).Exec(ctx)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteAccessPolicyResponse{Revision: revisionOf(rev)}), nil
}

// hashRules checks rules and hashes the passwords they give, under the instance's profile, a few
// at once. It runs outside a transaction, which the hashes would hold for long.
func (p *Policies) hashRules(ctx context.Context, rules []*rpmgrv1.AccessRule) (map[*rpmgrv1.BasicAuthCredential]string, error) {
	var users []*rpmgrv1.BasicAuthCredential
	headers := map[string]bool{} // the policy's required headers, by canonical name
	for i, r := range rules {
		invalid := func(format string, args ...any) error {
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: rule %d: "+format, append([]any{i + 1}, args...)...))
		}
		for _, c := range ipRuleOf(r).GetCidrs() {
			if _, err := netip.ParsePrefix(c); err != nil {
				return nil, invalid("%q is not a CIDR", c)
			}
		}
		if rh := r.GetRequireHeader(); rh != nil {
			if err := checkRequireHeader(rh, headers); err != nil {
				return nil, invalid("%v", err)
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

// checkRequireHeader checks a require_header rule: a header that may be required, once per policy
// (seen), and up to 4 distinct values of 32 to 1024 visible ASCII characters. A rule without
// values keeps the stored ones, which storeRules checks.
func checkRequireHeader(rh *rpmgrv1.RequireHeaderRule, seen map[string]bool) error {
	name := textproto.CanonicalMIMEHeaderKey(rh.GetName())
	switch {
	case !httpguts.ValidHeaderFieldName(rh.GetName()) || len(rh.GetName()) > maxHeaderName:
		return fmt.Errorf("header name %q", rh.GetName())
	case gateway.NotRequirable(name) != "":
		return fmt.Errorf("header %s %s and cannot be required", name, gateway.NotRequirable(name))
	case seen[name]:
		return fmt.Errorf("header %s is required twice; give its values in one rule", name)
	case len(rh.GetValues()) > 4:
		return fmt.Errorf("header %s has %d values, at most 4", name, len(rh.GetValues()))
	}
	seen[name] = true
	for i, v := range rh.GetValues() {
		switch {
		case len(v) < minHeaderValue || len(v) > maxHeaderValue:
			return fmt.Errorf("value %d of header %s has %d characters, not %d to %d", i+1, name, len(v), minHeaderValue, maxHeaderValue)
		case strings.IndexFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0:
			return fmt.Errorf("value %d of header %s has a character that is not visible ASCII", i+1, name)
		case slices.Contains(rh.GetValues()[:i], v):
			return fmt.Errorf("value %d of header %s is given twice", i+1, name)
		case distinct(v) < minDistinct:
			return fmt.Errorf("value %d of header %s has fewer than %d different characters; use a random value, such as one of openssl rand -base64 32", i+1, name, minDistinct)
		}
	}
	return nil
}

// ipRuleOf is an IP rule's parameters; nil for another kind.
func ipRuleOf(r *rpmgrv1.AccessRule) *rpmgrv1.IPRuleParams {
	if r.GetIpAllow() != nil {
		return r.GetIpAllow()
	}
	return r.GetIpDeny()
}

// keptSecrets are the hashes of a policy's secrets that an update keeps when it does not give them
// again: passwords by basic_auth user name, the first rule's where two have the name, and value
// hashes by required header.
type keptSecrets struct {
	passwords map[string]string
	headers   map[string][][]byte
}

// keptHashes reads the hashes of a policy's secrets.
func keptHashes(ctx context.Context, tx *ent.Tx, policyID string) (keptSecrets, error) {
	out := keptSecrets{passwords: map[string]string{}, headers: map[string][][]byte{}}
	rows, err := tx.PolicyRule.Query().Where(policyrule.PolicyID(policyID), policyrule.KindIn(policyrule.KindBasicAuth,
		policyrule.KindRequireHeader)).Order(ent.Asc(policyrule.FieldPosition)).All(ctx)
	if err != nil {
		return out, err
	}
	for _, r := range rows {
		var params rpmgrv1.PolicyRuleParams
		if err := proto.Unmarshal(r.Params, &params); err != nil {
			return out, err
		}
		for _, u := range params.GetBasicAuth().GetUsers() {
			if _, ok := out.passwords[u.GetName()]; !ok {
				out.passwords[u.GetName()] = u.GetPasswordHash()
			}
		}
		if rh := params.GetRequireHeader(); rh != nil {
			out.headers[rh.GetName()] = rh.GetValueSha256()
		}
	}
	return out, nil
}

// storeRules adds a policy's rules in order: CIDRs in their masked form, basic_auth users with the
// hash of their password or, without one, their kept hash, and require_header rules with the
// SHA-256 of their values or, without any, the kept ones. A basic_auth or require_header rule is
// refused while a route that is not an http route applies the policy.
func storeRules(ctx context.Context, tx *ent.Tx, policy *ent.AccessPolicy, rules []*rpmgrv1.AccessRule,
	hashes map[*rpmgrv1.BasicAuthCredential]string, kept keptSecrets) error {
	httpOnly := func(i int, what, reason string) error {
		n, err := tx.RoutePolicy.Query().Where(routepolicy.PolicyID(policy.ID),
			routepolicy.HasRouteWith(route.TypeNEQ(route.TypeHTTP))).Count(ctx)
		if err != nil || n == 0 {
			return err
		}
		return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"apisvc: rule %d: %d routes that are not http routes apply the policy, and no client could pass %s there", i+1, n, what)), reason)
	}
	// basicOnly is httpOnly for basic auth, which a CONNECT route of a basic mode takes too.
	basicOnly := func(i int) error {
		ids, err := tx.RoutePolicy.Query().Where(routepolicy.PolicyID(policy.ID)).Select(routepolicy.FieldRouteID).Strings(ctx)
		if err != nil {
			return err
		}
		others, err := tx.Route.Query().Where(route.IDIn(ids...), route.TypeNEQ(route.TypeHTTP)).All(ctx)
		if err != nil {
			return err
		}
		n := 0
		for _, rt := range others {
			if ok, err := routes.BasicAuthAllowed(ctx, tx, rt); err != nil {
				return err
			} else if !ok {
				n++
			}
		}
		if n == 0 {
			return nil
		}
		return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"apisvc: rule %d: %d routes that are not http routes apply the policy, and no client could pass basic auth there", i+1, n)),
			ReasonBasicAuthNotHTTP)
	}
	rateLimits := 0
	for i, r := range rules {
		params := &rpmgrv1.PolicyRuleParams{}
		var kind policyrule.Kind
		switch {
		case r.GetRequireHeader() != nil:
			kind = policyrule.KindRequireHeader
			if err := httpOnly(i, "a require-header rule", ReasonRequireHeaderNotHTTP); err != nil {
				return err
			}
			rh := &rpmgrv1.RequireHeaderParams{Name: textproto.CanonicalMIMEHeaderKey(r.GetRequireHeader().GetName())}
			for _, v := range r.GetRequireHeader().GetValues() {
				sum := sha256.Sum256([]byte(v))
				rh.ValueSha256 = append(rh.ValueSha256, sum[:])
			}
			if len(rh.ValueSha256) == 0 {
				if rh.ValueSha256 = kept.headers[rh.GetName()]; len(rh.ValueSha256) == 0 {
					return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: rule %d: header %s needs a value", i+1, rh.GetName()))
				}
			}
			params.Params = &rpmgrv1.PolicyRuleParams_RequireHeader{RequireHeader: rh}
		case r.GetBasicAuth() != nil:
			kind = policyrule.KindBasicAuth
			if err := basicOnly(i); err != nil {
				return err
			}
			ba := &rpmgrv1.BasicAuthParams{}
			for _, u := range r.GetBasicAuth().GetUsers() {
				h, ok := hashes[u]
				if !ok {
					if h, ok = kept.passwords[u.GetName()]; !ok {
						return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: rule %d: user %q needs a password", i+1, u.GetName()))
					}
				}
				ba.Users = append(ba.Users, &rpmgrv1.BasicAuthUser{Name: u.GetName(), PasswordHash: h})
			}
			params.Params = &rpmgrv1.PolicyRuleParams_BasicAuth{BasicAuth: ba}
		case r.GetRateLimit() != nil:
			// On every route type (D131): gateways count new connections and flows as requests. One
			// rule a policy, as each new client takes an entry in a gateway's table of every rule
			// (D137).
			if rateLimits++; rateLimits > 1 {
				return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: rule %d: a policy has at most one rate_limit rule", i+1))
			}
			kind = policyrule.KindRateLimit
			params.Params = &rpmgrv1.PolicyRuleParams_RateLimit{RateLimit: r.GetRateLimit()}
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
// only, require_header rules by header only, and the routes that apply it.
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
		case policyrule.KindRequireHeader:
			out.Rules = append(out.Rules, &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_RequireHeader{
				RequireHeader: &rpmgrv1.RequireHeaderRule{Name: params.GetRequireHeader().GetName()}}})
		case policyrule.KindRateLimit:
			out.Rules = append(out.Rules, &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_RateLimit{RateLimit: params.GetRateLimit()}})
		}
	}
	if out.RouteIds, err = c.RoutePolicy.Query().Where(routepolicy.PolicyID(row.ID)).Order(ent.Asc(routepolicy.FieldRouteID)).
		Select(routepolicy.FieldRouteID).Strings(ctx); err != nil {
		return nil, err
	}
	return out, nil
}
