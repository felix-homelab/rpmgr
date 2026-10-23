// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/totp"
)

// The upgrade test's fixture data (docs/12-testing-and-quality.md, "Upgrade test"): what an
// installation of the earlier release holds beyond its routes, created through that release's API
// and local commands before the upgrade and read back through this tree's API after it.

// ctlAddr is the controller's address on the public network of compose.yaml, which the host
// reaches; its web certificate names ctl.
const ctlAddr = "172.30.0.10:8443"

const fixturePassword = "upgrade-fixture-passphrase-1"

const (
	fixtureAdmin  = "ada@upgrade.e2e.test"
	fixtureMember = "grace@upgrade.e2e.test"
)

// api holds the API's services for one caller: a session whose cookie the jar keeps, or an API
// token.
type api struct {
	auth  rpmgrv1connect.AuthServiceClient
	org   rpmgrv1connect.OrgServiceClient
	user  rpmgrv1connect.UserServiceClient
	tok   rpmgrv1connect.TokenServiceClient
	audit rpmgrv1connect.AuditServiceClient
	con   rpmgrv1connect.ConnectorServiceClient
	enr   rpmgrv1connect.EnrollmentServiceClient
	dom   rpmgrv1connect.DomainServiceClient
	pol   rpmgrv1connect.PolicyServiceClient
	cert  rpmgrv1connect.CertificateServiceClient
	set   rpmgrv1connect.SettingsServiceClient
}

// newAPI is a client of the controller's API from the host; with a token, it sends it as a Bearer
// header, as the CLI does.
func newAPI(t *testing.T, token string) *api {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(webCA)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	hc := &http.Client{Jar: jar, Timeout: time.Minute, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == "ctl:8443" {
				addr = ctlAddr
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}}
	var opts []connect.ClientOption
	if token != "" {
		opts = append(opts, connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				req.Header().Set("Authorization", "Bearer "+token)
				return next(ctx, req)
			}
		})))
	}
	base := controllerURL
	return &api{
		auth: rpmgrv1connect.NewAuthServiceClient(hc, base, opts...), org: rpmgrv1connect.NewOrgServiceClient(hc, base, opts...),
		user: rpmgrv1connect.NewUserServiceClient(hc, base, opts...), tok: rpmgrv1connect.NewTokenServiceClient(hc, base, opts...),
		audit: rpmgrv1connect.NewAuditServiceClient(hc, base, opts...), con: rpmgrv1connect.NewConnectorServiceClient(hc, base, opts...),
		enr: rpmgrv1connect.NewEnrollmentServiceClient(hc, base, opts...), dom: rpmgrv1connect.NewDomainServiceClient(hc, base, opts...),
		pol: rpmgrv1connect.NewPolicyServiceClient(hc, base, opts...), cert: rpmgrv1connect.NewCertificateServiceClient(hc, base, opts...),
		set: rpmgrv1connect.NewSettingsServiceClient(hc, base, opts...),
	}
}

// call runs one API call and stops the test if it fails.
func call[Req, Res any](t *testing.T, what string, f func(context.Context, *connect.Request[Req]) (*connect.Response[Res], error), req *Req) *Res {
	t.Helper()
	res, err := f(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	return res.Msg
}

// fragment is the token of a one-time link.
func fragment(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil || u.Fragment == "" {
		t.Fatalf("a one-time link without its token: %q", link)
	}
	return u.Fragment
}

// fixtures is what seedFixtures created and what the earlier release reported about it.
type fixtures struct {
	org            string
	totpSecret     []byte
	apiToken       string
	apiTokenID     string
	revoked        string // the decommissioned connector
	enrollment     string
	domain         *rpmgrv1.Domain
	policy         *rpmgrv1.AccessPolicy
	certificates   []string
	settings       *rpmgrv1.InstanceSettings
	audit          map[string]string // entry ID → action, of the org's chain
	instanceAudit  map[string]string // of the instance's chain
	orgHead        int64
	instanceHead   int64
	connectorsSeen int
}

// seedFixtures fills the earlier release's controller through its API and local commands: the
// first user, Instance Admin and Owner; an Operator with an authenticator; an API token; an
// enrollment token; a trusted domain; an access policy with basic auth; mail and ACME settings;
// and a connector that ran, then was decommissioned, so that its identity is revoked and its
// session ended. It records the audit chains last.
func seedFixtures(t *testing.T) *fixtures {
	t.Helper()
	f := &fixtures{}
	out, err := in("ctl", binOf("ctl"), "user", "reset-password", "--config", "/var/lib/rpmgr/controller.yaml")
	if err != nil {
		t.Fatal(err)
	}
	link := regexp.MustCompile(`https://\S+`).FindString(out)
	ada := newAPI(t, "")
	call(t, "the first user", ada.auth.CompletePasswordReset, &rpmgrv1.CompletePasswordResetRequest{Token: fragment(t, link),
		NewPassword: fixturePassword, Email: fixtureAdmin, DisplayName: "Ada Lovelace"})
	call(t, "sign-in", ada.auth.Login, &rpmgrv1.LoginRequest{Email: fixtureAdmin, Password: fixturePassword})
	call(t, "step-up", ada.auth.StepUp, &rpmgrv1.StepUpRequest{Password: fixturePassword})
	f.org = call(t, "session", ada.auth.GetSession, &rpmgrv1.GetSessionRequest{}).GetMemberships()[0].GetOrgId()

	// An Operator with an authenticator, whose secret the KEK encrypts.
	inv := call(t, "invite", ada.org.CreateInvitation, &rpmgrv1.CreateInvitationRequest{OrgId: f.org, Email: fixtureMember,
		Role: "operator", RequestId: uuid.NewString()})
	grace := newAPI(t, "")
	call(t, "accept", grace.org.AcceptInvitation, &rpmgrv1.AcceptInvitationRequest{Token: fragment(t, inv.GetUrl()),
		DisplayName: "Grace Hopper", Password: fixturePassword})
	call(t, "sign-in of the operator", grace.auth.Login, &rpmgrv1.LoginRequest{Email: fixtureMember, Password: fixturePassword})
	call(t, "step-up of the operator", grace.auth.StepUp, &rpmgrv1.StepUpRequest{Password: fixturePassword})
	secret := call(t, "authenticator", grace.user.EnrollTOTP, &rpmgrv1.EnrollTOTPRequest{}).GetSecret()
	if f.totpSecret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		t.Fatal(err)
	}
	call(t, "confirm the authenticator", grace.user.ConfirmTOTP, &rpmgrv1.ConfirmTOTPRequest{
		Code: totp.Code(f.totpSecret, totp.StepOf(time.Now()))})
	call(t, "sign-out of the operator", grace.auth.Logout, &rpmgrv1.LogoutRequest{})

	tok := call(t, "API token", ada.tok.CreateAPIToken, &rpmgrv1.CreateAPITokenRequest{OrgId: f.org, RequestId: uuid.NewString(),
		Name: "upgrade-fixture", Scopes: []string{"org.read", "audit.read"}, Ttl: durationpb.New(30 * 24 * time.Hour)})
	f.apiToken, f.apiTokenID = tok.GetToken(), tok.GetApiToken().GetId()
	maxUses := int32(5)
	f.enrollment = call(t, "enrollment token", ada.enr.CreateEnrollmentToken, &rpmgrv1.CreateEnrollmentTokenRequest{OrgId: f.org,
		RequestId: uuid.NewString(), Labels: map[string]string{"pool": "upgrade"}, Ephemeral: true, MaxUses: &maxUses,
		Ttl: durationpb.New(7 * 24 * time.Hour)}).GetEnrollmentToken().GetId()
	dom := call(t, "domain", ada.dom.CreateDomain, &rpmgrv1.CreateDomainRequest{OrgId: f.org, RequestId: uuid.NewString(),
		Domain: &rpmgrv1.Domain{Fqdn: "fixture.upgrade.test", Wildcard: true, Method: rpmgrv1.DomainMethod_DOMAIN_METHOD_DNS_TXT}}).GetDomain()
	call(t, "trust the domain", ada.dom.MarkDomainTrusted, &rpmgrv1.MarkDomainTrustedRequest{DomainId: dom.GetId()})
	f.domain = call(t, "the domain", ada.dom.GetDomain, &rpmgrv1.GetDomainRequest{DomainId: dom.GetId()}).GetDomain()
	f.policy = call(t, "access policy", ada.pol.CreateAccessPolicy, &rpmgrv1.CreateAccessPolicyRequest{OrgId: f.org,
		RequestId: uuid.NewString(), AccessPolicy: &rpmgrv1.AccessPolicy{Name: "upgrade-staff", Description: "basic auth across the upgrade",
			Rules: []*rpmgrv1.AccessRule{
				{Rule: &rpmgrv1.AccessRule_IpAllow{IpAllow: &rpmgrv1.IPRuleParams{Cidrs: []string{"198.51.100.0/24"}}}},
				{Rule: &rpmgrv1.AccessRule_BasicAuth{BasicAuth: &rpmgrv1.BasicAuthRule{Users: []*rpmgrv1.BasicAuthCredential{
					{Name: "staff", Password: fixturePassword}}}}},
			}}}).GetAccessPolicy()
	for _, c := range call(t, "certificates", ada.cert.ListCertificates, &rpmgrv1.ListCertificatesRequest{OrgId: f.org, PageSize: 100}).GetCertificates() {
		f.certificates = append(f.certificates, c.GetId())
	}

	// Mail and ACME settings, set after the invitation so that nothing is mailed.
	is := call(t, "instance settings", ada.set.GetInstanceSettings, &rpmgrv1.GetInstanceSettingsRequest{})
	is.GetSettings().Smtp = &rpmgrv1.SmtpSettings{Server: "smtp.upgrade.e2e.test:587", From: "rpmgr@upgrade.e2e.test", Username: "rpmgr",
		Security: rpmgrv1.SmtpSecurity_SMTP_SECURITY_STARTTLS}
	acme := "acme@upgrade.e2e.test"
	is.GetSettings().AcmeEmail = &acme
	f.settings = call(t, "update the instance settings", ada.set.UpdateInstanceSettings, &rpmgrv1.UpdateInstanceSettingsRequest{
		Settings: is.GetSettings(), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"smtp", "acme_email"}}, Etag: is.GetEtag()}).GetSettings()

	f.revoked = revokedConnector(t, ada, f.org)
	f.connectorsSeen = len(call(t, "connectors", ada.con.ListConnectors, &rpmgrv1.ListConnectorsRequest{OrgId: f.org,
		ShowDecommissioned: true, PageSize: 100}).GetConnectors())

	f.audit, f.orgHead = auditOf(t, ada, f.org)
	f.instanceAudit, f.instanceHead = auditOf(t, ada, "")
	return f
}

// revokedConnector enrolls a third connector in the client node with the earlier release, waits
// for its session, decommissions it and stops it.
func revokedConnector(t *testing.T, a *api, org string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(run, "ctl", "from", "rpmgr")) //nolint:gosec // G304: the test's own build output
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(run, "client", "from"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "client", "from", "rpmgr"), b, 0o755); err != nil { //nolint:gosec // G306: a binary the container runs
		t.Fatal(err)
	}
	binMu.Lock()
	fromNodes["client"] = true
	binMu.Unlock()
	tok, err := seed("connector-token", "--uses", "1")
	if err != nil {
		t.Fatal(err)
	}
	if err := enroll("client", tok); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"policy.yaml": connectorPolicy, "connector.yaml": `version: 1
controller: {endpoints: [` + controllerURL + `]}
identity_dir: /var/lib/rpmgr/identity
state_dir: /var/lib/rpmgr
policy_file: /var/lib/rpmgr/policy.yaml
listen: {admin: "127.0.0.1:7383"}
`} {
		if err := writeFile("client", name, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := startRole("client", "connector"); err != nil {
		t.Fatal(err)
	}
	var c *rpmgrv1.Connector
	eventually(t, 60*time.Second, "the third connector's session", func() error {
		c = nil
		res, err := a.con.ListConnectors(context.Background(), connect.NewRequest(&rpmgrv1.ListConnectorsRequest{OrgId: org, PageSize: 100}))
		if err != nil {
			return err
		}
		for _, x := range res.Msg.GetConnectors() {
			if !slices.Contains([]string{"con1", "con2"}, x.GetName()) && !x.GetBuiltIn() && x.GetSession().GetConnected() {
				c = x
				return nil
			}
		}
		return errNotYet
	})
	call(t, "decommission", a.con.DecommissionConnector, &rpmgrv1.DecommissionConnectorRequest{ConnectorId: c.GetId(), Etag: c.GetEtag()})
	stopClientConnector(t)
	eventually(t, 30*time.Second, "the decommissioned connector's session ended", func() error {
		res, err := a.con.GetConnector(context.Background(), connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: c.GetId()}))
		if err != nil {
			return err
		}
		if res.Msg.GetConnector().GetSession().GetConnected() {
			return errNotYet
		}
		return nil
	})
	return c.GetId()
}

// stopClientConnector stops the client node's connector, if it still runs: a revoked one may have
// ended by itself.
func stopClientConnector(t *testing.T) {
	t.Helper()
	if _, err := in("client", "pgrep", "-x", "rpmgr"); err != nil {
		return
	}
	if err := signal("client", "TERM"); err != nil {
		t.Fatal(err)
	}
}

// auditOf is every entry of the org's audit chain, or the instance's for org "", with the chain's
// head; the chain must verify.
func auditOf(t *testing.T, a *api, org string) (map[string]string, int64) {
	t.Helper()
	entries := map[string]string{}
	var head int64
	for page := ""; ; {
		var list []*rpmgrv1.AuditEntry
		var next string
		if org == "" {
			res := call(t, "the instance's audit", a.audit.ListInstanceAuditEntries, &rpmgrv1.ListInstanceAuditEntriesRequest{PageSize: 500, PageToken: page})
			list, next = res.GetEntries(), res.GetNextPageToken()
		} else {
			res := call(t, "the org's audit", a.audit.ListAuditEntries, &rpmgrv1.ListAuditEntriesRequest{OrgId: org, PageSize: 500, PageToken: page})
			list, next = res.GetEntries(), res.GetNextPageToken()
		}
		for _, e := range list {
			entries[e.GetId()] = e.GetAction()
		}
		if next == "" {
			break
		}
		page = next
	}
	var v *rpmgrv1.AuditVerification
	if org == "" {
		v = call(t, "verify the instance's audit", a.audit.VerifyInstanceAuditChain, &rpmgrv1.VerifyInstanceAuditChainRequest{}).GetVerification()
	} else {
		v = call(t, "verify the org's audit", a.audit.VerifyAuditChain, &rpmgrv1.VerifyAuditChainRequest{OrgId: org}).GetVerification()
	}
	if !v.GetIntact() {
		t.Errorf("the audit chain of org %q is broken at %d: %s", org, v.GetBrokenAt(), v.GetProblem())
	}
	head = v.GetHeadSeq()
	if len(entries) == 0 {
		t.Errorf("no audit entries in org %q", org)
	}
	return entries, head
}

// checkFixtures reads the fixture data back through this tree's API after the upgrade.
func checkFixtures(t *testing.T, f *fixtures) {
	t.Helper()
	ada := newAPI(t, "")
	if _, err := ada.auth.Login(context.Background(), connect.NewRequest(&rpmgrv1.LoginRequest{Email: fixtureAdmin, Password: "not-" + fixturePassword})); err == nil {
		t.Error("a sign-in with a wrong password succeeded after the upgrade")
	}
	call(t, "sign-in after the upgrade", ada.auth.Login, &rpmgrv1.LoginRequest{Email: fixtureAdmin, Password: fixturePassword})
	call(t, "step-up after the upgrade", ada.auth.StepUp, &rpmgrv1.StepUpRequest{Password: fixturePassword})
	if me := call(t, "me", ada.user.GetMe, &rpmgrv1.GetMeRequest{}).GetUser(); !me.GetInstanceAdmin() || me.GetEmail() != fixtureAdmin {
		t.Errorf("the first user after the upgrade: %v", me)
	}
	roles := map[string]string{}
	for _, m := range call(t, "members", ada.org.ListMembers, &rpmgrv1.ListMembersRequest{OrgId: f.org}).GetMembers() {
		roles[m.GetEmail()] = m.GetRole()
	}
	if roles[fixtureAdmin] != "owner" || roles[fixtureMember] != "operator" {
		t.Errorf("the members after the upgrade: %v", roles)
	}

	// The Operator needs the authenticator enrolled before the upgrade.
	grace := newAPI(t, "")
	if _, err := grace.auth.Login(context.Background(), connect.NewRequest(&rpmgrv1.LoginRequest{Email: fixtureMember, Password: fixturePassword,
		SecondFactor: "000000"})); err == nil {
		t.Error("the operator signed in with a wrong authenticator code after the upgrade")
	}
	eventually(t, 70*time.Second, "the operator's sign-in with the authenticator", func() error {
		// A code is accepted once; a refused attempt above or a code of the same step waits for the next.
		_, err := grace.auth.Login(context.Background(), connect.NewRequest(&rpmgrv1.LoginRequest{Email: fixtureMember, Password: fixturePassword,
			SecondFactor: totp.Code(f.totpSecret, totp.StepOf(time.Now()))}))
		return err
	})
	if me := call(t, "the operator", grace.user.GetMe, &rpmgrv1.GetMeRequest{}).GetUser(); !me.GetMfa() {
		t.Errorf("the operator has no second factor after the upgrade: %v", me)
	}

	// The API token of the earlier release, with its scopes.
	bearer := newAPI(t, f.apiToken)
	call(t, "the org through the API token", bearer.org.GetOrg, &rpmgrv1.GetOrgRequest{OrgId: f.org})
	if _, err := bearer.tok.CreateAPIToken(context.Background(), connect.NewRequest(&rpmgrv1.CreateAPITokenRequest{OrgId: f.org,
		RequestId: uuid.NewString(), Name: "beyond-scope", Scopes: []string{"org.read"}})); err == nil {
		t.Error("the read-only API token created a token after the upgrade")
	}

	// The audit chains keep every earlier entry and still verify; the upgrade only appends.
	for _, c := range []struct {
		org    string
		before map[string]string
		head   int64
	}{{f.org, f.audit, f.orgHead}, {"", f.instanceAudit, f.instanceHead}} {
		after, head := auditOf(t, ada, c.org)
		for id, action := range c.before {
			if after[id] != action {
				t.Errorf("audit entry %s (%s) of org %q after the upgrade: %q", id, action, c.org, after[id])
			}
		}
		if head < c.head {
			t.Errorf("the audit head of org %q went back from %d to %d", c.org, c.head, head)
		}
	}

	// The decommissioned connector stays revoked: its record, and its identity, which the
	// upgraded controller does not admit.
	revoked := call(t, "the decommissioned connector", ada.con.GetConnector, &rpmgrv1.GetConnectorRequest{ConnectorId: f.revoked}).GetConnector()
	if revoked.GetDecommissionTime() == nil || revoked.GetSession().GetConnected() {
		t.Errorf("the decommissioned connector after the upgrade: %v", revoked)
	}
	upgraded("client")
	if err := startRole("client", "connector"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Second)
	if c := call(t, "the decommissioned connector", ada.con.GetConnector, &rpmgrv1.GetConnectorRequest{ConnectorId: f.revoked}).GetConnector(); c.GetSession().GetConnected() {
		t.Error("the decommissioned connector's identity connected after the upgrade")
	}
	stopClientConnector(t)
	if n := len(call(t, "connectors", ada.con.ListConnectors, &rpmgrv1.ListConnectorsRequest{OrgId: f.org, ShowDecommissioned: true,
		PageSize: 100}).GetConnectors()); n != f.connectorsSeen {
		t.Errorf("%d connectors after the upgrade, %d before", n, f.connectorsSeen)
	}

	var enrollment *rpmgrv1.EnrollmentToken
	for _, e := range call(t, "enrollment tokens", ada.enr.ListEnrollmentTokens, &rpmgrv1.ListEnrollmentTokensRequest{OrgId: f.org,
		ShowInactive: true, PageSize: 100}).GetEnrollmentTokens() {
		if e.GetId() == f.enrollment {
			enrollment = e
		}
	}
	if enrollment == nil || enrollment.GetRevokeTime() != nil || !enrollment.GetEphemeral() || enrollment.GetMaxUses() != 5 || enrollment.GetLabels()["pool"] != "upgrade" {
		t.Errorf("the enrollment token after the upgrade: %v", enrollment)
	}
	if d := call(t, "the domain", ada.dom.GetDomain, &rpmgrv1.GetDomainRequest{DomainId: f.domain.GetId()}).GetDomain(); d.GetStatus() != f.domain.GetStatus() ||
		d.GetStatus() != rpmgrv1.DomainStatus_DOMAIN_STATUS_VERIFIED || d.GetFqdn() != f.domain.GetFqdn() || d.GetWildcard() != f.domain.GetWildcard() {
		t.Errorf("the domain after the upgrade: %v, before %v", d, f.domain)
	}
	if p := call(t, "the access policy", ada.pol.GetAccessPolicy, &rpmgrv1.GetAccessPolicyRequest{AccessPolicyId: f.policy.GetId()}).GetAccessPolicy(); p.GetName() != f.policy.GetName() ||
		len(p.GetRules()) != 2 || len(p.GetRules()[1].GetBasicAuth().GetUsers()) != 1 || p.GetRules()[1].GetBasicAuth().GetUsers()[0].GetName() != "staff" {
		t.Errorf("the access policy after the upgrade: %v", p)
	}
	var certs []string
	for _, c := range call(t, "certificates", ada.cert.ListCertificates, &rpmgrv1.ListCertificatesRequest{OrgId: f.org, PageSize: 100}).GetCertificates() {
		certs = append(certs, c.GetId())
	}
	slices.Sort(certs)
	slices.Sort(f.certificates)
	if !slices.Equal(certs, f.certificates) || len(certs) == 0 {
		t.Errorf("certificates after the upgrade %v, before %v", certs, f.certificates)
	}
	is := call(t, "instance settings", ada.set.GetInstanceSettings, &rpmgrv1.GetInstanceSettingsRequest{}).GetSettings()
	if !proto.Equal(is.GetSmtp(), f.settings.GetSmtp()) || is.GetAcmeEmail() != f.settings.GetAcmeEmail() {
		t.Errorf("the mail and ACME settings after the upgrade: %v %q, before %v %q", is.GetSmtp(), is.GetAcmeEmail(),
			f.settings.GetSmtp(), f.settings.GetAcmeEmail())
	}
}

// errNotYet is a condition eventually waits for.
var errNotYet = errors.New("not yet")
