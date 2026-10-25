// SPDX-License-Identifier: Apache-2.0

//go:build webe2e

package webe2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"image/png"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/totp"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// screensPassword is the password of every user the screenshots show; the spec gets it from
// SCREENS_PASSWORD. A phrase, so that no secret scanner takes it for a key.
const screensPassword = "correct horse battery staple"

// screensMaintenancePage is the default group's own maintenance page.
const screensMaintenancePage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Back soon</title>
<style>body{font-family:system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#0f172a;color:#e2e8f0}
main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:2rem;margin:0 0 1rem}p{color:#94a3b8}</style></head>
<body><main><h1>Example Lab is back soon</h1><p>{{message}}</p><p>{{hostname}} · {{status}} · {{request_id}}</p></main></body></html>`

// TestScreens takes the screenshots of the user guide (docs/guide/images/README.md): it runs an
// all-in-one with two more connectors in this process, seeds it through the public API with made-up
// data (example.com names, documentation addresses of RFC 5737), and runs web/screens in the
// Playwright image, which writes one PNG per page into docs/guide/images/web. It runs only when
// SCREENS is set (all, or a comma-separated list of screenshot names), so the browser tests of CI
// never take screenshots; .github/scripts/screenshots.sh runs it.
func TestScreens(t *testing.T) {
	only := os.Getenv("SCREENS")
	if only == "" {
		t.Skip("SCREENS is not set; run .github/scripts/screenshots.sh")
	}
	image := os.Getenv("PLAYWRIGHT_IMAGE")
	if image == "" {
		t.Fatal("PLAYWRIGHT_IMAGE is not set; run .github/scripts/screenshots.sh")
	}
	web, err := filepath.Abs("../../web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("../../internal/webui/ui/app/index.html"); err != nil {
		t.Fatalf("the UI is not built into internal/webui (npm run build in web/): %v", err)
	}
	out, err := filepath.Abs("../../docs/guide/images/web")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(out, 0o750); err != nil {
		t.Fatal(err)
	}

	// The sidebar shows the version the controller runs, which a test binary has not linked in.
	version.Version = "0.1.0"
	dir := t.TempDir()
	port := screensPort(t)
	public := "https://localhost:" + strconv.Itoa(port)
	certFile, keyFile := filepath.Join(dir, "ui.crt"), filepath.Join(dir, "ui.key")
	spki := uiCertificate(t, certFile, keyFile)
	state := filepath.Join(dir, "lib")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	// The built-in connector "local" may reach two addresses of the made-up home network.
	policyFile := writePolicy(t, dir, "local", "192.0.2.1/32", "192.0.2.53/32")
	boot := filepath.Join(dir, "all-in-one.yaml")
	if err := os.WriteFile(boot, fmt.Appendf(nil, `version: 1
public_url: %s
listen: {tcp: ":%d", udp: ":%d", http: "127.0.0.1:%d", admin: "127.0.0.1:%d"}
database: {dsn: %s}
kek: {source: file, path: %s}
tls: {cert_file: %s, key_file: %s}
state_dir: %s
policy_file: %s
`, public, port, port, freePort(t), freePort(t), filepath.Join(state, "controller.db"), filepath.Join(dir, "kek"), certFile, keyFile, state,
		policyFile), 0o600); err != nil {
		t.Fatal(err)
	}
	none := func(string) string { return "" }
	quiet := slog.New(slog.DiscardHandler)
	r, err := allinone.Init(context.Background(), controller.InitOptions{ConfigPath: boot, Getenv: none})
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.AllInOne
	if err := config.Load(boot, &cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	listening, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- allinone.Run(ctx, allinone.RunOptions{Config: cfg, Version: "0.1.0", Getenv: none, Logger: quiet,
			DrainPeriod: 200 * time.Millisecond, Listening: func() { close(listening) }})
	}()
	select {
	case <-listening:
	case err := <-done:
		cancel()
		t.Fatalf("Run: %v", err)
	}
	defer func() { cancel(); <-done }()

	// The browser's certificate is the one the API clients trust: its own trust anchor.
	pool := x509.NewCertPool()
	pemCert, err := os.ReadFile(certFile)
	if err != nil || !pool.AppendCertsFromPEM(pemCert) {
		t.Fatalf("the UI certificate: %v", err)
	}
	s := &seeder{t: t, ctx: ctx, public: public, pool: pool, pin: r.RootPin, dir: dir, quiet: quiet}
	s.seed(r.FirstUserLink)

	cmd := exec.Command("docker", "run", "--rm", "--network", "host", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-e", "HOME=/tmp", "-e", "CI=1", "-e", "RPMGR_URL="+public, "-e", "RPMGR_SPKI="+spki,
		"-e", "SCREENS="+only, "-e", "SCREENS_OUT=/screens-out", "-e", "SCREENS_PASSWORD="+screensPassword,
		"-v", web+":/web", "-v", out+":/screens-out", "-w", "/web", image, "npx", "--no-install", "playwright", "test", "-c", "screens.config.ts")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("the screenshots failed: %v", err)
	}
	recompress(t, out)
}

// screensPort is the all-in-one's port: 8443, which the install command in the screenshots shows,
// if it is free for TCP and UDP, else any free port.
func screensPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		return freePort(t)
	}
	defer func() { _ = ln.Close() }()
	pc, err := net.ListenPacket("udp", ":8443")
	if err != nil {
		return freePort(t)
	}
	_ = pc.Close()
	return 8443
}

// seeder fills the instance with the made-up organisation the screenshots show.
type seeder struct {
	t      *testing.T
	ctx    context.Context
	public string
	pool   *x509.CertPool
	pin    string
	dir    string
	quiet  *slog.Logger
}

// clients are the API's services for one caller, whose session cookie the jar keeps.
type clients struct {
	auth  rpmgrv1connect.AuthServiceClient
	org   rpmgrv1connect.OrgServiceClient
	user  rpmgrv1connect.UserServiceClient
	gw    rpmgrv1connect.GatewayServiceClient
	dom   rpmgrv1connect.DomainServiceClient
	cert  rpmgrv1connect.CertificateServiceClient
	pol   rpmgrv1connect.PolicyServiceClient
	route rpmgrv1connect.RouteServiceClient
	enr   rpmgrv1connect.EnrollmentServiceClient
	con   rpmgrv1connect.ConnectorServiceClient
	set   rpmgrv1connect.SettingsServiceClient
	tok   rpmgrv1connect.TokenServiceClient
}

func (s *seeder) httpClient() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: time.Minute,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.pool, MinVersion: tls.VersionTLS13}}}
}

func (s *seeder) clients() *clients {
	hc, base := s.httpClient(), s.public
	return &clients{
		auth: rpmgrv1connect.NewAuthServiceClient(hc, base), org: rpmgrv1connect.NewOrgServiceClient(hc, base),
		user: rpmgrv1connect.NewUserServiceClient(hc, base), gw: rpmgrv1connect.NewGatewayServiceClient(hc, base),
		dom: rpmgrv1connect.NewDomainServiceClient(hc, base), cert: rpmgrv1connect.NewCertificateServiceClient(hc, base),
		pol: rpmgrv1connect.NewPolicyServiceClient(hc, base), route: rpmgrv1connect.NewRouteServiceClient(hc, base),
		enr: rpmgrv1connect.NewEnrollmentServiceClient(hc, base), con: rpmgrv1connect.NewConnectorServiceClient(hc, base),
		set: rpmgrv1connect.NewSettingsServiceClient(hc, base), tok: rpmgrv1connect.NewTokenServiceClient(hc, base),
	}
}

// call runs one API call and stops the test if it fails.
func call[Req, Res any](s *seeder, what string, f func(context.Context, *connect.Request[Req]) (*connect.Response[Res], error), req *Req) *Res {
	s.t.Helper()
	res, err := f(s.ctx, connect.NewRequest(req))
	if err != nil {
		s.t.Fatalf("%s: %v", what, err)
	}
	return res.Msg
}

func mask(paths ...string) *fieldmaskpb.FieldMask { return &fieldmaskpb.FieldMask{Paths: paths} }

func days(n int) *durationpb.Duration { return durationpb.New(time.Duration(n) * 24 * time.Hour) }

func fragment(s *seeder, link string) string {
	u, err := url.Parse(link)
	if err != nil || u.Fragment == "" {
		s.t.Fatalf("a one-time link without its token: %q", link)
	}
	return u.Fragment
}

func (s *seeder) seed(firstUserLink string) {
	t := s.t
	ada := s.clients()
	call(s, "the first user", ada.auth.CompletePasswordReset, &rpmgrv1.CompletePasswordResetRequest{Token: fragment(s, firstUserLink),
		NewPassword: screensPassword, Email: "ada@example.com", DisplayName: "Ada Lovelace"})
	call(s, "sign-in", ada.auth.Login, &rpmgrv1.LoginRequest{Email: "ada@example.com", Password: screensPassword})
	call(s, "step-up", ada.auth.StepUp, &rpmgrv1.StepUpRequest{Password: screensPassword})
	org := call(s, "session", ada.auth.GetSession, &rpmgrv1.GetSessionRequest{}).GetMemberships()[0].GetOrgId()
	call(s, "org name", ada.org.UpdateOrg, &rpmgrv1.UpdateOrgRequest{OrgId: org, Name: "Example Lab"})

	// Gateways: the all-in-one's group with its public hostname, and a second group whose gateway
	// has not enrolled yet.
	def := call(s, "groups", ada.gw.ListGatewayGroups, &rpmgrv1.ListGatewayGroupsRequest{OrgId: org}).GetGatewayGroups()[0]
	def.Region, def.PublicHostnames = "home", []string{"edge.example.com"}
	call(s, "group default", ada.gw.UpdateGatewayGroup, &rpmgrv1.UpdateGatewayGroupRequest{GatewayGroup: def,
		UpdateMask: mask("region", "public_hostnames"), Etag: def.GetEtag()})
	eu := call(s, "group eu-west", ada.gw.CreateGatewayGroup, &rpmgrv1.CreateGatewayGroupRequest{OrgId: org, RequestId: uuid.NewString(),
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "eu-west", Region: "eu-west", PublicHostnames: []string{"eu.example.net"},
			TrustedProxyCidrs: []string{"198.51.100.0/24"}}}).GetGatewayGroup()
	call(s, "gateway gw-eu-1", ada.gw.CreateGateway, &rpmgrv1.CreateGatewayRequest{OrgId: org, RequestId: uuid.NewString(),
		Gateway: &rpmgrv1.Gateway{GatewayGroupId: eu.GetId(), Name: "gw-eu-1", TunnelEndpoints: []string{"203.0.113.20:443"}, Enabled: true}})
	for _, p := range []rpmgrv1.PortProtocol{rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP, rpmgrv1.PortProtocol_PORT_PROTOCOL_UDP} {
		call(s, "port pool", ada.gw.CreatePortPool, &rpmgrv1.CreatePortPoolRequest{OrgId: org, RequestId: uuid.NewString(),
			PortPool: &rpmgrv1.PortPool{GatewayGroupId: def.GetId(), Protocol: p, PortFrom: 30000, PortTo: 30099}})
	}
	call(s, "maintenance page", ada.gw.SetGatewayPage, &rpmgrv1.SetGatewayPageRequest{GatewayPage: &rpmgrv1.GatewayPage{
		GatewayGroupId: def.GetId(), Kind: rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE, Html: screensMaintenancePage}})
	call(s, "port quota", ada.gw.SetPortQuota, &rpmgrv1.SetPortQuotaRequest{OrgId: org, GatewayGroupId: def.GetId(),
		Protocol: rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP, MaxPorts: 20})

	// Domains: example.com, trusted by the Instance Admin, and example.net, waiting for its TXT
	// record.
	com := call(s, "domain example.com", ada.dom.CreateDomain, &rpmgrv1.CreateDomainRequest{OrgId: org, RequestId: uuid.NewString(),
		Domain: &rpmgrv1.Domain{Fqdn: "example.com", Wildcard: true, Method: rpmgrv1.DomainMethod_DOMAIN_METHOD_DNS_TXT}}).GetDomain()
	call(s, "trust example.com", ada.dom.MarkDomainTrusted, &rpmgrv1.MarkDomainTrustedRequest{DomainId: com.GetId()})
	call(s, "domain example.net", ada.dom.CreateDomain, &rpmgrv1.CreateDomainRequest{OrgId: org, RequestId: uuid.NewString(),
		Domain: &rpmgrv1.Domain{Fqdn: "example.net", Method: rpmgrv1.DomainMethod_DOMAIN_METHOD_DNS_TXT}})

	// Certificates: the routes' certificate for example.com and its names, and the CA bundle of the
	// home network's internal CA.
	chain, key := exampleCertificate(t, "Example Issuing CA", "example.com", "*.example.com")
	certID := call(s, "certificate", ada.cert.UploadCertificate, &rpmgrv1.UploadCertificateRequest{OrgId: org, RequestId: uuid.NewString(),
		ChainPem: chain, PrivateKeyPem: key}).GetCertificate().GetId()
	homeCA, _ := exampleCertificate(t, "Example Home Root CA", "")
	bundle := call(s, "CA bundle", ada.cert.CreateCABundle, &rpmgrv1.CreateCABundleRequest{OrgId: org, RequestId: uuid.NewString(),
		CaBundle: &rpmgrv1.CABundle{Name: "home-ca", Pem: homeCA}}).GetCaBundle()

	office := call(s, "policy office", ada.pol.CreateAccessPolicy, &rpmgrv1.CreateAccessPolicyRequest{OrgId: org, RequestId: uuid.NewString(),
		AccessPolicy: &rpmgrv1.AccessPolicy{Name: "office", Description: "Only the office network", Rules: []*rpmgrv1.AccessRule{
			{Rule: &rpmgrv1.AccessRule_IpAllow{IpAllow: &rpmgrv1.IPRuleParams{Cidrs: []string{"198.51.100.0/24", "2001:db8:100::/48"}}}},
			{Rule: &rpmgrv1.AccessRule_IpDeny{IpDeny: &rpmgrv1.IPRuleParams{Cidrs: []string{"198.51.100.66/32"}}}},
			{Rule: &rpmgrv1.AccessRule_RateLimit{RateLimit: &rpmgrv1.RateLimitRule{PerSecond: 20, Burst: 50}}},
		}}}).GetAccessPolicy()
	call(s, "policy staff-login", ada.pol.CreateAccessPolicy, &rpmgrv1.CreateAccessPolicyRequest{OrgId: org, RequestId: uuid.NewString(),
		AccessPolicy: &rpmgrv1.AccessPolicy{Name: "staff-login", Description: "A password for the staff", Rules: []*rpmgrv1.AccessRule{
			{Rule: &rpmgrv1.AccessRule_BasicAuth{BasicAuth: &rpmgrv1.BasicAuthRule{Users: []*rpmgrv1.BasicAuthCredential{
				{Name: "staff", Password: screensPassword}, {Name: "guest", Password: screensPassword}}}}},
		}}})
	call(s, "policy cdn-only", ada.pol.CreateAccessPolicy, &rpmgrv1.CreateAccessPolicyRequest{OrgId: org, RequestId: uuid.NewString(),
		AccessPolicy: &rpmgrv1.AccessPolicy{Name: "cdn-only", Description: "Requests through the CDN only", Rules: []*rpmgrv1.AccessRule{
			{Rule: &rpmgrv1.AccessRule_RequireHeader{RequireHeader: &rpmgrv1.RequireHeaderRule{Name: "X-Origin-Token",
				Values: []string{"cdn-origin-token-0123456789abcdefghijkl"}}}},
		}}})

	// Connectors: two hosts of the home network, enrolled and running beside the all-in-one, and
	// a token that may enroll a few CI runners.
	nas := s.connector(ada, org, "nas-01", map[string]string{"site": "home", "role": "storage"}, "192.0.2.10/32")
	db := s.connector(ada, org, "db-host-1", map[string]string{"site": "home", "role": "database"}, "192.0.2.20:3000", "192.0.2.20:5432")
	call(s, "enrollment token", ada.enr.CreateEnrollmentToken, &rpmgrv1.CreateEnrollmentTokenRequest{OrgId: org, RequestId: uuid.NewString(),
		Labels: map[string]string{"pool": "ci"}, Ephemeral: true, MaxUses: ptr(int32(5)), Ttl: days(7)})
	local := ""
	for _, c := range call(s, "connectors", ada.con.ListConnectors, &rpmgrv1.ListConnectorsRequest{OrgId: org}).GetConnectors() {
		if c.GetBuiltIn() {
			local = c.GetId()
		}
	}

	s.routes(ada, org, def.GetId(), certID, bundle.GetId(), office.GetId(), map[string]string{"nas-01": nas, "db-host-1": db, "local": local})

	// Members: an Admin with an authenticator, an Operator and a Viewer.
	s.member(ada, org, "grace@example.com", "Grace Hopper", "admin", true)
	s.member(ada, org, "alan@example.com", "Alan Turing", "operator", false)
	s.member(ada, org, "margaret@example.com", "Margaret Hamilton", "viewer", false)
	call(s, "API token", ada.tok.CreateAPIToken, &rpmgrv1.CreateAPITokenRequest{OrgId: org, RequestId: uuid.NewString(),
		Name: "backup-script", Scopes: []string{"org.read", "audit.read"}, Ttl: days(30)})

	// Settings: the default gateway group, and a mail relay, set last so that nothing is mailed.
	orgSet := call(s, "org settings", ada.set.GetOrgSettings, &rpmgrv1.GetOrgSettingsRequest{OrgId: org})
	orgSet.GetSettings().DefaultGatewayGroupId = def.GetId()
	call(s, "org settings", ada.set.UpdateOrgSettings, &rpmgrv1.UpdateOrgSettingsRequest{OrgId: org, Settings: orgSet.GetSettings(),
		UpdateMask: mask("default_gateway_group_id"), Etag: orgSet.GetEtag()})
	is := call(s, "instance settings", ada.set.GetInstanceSettings, &rpmgrv1.GetInstanceSettingsRequest{})
	is.GetSettings().Smtp = &rpmgrv1.SmtpSettings{Server: "smtp.example.com:587", From: "rpmgr@example.com", Username: "rpmgr",
		Security: rpmgrv1.SmtpSecurity_SMTP_SECURITY_STARTTLS}
	is.GetSettings().AcmeEmail = ptr("admin@example.com")
	call(s, "instance settings", ada.set.UpdateInstanceSettings, &rpmgrv1.UpdateInstanceSettingsRequest{Settings: is.GetSettings(),
		UpdateMask: mask("smtp", "acme_email"), Etag: is.GetEtag()})

	s.waitForRoutes(ada, org)
	call(s, "sign-out", ada.auth.Logout, &rpmgrv1.LogoutRequest{})
}

func ptr[T any](v T) *T { return &v }

// connector enrolls a connector of a host with its labels, as the install command would, and runs
// it with a local policy that allows targets; it returns its ID once its control session is up.
func (s *seeder) connector(c *clients, org, host string, labels map[string]string, allow ...string) string {
	t := s.t
	tok := call(s, "enrollment token for "+host, c.enr.CreateEnrollmentToken, &rpmgrv1.CreateEnrollmentTokenRequest{OrgId: org,
		RequestId: uuid.NewString(), Labels: labels, Ttl: durationpb.New(time.Hour)})
	dir := filepath.Join(s.dir, host)
	ident := filepath.Join(dir, "identity")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	id, err := agent.Enroll(s.ctx, agent.EnrollOptions{Controller: s.public, Pin: s.pin, Token: tok.GetToken(), IdentityDir: ident,
		HTTPClient: s.httpClient(), Host: &agentv1.HostFacts{Hostname: host, Os: "linux", Arch: "amd64"}, Version: "0.1.0"})
	if err != nil {
		t.Fatalf("enroll %s: %v", host, err)
	}
	boot := filepath.Join(dir, "connector.yaml")
	if err := os.WriteFile(boot, fmt.Appendf(nil, `version: 1
controller: {endpoints: [%s]}
identity_dir: %s
state_dir: %s
policy_file: %s
listen: {admin: "127.0.0.1:%d"}
`, s.public, ident, dir, writePolicy(t, dir, host, allow...), freePort(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	var cfg config.Connector
	if err := config.Load(boot, &cfg); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- connector.Run(s.ctx, connector.RunOptions{Config: cfg, Version: "0.1.0", Getenv: func(string) string { return "" }, Logger: s.quiet})
	}()
	t.Cleanup(func() { <-done })
	s.waitFor("connector "+host+" to connect", func() bool {
		got, err := c.con.GetConnector(s.ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: id.AgentID}))
		return err == nil && got.Msg.GetConnector().GetSession().GetConnected()
	})
	return id.AgentID
}

// writePolicy writes a connector's local policy, which allows the targets given.
func writePolicy(t *testing.T, dir, name string, allow ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("version: 1\nallow_targets:\n")
	for _, a := range allow {
		fmt.Fprintf(&b, "  - %q\n", a)
	}
	path := filepath.Join(dir, name+"-policy.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// routes creates the org's routes, one or two of each type, with their targets.
func (s *seeder) routes(c *clients, org, group, certID, bundleID, officeID string, con map[string]string) {
	http := func(hosts ...string) *rpmgrv1.Route_Http {
		return &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{Hostnames: hosts, TlsMode: rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE, CertificateId: certID,
			Port80: rpmgrv1.Port80Mode_PORT80_MODE_REDIRECT}}
	}
	type target struct {
		connector, host string
		port            uint32
		upstream        rpmgrv1.UpstreamProtocol
		tls             *rpmgrv1.UpstreamTLSSettings
		proxy           rpmgrv1.ProxyProtocol
		priority        uint32
	}
	httpTarget := func(connector, host string, port uint32) target {
		return target{connector: connector, host: host, port: port, upstream: rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTP}
	}
	tcpTarget := func(connector, host string, port uint32) target {
		return target{connector: connector, host: host, port: port, upstream: rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_TCP,
			proxy: rpmgrv1.ProxyProtocol_PROXY_PROTOCOL_NONE}
	}
	maintenance := http("status.example.com")
	maintenance.Http.Maintenance, maintenance.Http.MaintenanceMessage = true, "Planned maintenance until 18:00 UTC."
	cloud := httpTarget("nas-01", "192.0.2.10", 443)
	cloud.upstream = rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS
	cloud.tls = &rpmgrv1.UpstreamTLSSettings{ServerName: "nas-01.home.example.com", CaBundleId: bundleID,
		Verification: rpmgrv1.UpstreamVerification_UPSTREAM_VERIFICATION_VERIFIED}
	router := httpTarget("local", "192.0.2.1", 443)
	router.upstream = rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS
	router.tls = &rpmgrv1.UpstreamTLSSettings{Verification: rpmgrv1.UpstreamVerification_UPSTREAM_VERIFICATION_UNVERIFIED}
	failover := httpTarget("db-host-1", "192.0.2.40", 8080) // the local policy of db-host-1 does not allow it
	failover.priority = 1
	git := tcpTarget("nas-01", "192.0.2.10", 2443)
	git.proxy = rpmgrv1.ProxyProtocol_PROXY_PROTOCOL_V2
	for _, r := range []struct {
		route   *rpmgrv1.Route
		targets []target
	}{
		// The wiki's health check finds its documentation address unreachable within seconds.
		{&rpmgrv1.Route{Name: "wiki", Description: "The lab's wiki", Spec: http("wiki.example.com"), HealthCheck: &rpmgrv1.HealthCheck{
			Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, HttpPath: "/healthz", IntervalSeconds: 5, UnhealthyThreshold: 1}},
			[]target{httpTarget("nas-01", "192.0.2.10", 8080), failover}},
		{&rpmgrv1.Route{Name: "grafana", Description: "Dashboards", Spec: http("grafana.example.com"), PolicyIds: []string{officeID}},
			[]target{httpTarget("db-host-1", "192.0.2.20", 3000)}},
		{&rpmgrv1.Route{Name: "cloud", Description: "File sync", Spec: http("cloud.example.com")}, []target{cloud}},
		{&rpmgrv1.Route{Name: "router", Description: "The router's admin page", Spec: http("router.example.com")}, []target{router}},
		{&rpmgrv1.Route{Name: "status", Description: "Status page", Spec: maintenance}, []target{httpTarget("nas-01", "192.0.2.10", 8082)}},
		{&rpmgrv1.Route{Name: "postgres", Description: "The lab's database", Spec: &rpmgrv1.Route_Tcp{Tcp: &rpmgrv1.TCPRouteSpec{}}},
			[]target{tcpTarget("db-host-1", "192.0.2.20", 5432)}},
		{&rpmgrv1.Route{Name: "dns", Description: "The home network's resolver", Spec: &rpmgrv1.Route_Udp{Udp: &rpmgrv1.UDPRouteSpec{}}},
			[]target{tcpTarget("local", "192.0.2.53", 53)}},
		{&rpmgrv1.Route{Name: "game", Description: "Game server", Spec: &rpmgrv1.Route_TcpUdp{TcpUdp: &rpmgrv1.TCPUDPRouteSpec{}}},
			[]target{tcpTarget("nas-01", "192.0.2.10", 25565)}},
		{&rpmgrv1.Route{Name: "git", Description: "Git server, TLS to the end", Spec: &rpmgrv1.Route_TlsPassthrough{
			TlsPassthrough: &rpmgrv1.TLSPassthroughRouteSpec{Hostnames: []string{"git.example.com"}}}}, []target{git}},
	} {
		r.route.GatewayGroupId, r.route.Enabled = group, true
		if _, ok := r.route.GetSpec().(*rpmgrv1.Route_Udp); ok {
			for i := range r.targets {
				r.targets[i].proxy = rpmgrv1.ProxyProtocol_PROXY_PROTOCOL_UNSPECIFIED
			}
		}
		created := call(s, "route "+r.route.GetName(), c.route.CreateRoute, &rpmgrv1.CreateRouteRequest{OrgId: org, Route: r.route,
			RequestId: uuid.NewString()}).GetRoute()
		for _, tg := range r.targets {
			call(s, "target of "+r.route.GetName(), c.route.CreateRouteTarget, &rpmgrv1.CreateRouteTargetRequest{RouteId: created.GetId(),
				RequestId: uuid.NewString(), Target: &rpmgrv1.RouteTarget{ConnectorId: con[tg.connector],
					Address:          &rpmgrv1.RouteTarget_HostPort{HostPort: &rpmgrv1.HostPort{Host: tg.host, Port: tg.port}},
					UpstreamProtocol: tg.upstream, Tls: tg.tls, ProxyProtocol: tg.proxy, Weight: 100, Priority: tg.priority, Enabled: true}})
		}
	}
}

// member invites someone with a role and accepts the invitation as them; with mfa, they set up an
// authenticator, so that signing in asks for its code.
func (s *seeder) member(c *clients, org, email, name, role string, mfa bool) {
	inv := call(s, "invite "+email, c.org.CreateInvitation, &rpmgrv1.CreateInvitationRequest{OrgId: org, Email: email, Role: role,
		RequestId: uuid.NewString()})
	m := s.clients()
	call(s, "accept "+email, m.org.AcceptInvitation, &rpmgrv1.AcceptInvitationRequest{Token: fragment(s, inv.GetUrl()), DisplayName: name,
		Password: screensPassword})
	if !mfa {
		return
	}
	call(s, "sign-in "+email, m.auth.Login, &rpmgrv1.LoginRequest{Email: email, Password: screensPassword})
	call(s, "step-up "+email, m.auth.StepUp, &rpmgrv1.StepUpRequest{Password: screensPassword})
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		call(s, "authenticator of "+email, m.user.EnrollTOTP, &rpmgrv1.EnrollTOTPRequest{}).GetSecret())
	if err != nil {
		s.t.Fatal(err)
	}
	call(s, "confirm the authenticator of "+email, m.user.ConfirmTOTP, &rpmgrv1.ConfirmTOTPRequest{Code: totp.Code(secret, totp.StepOf(time.Now()))})
	call(s, "sign-out "+email, m.auth.Logout, &rpmgrv1.LogoutRequest{})
}

// waitForRoutes waits until every route has left pending, so the pages show what the agents report.
func (s *seeder) waitForRoutes(c *clients, org string) {
	s.waitFor("the routes to leave pending", func() bool {
		res, err := c.route.ListRoutes(s.ctx, connect.NewRequest(&rpmgrv1.ListRoutesRequest{OrgId: org, PageSize: 100}))
		if err != nil {
			return false
		}
		for _, r := range res.Msg.GetRoutes() {
			if r.GetStatus().GetState() == rpmgrv1.RouteState_ROUTE_STATE_PENDING || r.GetStatus().GetState() == rpmgrv1.RouteState_ROUTE_STATE_UNSPECIFIED {
				return false
			}
		}
		return true
	})
}

func (s *seeder) waitFor(what string, ok func() bool) {
	s.t.Helper()
	for end := time.Now().Add(time.Minute); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if ok() {
			return
		}
	}
	s.t.Fatalf("timed out waiting for %s", what)
}

// exampleCertificate returns a certificate chain in PEM for the names, issued by a CA of the given
// name, and its key; without names, the CA's own certificate.
func exampleCertificate(t *testing.T, ca string, names ...string) (chain, key string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: ca, Organization: []string{"Example Lab"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	if len(names) == 0 || names[0] == "" {
		return caPEM, ""
	}
	parent, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + caPEM,
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// recompress writes each screenshot again with the best compression of image/png where that makes
// it smaller, so the repository holds no larger PNG than needed.
func recompress(t *testing.T, dir string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.png"))
	if err != nil {
		t.Fatal(err)
	}
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		img, err := png.Decode(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var b bytes.Buffer
		if err := enc.Encode(&b, img); err != nil {
			t.Fatal(err)
		}
		if b.Len() < len(raw) {
			if err := os.WriteFile(f, b.Bytes(), 0o644); err != nil { //nolint:gosec // G306: a picture of the documentation
				t.Fatal(err)
			}
		}
	}
}
