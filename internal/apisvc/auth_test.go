// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/websession"
)

const pw = "correct horse battery staple"

// env serves AuthService behind the API interceptor, as the controller does.
type env struct {
	db       *store.DB
	sys      context.Context
	clock    time.Time
	acc      *accounts.Accounts
	mfa      *accounts.MFA
	sessions *websession.Sessions
	auth     *apisvc.Auth
	orgs     *apisvc.Org
	tokens   *accounts.Tokens
	log      string // the revocation log
	url      string
	ada      string       // the first user's ID
	denied   atomic.Int32 // how often a service applied a changed deny-list
	txt      fakeVerifier // the TXT proofs DomainService finds
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	e := &env{db: db, sys: sys, clock: time.Now()}
	now := func() time.Time { return e.clock }
	e.log = filepath.Join(t.TempDir(), "revocations.log")
	rl, err := revlog.Open(e.log, now)
	if err != nil {
		t.Fatal(err)
	}
	e.acc = accounts.New(db, sys, now)
	e.sessions = websession.New(websession.Options{DB: db, Sys: sys, RevLog: rl, Now: now})
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	kek, _ := secret.NewKEK(key)
	sealer, _ := secret.NewSealer(kek)
	e.mfa = &accounts.MFA{Accounts: e.acc, Sealer: sealer, RevLog: rl}
	e.tokens = &accounts.Tokens{Accounts: e.acc, RevLog: rl}
	srv, err := api.New(api.Options{DB: db, Sys: sys, Sealer: sealer, Now: now,
		Authenticator:      apisvc.Credentials{Sessions: e.sessions, Tokens: e.tokens},
		Resolver:           api.StoreResolver(db, sys),
		OperatorsMayEnroll: api.StoreOperatorsMayEnroll(db, sys),
		Origins:            func(context.Context) ([]string, error) { return []string{"https://panel.example.com"}, nil },
		ApplyStatus: func(ctx context.Context, org string, rev *rpmgrv1.Revision) (*rpmgrv1.ApplyStatus, error) {
			return apisvc.ApplyStatusOf(ctx, db.ReadClient(), org, store.Revision{DBEpoch: rev.GetDbEpoch(), Seq: rev.GetSeq()}, now())
		}})
	if err != nil {
		t.Fatal(err)
	}
	revocations := &apisvc.Revocations{Sys: sys, RevLog: rl, Denied: func() { e.denied.Add(1) }}
	mux := http.NewServeMux()
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_auth_proto.Services().ByName("AuthService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			e.auth = apisvc.NewAuth(e.mfa, e.sessions, now)
			e.auth.PublicURL = "https://panel.example.com"
			return rpmgrv1connect.NewAuthServiceHandler(e.auth, o...)
		}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_org_proto.Services().ByName("OrgService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			e.orgs = &apisvc.Org{Members: &accounts.Members{Accounts: e.acc, RevLog: rl}, API: srv,
				PublicURL: "https://panel.example.com", Now: now}
			return rpmgrv1connect.NewOrgServiceHandler(e.orgs, o...)
		}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_gateway_proto.Services().ByName("GatewayService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewGatewayServiceHandler(&apisvc.Gateways{DB: db, API: srv, Revocations: revocations, Now: now}, o...)
		}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_connector_proto.Services().ByName("ConnectorService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewConnectorServiceHandler(&apisvc.Connectors{DB: db, API: srv, Revocations: revocations, Now: now}, o...)
		}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_domain_proto.Services().ByName("DomainService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewDomainServiceHandler(&apisvc.Domains{DB: db, API: srv, Sys: sys, Now: now, TXT: &e.txt}, o...)
		}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_status_proto.Services().ByName("StatusService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewStatusServiceHandler(&apisvc.Status{DB: db, Sys: sys, Now: now, Every: 20 * time.Millisecond}, o...)
		}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_route_proto.Services().ByName("RouteService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewRouteServiceHandler(&apisvc.Routes{DB: db, API: srv, Sys: sys, Now: now}, o...)
		}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_policy_proto.Services().ByName("PolicyService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewPolicyServiceHandler(&apisvc.Policies{DB: db, API: srv, Sys: sys}, o...)
		}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_enrollment_proto.Services().ByName("EnrollmentService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewEnrollmentServiceHandler(&apisvc.Enrollment{DB: db, API: srv, Now: now,
				PublicURL: "https://panel.example.com/", RootPin: "sha256:3q2+7w=="}, o...)
		}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_token_proto.Services().ByName("TokenService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewTokenServiceHandler(&apisvc.Token{Tokens: e.tokens, API: srv}, o...)
		}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Mount(mux, rpmgrv1.File_rpmgr_v1_user_proto.Services().ByName("UserService"),
		func(o ...connect.HandlerOption) (string, http.Handler) {
			return rpmgrv1connect.NewUserServiceHandler(&apisvc.User{MFA: e.mfa, Sessions: e.sessions, Issuer: "rpmgr test", API: srv,
				PublicURL: "https://panel.example.com", Backoff: e.auth.Backoff}, o...)
		}); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)
	e.url = hs.URL
	link, _ := e.acc.FirstUserLink("local-cli")
	u, err := e.acc.CompleteReset(context.Background(), link, pw, "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	e.ada = u.ID
	return e
}

// browser is a client with one session cookie, sent by hand: the test server speaks plain HTTP,
// over which a cookie jar would not send a Secure cookie.
type browser struct {
	cookie string
	bearer string // an API token instead of the cookie
	auth   rpmgrv1connect.AuthServiceClient
	user   rpmgrv1connect.UserServiceClient
	org    rpmgrv1connect.OrgServiceClient
	token  rpmgrv1connect.TokenServiceClient
	gw     rpmgrv1connect.GatewayServiceClient
	enr    rpmgrv1connect.EnrollmentServiceClient
	con    rpmgrv1connect.ConnectorServiceClient
	dom    rpmgrv1connect.DomainServiceClient
	rt     rpmgrv1connect.RouteServiceClient
	st     rpmgrv1connect.StatusServiceClient
	pol    rpmgrv1connect.PolicyServiceClient
}

func (e *env) browser() *browser {
	b := &browser{}
	b.auth = rpmgrv1connect.NewAuthServiceClient(&http.Client{Transport: b}, e.url)
	b.user = rpmgrv1connect.NewUserServiceClient(&http.Client{Transport: b}, e.url)
	b.org = rpmgrv1connect.NewOrgServiceClient(&http.Client{Transport: b}, e.url)
	b.token = rpmgrv1connect.NewTokenServiceClient(&http.Client{Transport: b}, e.url)
	b.gw = rpmgrv1connect.NewGatewayServiceClient(&http.Client{Transport: b}, e.url)
	b.enr = rpmgrv1connect.NewEnrollmentServiceClient(&http.Client{Transport: b}, e.url)
	b.con = rpmgrv1connect.NewConnectorServiceClient(&http.Client{Transport: b}, e.url)
	b.dom = rpmgrv1connect.NewDomainServiceClient(&http.Client{Transport: b}, e.url)
	b.rt = rpmgrv1connect.NewRouteServiceClient(&http.Client{Transport: b}, e.url)
	b.st = rpmgrv1connect.NewStatusServiceClient(&http.Client{Transport: b}, e.url)
	b.pol = rpmgrv1connect.NewPolicyServiceClient(&http.Client{Transport: b}, e.url)
	return b
}

// RoundTrip sends the cookie and keeps the one the server sets.
func (b *browser) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.cookie != "" {
		r.Header.Set("Cookie", websession.CookieName+"="+b.cookie)
	}
	if b.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+b.bearer)
	}
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	for _, c := range resp.Cookies() {
		if c.Name == websession.CookieName {
			b.cookie = c.Value
			if c.MaxAge < 0 {
				b.cookie = ""
			}
		}
	}
	return resp, nil
}

func (b *browser) login(email, password string) error {
	_, err := b.auth.Login(context.Background(), connect.NewRequest(&rpmgrv1.LoginRequest{Email: email, Password: password}))
	return err
}

func (b *browser) session() (*rpmgrv1.GetSessionResponse, error) {
	resp, err := b.auth.GetSession(context.Background(), connect.NewRequest(&rpmgrv1.GetSessionRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func code(err error) connect.Code {
	if err == nil {
		return 0
	}
	return connect.CodeOf(err)
}

func retryAfter(err error) time.Duration {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return 0
	}
	for _, d := range cerr.Details() {
		if v, derr := d.Value(); derr == nil {
			if ri, ok := v.(*errdetails.RetryInfo); ok {
				return ri.GetRetryDelay().AsDuration()
			}
		}
	}
	return 0
}

// TestAuth_Sessions: a login sets the session cookie and the session describes the user; a second
// login with the cookie replaces its session; the user lists sessions, revokes another one, and
// logging out ends the current one and clears the cookie; a password reset ends every session.
func TestAuth_Sessions(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	if _, err := b.session(); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("no session: %v", err)
	}
	if err := b.login("Ada@Example.com", pw); err != nil || !strings.HasPrefix(b.cookie, "rpmgr_ses_") {
		t.Fatalf("login: %v, cookie %q", err, b.cookie)
	}
	s, err := b.session()
	if err != nil || s.GetUserId() != e.ada || s.GetEmail() != "ada@example.com" || !s.GetInstanceAdmin() ||
		len(s.GetMemberships()) != 1 || s.GetMemberships()[0].GetRole() != "owner" || !s.GetSession().GetCurrent() {
		t.Fatalf("the session: %v %v", s, err)
	}
	first := b.cookie
	if err := b.login("ada@example.com", pw); err != nil || b.cookie == first {
		t.Fatalf("a second login: %v", err)
	}
	if _, err := e.sessions.Lookup(first); !errors.Is(err, websession.ErrNoSession) {
		t.Fatal("the replaced session still works")
	}
	other := e.browser()
	if err := other.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	list, err := b.auth.ListSessions(context.Background(), connect.NewRequest(&rpmgrv1.ListSessionsRequest{}))
	if err != nil || len(list.Msg.GetSessions()) != 2 {
		t.Fatalf("two sessions: %v %v", list, err)
	}
	var otherID string
	for _, s := range list.Msg.GetSessions() {
		if !s.GetCurrent() {
			otherID = s.GetId()
		}
	}
	if _, err := b.auth.RevokeSession(context.Background(), connect.NewRequest(&rpmgrv1.RevokeSessionRequest{SessionId: otherID})); err != nil {
		t.Fatal(err)
	}
	if _, err := other.session(); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("the revoked browser: %v", err)
	}
	if _, err := b.auth.RevokeSession(context.Background(), connect.NewRequest(&rpmgrv1.RevokeSessionRequest{SessionId: "ses_unknown"})); code(err) != connect.CodeNotFound {
		t.Fatalf("an unknown session: %v", err)
	}
	if _, err := b.auth.Logout(context.Background(), connect.NewRequest(&rpmgrv1.LogoutRequest{})); err != nil || b.cookie != "" {
		t.Fatalf("logout: %v, cookie %q", err, b.cookie)
	}

	if err := b.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	link, _ := e.acc.ResetLink(e.ada, "local-cli")
	if _, err := e.browser().auth.CompletePasswordReset(context.Background(), connect.NewRequest(&rpmgrv1.CompletePasswordResetRequest{
		Token: link, NewPassword: "an entirely new passphrase"})); err != nil {
		t.Fatal(err)
	}
	if _, err := b.session(); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a session after a password reset: %v", err)
	}
}

// TestAuth_Limits: a wrong password and an unknown address are the same error; after five failures
// in a row an account waits 1 s, then 2 s, even for the right password, and a success forgets
// that; an address gets 20 attempts at once, then one every 6 s.
func TestAuth_Limits(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	wrong := b.login("ada@example.com", "wrong password")
	unknown := b.login("eve@example.com", pw)
	if code(wrong) != connect.CodeUnauthenticated || code(unknown) != connect.CodeUnauthenticated || wrong.Error() != unknown.Error() {
		t.Fatalf("%v / %v", wrong, unknown)
	}
	for range 4 {
		_ = b.login("ada@example.com", "wrong password")
	}
	err := b.login("ada@example.com", pw)
	if code(err) != connect.CodeResourceExhausted || retryAfter(err) != time.Second {
		t.Fatalf("after five failures: %v (%v)", err, retryAfter(err))
	}
	e.clock = e.clock.Add(time.Second)
	_ = b.login("ada@example.com", "wrong password")
	if err := b.login("ada@example.com", pw); retryAfter(err) != 2*time.Second {
		t.Fatalf("after six failures: %v", err)
	}
	e.clock = e.clock.Add(2 * time.Second)
	if err := b.login("ada@example.com", pw); err != nil {
		t.Fatalf("the right password after the wait: %v", err)
	}
	if err := b.login("ada@example.com", "wrong password"); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a failure after a success: %v", err)
	}

	// 11 attempts so far from this address within 3 s; 9 more fill the burst of 20, refilled by
	// about one meanwhile.
	for i := 0; ; i++ {
		err := b.login(fmt.Sprintf("u%d@example.com", i), pw)
		if code(err) == connect.CodeResourceExhausted {
			if i < 9 || retryAfter(err) != apisvc.IPEvery {
				t.Fatalf("limited after %d more attempts: %v", i, err)
			}
			break
		}
		if code(err) != connect.CodeUnauthenticated || i > 10 {
			t.Fatalf("attempt %d: %v", 12+i, err)
		}
	}
	e.clock = e.clock.Add(apisvc.IPEvery)
	if err := b.login("z@example.com", pw); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("after a refill: %v", err)
	}
}

// TestAuth_CompletePasswordReset: the errors of a reset reach the client with the codes of
// docs/07-api.md: input that is not valid and unusable links are INVALID_ARGUMENT, a first-user
// link once a user exists FAILED_PRECONDITION.
func TestAuth_CompletePasswordReset(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	acc := accounts.New(db, sys, nil)
	rl, err := revlog.Open(filepath.Join(t.TempDir(), "revocations.log"), nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := apisvc.NewAuth(&accounts.MFA{Accounts: acc}, websession.New(websession.Options{DB: db, Sys: sys, RevLog: rl}), nil)
	first, _ := acc.FirstUserLink("local-cli")
	spare, _ := acc.FirstUserLink("local-cli")
	call := func(tok, pw, email, name string) connect.Code {
		_, err := auth.CompletePasswordReset(context.Background(), connect.NewRequest(&rpmgrv1.CompletePasswordResetRequest{
			Token: tok, NewPassword: pw, Email: email, DisplayName: name}))
		return code(err)
	}
	for name, c := range map[string][4]string{
		"bad e-mail":       {first, pw, "nobody", "Ada"},
		"no display name":  {first, pw, "ada@example.com", ""},
		"short password":   {first, "short", "ada@example.com", "Ada"},
		"not a link token": {"rpmgr_prs_x", pw, "ada@example.com", "Ada"},
	} {
		if c := call(c[0], c[1], c[2], c[3]); c != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, c)
		}
	}
	if c := call(first, pw, "ada@example.com", "Ada"); c != 0 {
		t.Fatalf("the first user: %v", c)
	}
	if c := call(spare, pw, "eve@example.com", "Eve"); c != connect.CodeFailedPrecondition {
		t.Errorf("a spare first-user link: %v", c)
	}
}
