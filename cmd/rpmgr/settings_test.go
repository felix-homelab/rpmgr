// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

const edgeGroup = "gwg_01J9Z3ABCDEFGHJKMNPQRSTVWX"

// settingsAPI serves an org's and the instance's settings. The token rpmgr_pat_admin is an
// Admin's: it reads the org's settings but changes nothing, and is no Instance Admin. Changing the
// MFA requirement needs a step-up.
type settingsAPI struct {
	rpmgrv1connect.UnimplementedSettingsServiceHandler
	rpmgrv1connect.UnimplementedGatewayServiceHandler
	stepUpAPI

	mu       sync.Mutex
	org      *rpmgrv1.UpdateOrgSettingsRequest
	instance *rpmgrv1.UpdateInstanceSettingsRequest
	smtp     *rpmgrv1.SetSmtpPasswordRequest
}

func admin(h http.Header) bool { return h.Get("Authorization") == "Bearer rpmgr_pat_admin" }

func (a *settingsAPI) GetOrgSettings(context.Context, *connect.Request[rpmgrv1.GetOrgSettingsRequest]) (*connect.Response[rpmgrv1.GetOrgSettingsResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetOrgSettingsResponse{Etag: "4",
		Settings: &rpmgrv1.OrgSettings{RequireMfa: proto.Bool(false), OperatorsMayEnroll: proto.Bool(false)}}), nil
}

func (a *settingsAPI) UpdateOrgSettings(_ context.Context, req *connect.Request[rpmgrv1.UpdateOrgSettingsRequest]) (
	*connect.Response[rpmgrv1.UpdateOrgSettingsResponse], error) {
	if admin(req.Header()) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("authz: only an Owner changes the org's settings"))
	}
	if slices.Contains(req.Msg.GetUpdateMask().GetPaths(), "require_mfa") {
		a.stepUpAPI.mu.Lock()
		stepped := a.stepped
		a.stepUpAPI.mu.Unlock()
		if !stepped {
			return nil, stepUpError()
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.org = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateOrgSettingsResponse{Settings: req.Msg.GetSettings(), Etag: "5", Revision: &rpmgrv1.Revision{Seq: 7}}), nil
}

func (a *settingsAPI) GetInstanceSettings(_ context.Context, req *connect.Request[rpmgrv1.GetInstanceSettingsRequest]) (
	*connect.Response[rpmgrv1.GetInstanceSettingsResponse], error) {
	if admin(req.Header()) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("authz: for an Instance Admin"))
	}
	return connect.NewResponse(&rpmgrv1.GetInstanceSettingsResponse{Etag: "9", SmtpPasswordSet: true, Settings: &rpmgrv1.InstanceSettings{
		DefaultTransport:        rpmgrv1.TransportPolicy_TRANSPORT_POLICY_AUTO.Enum(),
		LeafCertificateLifetime: durationpb.New(7 * 24 * time.Hour), ExpiredCertificateGrace: durationpb.New(90 * time.Minute),
		PasswordHashProfile: rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_DEFAULT.Enum(), AcmeEmail: proto.String("ops@example.com"),
		Smtp: &rpmgrv1.SmtpSettings{Server: "mail.example.com:587", From: "rpmgr@example.com", Security: rpmgrv1.SmtpSecurity_SMTP_SECURITY_STARTTLS},
	}}), nil
}

func (a *settingsAPI) UpdateInstanceSettings(_ context.Context, req *connect.Request[rpmgrv1.UpdateInstanceSettingsRequest]) (
	*connect.Response[rpmgrv1.UpdateInstanceSettingsResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.instance = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateInstanceSettingsResponse{Settings: req.Msg.GetSettings(), Etag: "10", Revision: &rpmgrv1.Revision{Seq: 8}}), nil
}

func (a *settingsAPI) SetSmtpPassword(_ context.Context, req *connect.Request[rpmgrv1.SetSmtpPasswordRequest]) (*connect.Response[rpmgrv1.SetSmtpPasswordResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.smtp = req.Msg
	return connect.NewResponse(&rpmgrv1.SetSmtpPasswordResponse{}), nil
}

func (a *settingsAPI) ListGatewayGroups(context.Context, *connect.Request[rpmgrv1.ListGatewayGroupsRequest]) (*connect.Response[rpmgrv1.ListGatewayGroupsResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListGatewayGroupsResponse{GatewayGroups: []*rpmgrv1.GatewayGroup{{Id: edgeGroup, Name: "edge"}}}), nil
}

// TestSettings (docs/16-cli.md): settings are shown by the names --set takes; an update sends the
// settings named, with the etag read, resolving a gateway group's name and restoring a default
// for an empty value; the MFA requirement takes a step-up; an Admin's change and an
// Instance-Admin-only read are refused by the API; values the API's rules refuse are usage errors;
// the mail relay's password comes from a file or a prompt, never an argument.
func TestSettings(t *testing.T) {
	a := &settingsAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewSettingsServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewGatewayServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := writeCA(t, srv)
	envOf := func(token string) map[string]string {
		creds := filepath.Join(dir, token+".yaml")
		if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte(token)), CAFile: ca}); err != nil {
			t.Fatal(err)
		}
		return map[string]string{"RPMGR_CREDENTIALS": creds}
	}
	owner, adm := envOf("rpmgr_pat_good"), envOf("rpmgr_pat_admin")
	run := func(args ...string) (int, string, string) { return runWith(owner, "", args...) }
	old, oldPw := stepUpPrompt, passwordPrompt
	stepUpPrompt = func() (string, error) { return "right", nil }
	var prompted []string
	answer := "relay-password"
	passwordPrompt = func(user string, _ bool) (string, error) { prompted = append(prompted, user); return answer, nil }
	t.Cleanup(func() { stepUpPrompt, passwordPrompt = old, oldPw })

	// rows reads a settings table into its values by setting.
	rows := func(out string) map[string]string {
		m := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n")[1:] {
			if kv := regexp.MustCompile(`\s{2,}`).Split(strings.TrimSpace(line), 2); len(kv) == 2 {
				m[kv[0]] = kv[1]
			}
		}
		return m
	}
	code, out, errOut := run("get", "settings")
	if got := rows(out); code != cli.ExitOK || got["require_mfa"] != "false" || got["operators_may_enroll"] != "false" ||
		got["default_gateway_group_id"] != "-" {
		t.Fatalf("the org's settings: %d %q %q", code, out, errOut)
	}
	code, out, _ = run("get", "--instance", "settings")
	for setting, want := range map[string]string{"leaf_certificate_lifetime": "7d", "expired_certificate_grace": "1h30m0s",
		"password_hash_profile": "default", "default_transport": "auto", "update_channel": "-", "public_url_aliases": "-",
		"acme_email": "ops@example.com", "smtp.server": "mail.example.com:587", "smtp.security": "starttls", "smtp.username": "-",
		"smtp password": "set"} {
		if got := rows(out)[setting]; code != cli.ExitOK || got != want {
			t.Errorf("the instance's %s: %q, want %q (%d)", setting, got, want, code)
		}
	}
	var asJSON map[string]any
	if code, out, _ := run("get", "-o", "json", "settings"); code != cli.ExitOK || json.Unmarshal([]byte(out), &asJSON) != nil || asJSON["requireMfa"] != false {
		t.Fatalf("JSON: %d %q", code, out)
	}
	if code, _, errOut := runWith(adm, "", "get", "--instance", "settings"); code != cli.ExitError || !strings.Contains(errOut, "Instance Admin") {
		t.Errorf("an Admin reads the instance's settings: %d %q", code, errOut)
	}

	code, out, _ = run("update", "settings", "--set", "operators_may_enroll=true", "--set", "default_gateway_group_id=edge")
	if code != cli.ExitOK || len(a.stepUps) != 0 || a.org.GetEtag() != "4" || a.org.GetOrgId() != "org_1" ||
		!slices.Equal(a.org.GetUpdateMask().GetPaths(), []string{"operators_may_enroll", "default_gateway_group_id"}) ||
		!a.org.GetSettings().GetOperatorsMayEnroll() || a.org.GetSettings().GetDefaultGatewayGroupId() != edgeGroup ||
		!strings.Contains(out, "Updated the org's settings in revision 7") {
		t.Fatalf("an org update: %d %q %v", code, out, a.org)
	}
	if code, _, _ := run("update", "settings", "--force", "--set", "require_mfa=true"); code != cli.ExitOK || len(a.stepUps) != 1 ||
		!a.org.GetSettings().GetRequireMfa() || a.org.GetEtag() != "" {
		t.Fatalf("the MFA requirement: %d, %d step-ups, %v", code, len(a.stepUps), a.org)
	}
	a.org = nil
	if code, _, errOut := runWith(adm, "", "update", "settings", "--set", "operators_may_enroll=true"); code != cli.ExitError ||
		!strings.Contains(errOut, "only an Owner") || a.org != nil {
		t.Errorf("an Admin's change: %d %q", code, errOut)
	}

	code, out, _ = run("update", "settings", "--instance", "--set", "smtp.server=relay.example.com:465", "--set", "smtp.security=tls",
		"--set", "leaf_certificate_lifetime=14d", "--set", "password_hash_profile=low-memory",
		"--set", "public_url_aliases=https://a.example.com,https://b.example.com", "--set", "acme_email=")
	in := a.instance.GetSettings()
	if code != cli.ExitOK || a.instance.GetEtag() != "9" || !slices.Equal(a.instance.GetUpdateMask().GetPaths(),
		[]string{"smtp", "leaf_certificate_lifetime", "password_hash_profile", "public_url_aliases", "acme_email"}) ||
		in.GetSmtp().GetServer() != "relay.example.com:465" || in.GetSmtp().GetFrom() != "rpmgr@example.com" ||
		in.GetSmtp().GetSecurity() != rpmgrv1.SmtpSecurity_SMTP_SECURITY_TLS || in.GetLeafCertificateLifetime().AsDuration() != 14*24*time.Hour ||
		in.GetPasswordHashProfile() != rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_LOW_MEMORY || len(in.GetPublicUrlAliases()) != 2 ||
		in.AcmeEmail != nil || !strings.Contains(out, "Updated the instance's settings in revision 8") || !strings.Contains(out, "14d") {
		t.Fatalf("an instance update: %d %q %v", code, out, a.instance)
	}

	for name, args := range map[string][]string{
		"no setting":          {},
		"no value":            {"--set", "require_mfa"},
		"an unknown setting":  {"--set", "colour=blue"},
		"not a bool":          {"--set", "require_mfa=maybe"},
		"an unknown part":     {"--instance", "--set", "smtp.port=25"},
		"a group as a value":  {"--instance", "--set", "smtp=relay"},
		"not a duration":      {"--instance", "--set", "leaf_certificate_lifetime=forever"},
		"too long":            {"--instance", "--set", "leaf_certificate_lifetime=31d"},
		"an unknown value":    {"--instance", "--set", "password_hash_profile=fast"},
		"a bad group ID":      {"--set", "default_gateway_group_id=gwg_bad"},
		"an org's in --inst.": {"--instance", "--set", "require_mfa=true"},
		"an argument":         {"--set", "require_mfa=true", "extra"},
	} {
		a.org, a.instance = nil, nil
		if code, _, _ := run(append([]string{"update", "settings"}, args...)...); code != cli.ExitUsage || a.org != nil || a.instance != nil {
			t.Errorf("%s: %d", name, code)
		}
	}

	pwFile := filepath.Join(dir, "smtp")
	if err := os.WriteFile(pwFile, []byte("file-password\r\nignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pwFile, 0o640); err != nil { //nolint:gosec // G302: a file other users may read, for the warning
		t.Fatal(err)
	}
	if code, out, errOut := run("set", "smtp-password", "--password-file", pwFile); code != cli.ExitOK || a.smtp.GetPassword() != "file-password" ||
		!strings.Contains(errOut, "open to other users (mode 0640)") || len(prompted) != 0 || strings.Contains(out, "file-password") {
		t.Fatalf("a password from a file: %d %q %q %v", code, out, errOut, a.smtp)
	}
	if code, _, _ := run("set", "smtp-password"); code != cli.ExitOK || a.smtp.GetPassword() != "relay-password" ||
		!slices.Equal(prompted, []string{"the mail relay"}) {
		t.Fatalf("a password from the prompt: %d %v", code, prompted)
	}
	if code, out, _ := run("set", "smtp-password", "--remove"); code != cli.ExitOK || a.smtp.GetPassword() != "" || !strings.Contains(out, "Removed") {
		t.Fatalf("a removal: %d %q", code, out)
	}
	a.smtp, answer = nil, ""
	if code, _, _ := run("set", "smtp-password"); code != cli.ExitUsage || a.smtp != nil {
		t.Errorf("an empty password: %d", code)
	}
	if code, _, _ := run("set", "smtp-password", "--remove", "--password-file", pwFile); code != cli.ExitUsage || a.smtp != nil {
		t.Errorf("--remove with a file: %d", code)
	}
}
