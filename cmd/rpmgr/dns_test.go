// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// theToken is a made-up provider token the tests look for in every output.
const theToken = "cf-token-of-the-test-0001" //nolint:gosec // G101: a made-up value

// dnsAPI is the three DNS services with one provider, one zone and one name; connecting, rotating
// and deleting a provider need a step-up, as the API's rules say.
type dnsAPI struct {
	rpmgrv1connect.UnimplementedDnsProviderServiceHandler
	rpmgrv1connect.UnimplementedDnsZoneServiceHandler
	rpmgrv1connect.UnimplementedDnsNameServiceHandler
	stepUpAPI

	mu         sync.Mutex
	connected  *rpmgrv1.ConnectDnsProviderRequest
	updated    *rpmgrv1.UpdateDnsProviderRequest
	deleted    *rpmgrv1.DeleteDnsProviderRequest
	imported   *rpmgrv1.ImportZoneRequest
	zoneUpdate *rpmgrv1.UpdateZoneRequest
	removed    *rpmgrv1.RemoveZoneRequest
	nameMade   *rpmgrv1.CreateDnsNameRequest
	nameUpdate *rpmgrv1.UpdateDnsNameRequest
	nameGone   *rpmgrv1.DeleteDnsNameRequest
	calls      int
	refuse     error // what a provider write answers, if set
	zonePlans  zoneFake
}

func (a *dnsAPI) stepped() error {
	a.stepUpAPI.mu.Lock()
	defer a.stepUpAPI.mu.Unlock()
	if !a.stepUpAPI.stepped {
		return stepUpError()
	}
	return nil
}

func theProvider() *rpmgrv1.DnsProvider {
	return &rpmgrv1.DnsProvider{Id: "dnp_1", Name: "cf", Status: rpmgrv1.ProviderStatus_PROVIDER_STATUS_OK, Etag: "3",
		Kind:           &rpmgrv1.DnsProvider_Cloudflare{Cloudflare: &rpmgrv1.CloudflareProvider{AccountId: "acc"}},
		TokenExpiresAt: timestamppb.New(time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)), TokenExpiring: true}
}

func theZone() *rpmgrv1.DnsZone {
	return &rpmgrv1.DnsZone{Id: "dnz_1", Name: "example.com", DnsProviderId: "dnp_1", ProviderZoneId: "pz1", Etag: "5",
		SyncState: rpmgrv1.ZoneSyncState_ZONE_SYNC_STATE_HELD, HeldReason: "imported", DefaultTtl: 300,
		ProviderStatus: rpmgrv1.ZoneProviderStatus_ZONE_PROVIDER_STATUS_PERMISSION_DENIED}
}

func (a *dnsAPI) ConnectDnsProvider(_ context.Context, req *connect.Request[rpmgrv1.ConnectDnsProviderRequest]) (*connect.Response[rpmgrv1.ConnectDnsProviderResponse], error) {
	if err := a.stepped(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.refuse != nil {
		return nil, a.refuse
	}
	a.connected = req.Msg
	return connect.NewResponse(&rpmgrv1.ConnectDnsProviderResponse{DnsProvider: theProvider()}), nil
}

func (a *dnsAPI) GetDnsProvider(context.Context, *connect.Request[rpmgrv1.GetDnsProviderRequest]) (*connect.Response[rpmgrv1.GetDnsProviderResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetDnsProviderResponse{DnsProvider: theProvider()}), nil
}

func (a *dnsAPI) ListDnsProviders(context.Context, *connect.Request[rpmgrv1.ListDnsProvidersRequest]) (*connect.Response[rpmgrv1.ListDnsProvidersResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListDnsProvidersResponse{DnsProviders: []*rpmgrv1.DnsProvider{theProvider()}}), nil
}

func (a *dnsAPI) UpdateDnsProvider(_ context.Context, req *connect.Request[rpmgrv1.UpdateDnsProviderRequest]) (*connect.Response[rpmgrv1.UpdateDnsProviderResponse], error) {
	if slices.Contains(req.Msg.GetUpdateMask().GetPaths(), "cloudflare.api_token") {
		if err := a.stepped(); err != nil {
			return nil, err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.refuse != nil {
		return nil, a.refuse
	}
	a.updated = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateDnsProviderResponse{DnsProvider: theProvider()}), nil
}

func (a *dnsAPI) DeleteDnsProvider(_ context.Context, req *connect.Request[rpmgrv1.DeleteDnsProviderRequest]) (*connect.Response[rpmgrv1.DeleteDnsProviderResponse], error) {
	if err := a.stepped(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deleted = req.Msg
	return connect.NewResponse(&rpmgrv1.DeleteDnsProviderResponse{}), nil
}

func (a *dnsAPI) ListProviderZones(_ context.Context, req *connect.Request[rpmgrv1.ListProviderZonesRequest]) (*connect.Response[rpmgrv1.ListProviderZonesResponse], error) {
	if req.Msg.GetDnsProviderId() != "dnp_1" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such provider"))
	}
	return connect.NewResponse(&rpmgrv1.ListProviderZonesResponse{Zones: []*rpmgrv1.ProviderZone{
		{Id: "pz1", Name: "example.com", Status: "active", Type: "full"}, {Id: "pz2", Name: "example.org", Status: "pending", Type: "full"}}}), nil
}

func (a *dnsAPI) ImportZone(_ context.Context, req *connect.Request[rpmgrv1.ImportZoneRequest]) (*connect.Response[rpmgrv1.ImportZoneResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.imported = req.Msg
	return connect.NewResponse(&rpmgrv1.ImportZoneResponse{DnsZone: theZone(),
		Domain: &rpmgrv1.Domain{Id: "dom_1", Fqdn: "example.com", Status: rpmgrv1.DomainStatus_DOMAIN_STATUS_VERIFIED}}), nil
}

func (a *dnsAPI) GetZone(context.Context, *connect.Request[rpmgrv1.GetZoneRequest]) (*connect.Response[rpmgrv1.GetZoneResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetZoneResponse{DnsZone: theZone()}), nil
}

func (a *dnsAPI) ListZones(context.Context, *connect.Request[rpmgrv1.ListZonesRequest]) (*connect.Response[rpmgrv1.ListZonesResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListZonesResponse{DnsZones: []*rpmgrv1.DnsZone{theZone()}}), nil
}

func (a *dnsAPI) UpdateZone(_ context.Context, req *connect.Request[rpmgrv1.UpdateZoneRequest]) (*connect.Response[rpmgrv1.UpdateZoneResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.zoneUpdate = req.Msg
	z := proto.Clone(theZone()).(*rpmgrv1.DnsZone)
	return connect.NewResponse(&rpmgrv1.UpdateZoneResponse{DnsZone: z}), nil
}

func (a *dnsAPI) RemoveZone(_ context.Context, req *connect.Request[rpmgrv1.RemoveZoneRequest]) (*connect.Response[rpmgrv1.RemoveZoneResponse], error) {
	if req.Msg.GetDeleteRecords() {
		if err := a.stepped(); err != nil {
			return nil, err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.zonePlans.calls = append(a.zonePlans.calls, "remove")
	if a.zonePlans.removeErr != nil {
		return nil, a.zonePlans.removeErr
	}
	a.removed = req.Msg
	return connect.NewResponse(&rpmgrv1.RemoveZoneResponse{}), nil
}

func theName() *rpmgrv1.DnsName {
	return &rpmgrv1.DnsName{Id: "dnn_1", Fqdn: "www.example.com", GatewayGroupId: "gwg_1", Ttl: 120, Etag: "2"}
}

func (a *dnsAPI) CreateDnsName(_ context.Context, req *connect.Request[rpmgrv1.CreateDnsNameRequest]) (*connect.Response[rpmgrv1.CreateDnsNameResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nameMade = req.Msg
	n := proto.Clone(req.Msg.GetDnsName()).(*rpmgrv1.DnsName)
	n.Id = "dnn_1"
	return connect.NewResponse(&rpmgrv1.CreateDnsNameResponse{DnsName: n}), nil
}

func (a *dnsAPI) GetDnsName(context.Context, *connect.Request[rpmgrv1.GetDnsNameRequest]) (*connect.Response[rpmgrv1.GetDnsNameResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetDnsNameResponse{DnsName: theName()}), nil
}

func (a *dnsAPI) ListDnsNames(context.Context, *connect.Request[rpmgrv1.ListDnsNamesRequest]) (*connect.Response[rpmgrv1.ListDnsNamesResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListDnsNamesResponse{DnsNames: []*rpmgrv1.DnsName{theName()}}), nil
}

func (a *dnsAPI) UpdateDnsName(_ context.Context, req *connect.Request[rpmgrv1.UpdateDnsNameRequest]) (*connect.Response[rpmgrv1.UpdateDnsNameResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nameUpdate = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateDnsNameResponse{DnsName: theName()}), nil
}

func (a *dnsAPI) DeleteDnsName(_ context.Context, req *connect.Request[rpmgrv1.DeleteDnsNameRequest]) (*connect.Response[rpmgrv1.DeleteDnsNameResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nameGone = req.Msg
	return connect.NewResponse(&rpmgrv1.DeleteDnsNameResponse{}), nil
}

// gatewayGroups answers the lookup of --group by name.
type gatewayGroups struct {
	rpmgrv1connect.UnimplementedGatewayServiceHandler
}

func (gatewayGroups) ListGatewayGroups(context.Context, *connect.Request[rpmgrv1.ListGatewayGroupsRequest]) (*connect.Response[rpmgrv1.ListGatewayGroupsResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListGatewayGroupsResponse{GatewayGroups: []*rpmgrv1.GatewayGroup{{Id: "gwg_1", Name: "edge"}}}), nil
}

// dnsEnv serves the fake API and returns a runner of commands against it.
func dnsEnv(t *testing.T, stdin string) (*dnsAPI, func(args ...string) (int, string, string), string) {
	t.Helper()
	a := &dnsAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewDnsProviderServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewDnsZoneServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewDnsNameServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(&a.stepUpAPI))
	mux.Handle(rpmgrv1connect.NewGatewayServiceHandler(gatewayGroups{}))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")), CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	oldIn, oldPrompt := stdinReader, stepUpPrompt
	stdinReader = strings.NewReader(stdin)
	stepUpPrompt = func() (string, error) { return "right", nil }
	t.Cleanup(func() { stdinReader, stepUpPrompt = oldIn, oldPrompt })
	return a, func(args ...string) (int, string, string) {
		return runWith(map[string]string{"RPMGR_CREDENTIALS": creds}, "", args...)
	}, dir
}

// TestDNSProviderCommands (docs/16-cli.md, #674): connect, list, get, rename, rotate and delete a
// provider. The token comes from a file or standard input and is never an argument; it never
// appears in an output or an error, whether the API took it or refused it; connecting, rotating
// and deleting take a step-up; a rename needs none and sends the etag it read.
func TestDNSProviderCommands(t *testing.T) {
	a, run, dir := dnsEnv(t, theToken+"\n")
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte(theToken+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sawToken := func(out, errOut string) bool { return strings.Contains(out+errOut, theToken) }

	// Refused input reaches no API call.
	for name, args := range map[string][]string{
		"no token file":      {"connect", "dns-provider", "--name", "cf", "--kind", "cloudflare"},
		"no name":            {"connect", "dns-provider", "--kind", "cloudflare", "--token-file", file},
		"an unknown kind":    {"connect", "dns-provider", "--name", "cf", "--kind", "route53", "--token-file", file},
		"no kind":            {"connect", "dns-provider", "--name", "cf", "--token-file", file},
		"an argument":        {"connect", "dns-provider", "--name", "cf", "--kind", "cloudflare", "--token-file", file, theToken},
		"a missing file":     {"connect", "dns-provider", "--name", "cf", "--kind", "cloudflare", "--token-file", filepath.Join(dir, "missing")},
		"no token to rotate": {"rotate", "dns-provider-token", "cf"},
		"no provider":        {"rotate", "dns-provider-token", "--token-file", file},
		"nothing to rename":  {"update", "dns-provider", "cf"},
		"no zone to import":  {"import", "zone", "--provider", "cf"},
	} {
		if code, out, errOut := run(args...); code == cli.ExitOK || sawToken(out, errOut) {
			t.Errorf("%s: %d %q %q", name, code, out, errOut)
		}
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run("connect", "dns-provider", "--name", "cf", "--kind", "cloudflare", "--token-file", empty); code != cli.ExitUsage ||
		!strings.Contains(errOut, "no token") {
		t.Errorf("an empty file: %d %q", code, errOut)
	}
	long := filepath.Join(dir, "long")
	if err := os.WriteFile(long, []byte(strings.Repeat("a", 5000)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := run("connect", "dns-provider", "--name", "cf", "--kind", "cloudflare", "--token-file", long); code != cli.ExitUsage || sawToken(out, errOut) ||
		strings.Contains(errOut+out, strings.Repeat("a", 100)) {
		t.Errorf("a file with more than a token: %d %q %q", code, out, errOut)
	}
	if a.calls != 0 || a.connected != nil {
		t.Fatalf("refused input reached the API: %d %v", a.calls, a.connected)
	}

	// A step-up, then the token from a file, with its line break trimmed.
	code, out, errOut := run("connect", "dns-provider", "--name", "cf", "--kind", "cloudflare", "--token-file", file, "--account-id", "acc")
	cf := a.connected.GetDnsProvider().GetCloudflare()
	if code != cli.ExitOK || cf.GetApiToken() != theToken || cf.GetAccountId() != "acc" || a.connected.GetOrgId() != "org_1" ||
		a.connected.GetDnsProvider().GetName() != "cf" || len(a.stepUps) != 1 || sawToken(out, errOut) ||
		!strings.Contains(out, "Connected dns provider dnp_1 (cf); its token is ok") || !strings.Contains(out, "expires 2027-01-02, soon") {
		t.Fatalf("connect: %d %q %q %v", code, out, errOut, a.connected)
	}
	// And from standard input.
	a.connected = nil
	if code, out, errOut := run("connect", "dns-provider", "--name", "cf2", "--kind", "cloudflare", "--token-file", "-"); code != cli.ExitOK ||
		a.connected.GetDnsProvider().GetCloudflare().GetApiToken() != theToken || sawToken(out, errOut) {
		t.Fatalf("connect from stdin: %d %q %q", code, out, errOut)
	}
	// A refusal of the provider does not echo the token either.
	a.refuse = connect.NewError(connect.CodeInvalidArgument, errors.New("the provider refused the token"))
	if code, out, errOut := run("connect", "dns-provider", "--name", "cf3", "--kind", "cloudflare", "--token-file", file); code != cli.ExitError ||
		!strings.Contains(errOut, "the provider refused the token") || sawToken(out, errOut) {
		t.Fatalf("a refused token: %d %q %q", code, out, errOut)
	}
	a.refuse = nil

	for _, args := range [][]string{{"get", "dns-provider", "cf"}, {"list", "dns-provider"}, {"get", "dns-provider", "dnp_1", "-o", "json"}} {
		code, out, errOut := run(args...)
		if code != cli.ExitOK || !strings.Contains(out, "dnp_1") || !strings.Contains(out, "OK") || sawToken(out, errOut) {
			t.Fatalf("%v: %d %q %q", args, code, out, errOut)
		}
	}

	// A rename needs no step-up and sends the etag it read.
	a.stepUpAPI.stepped, a.stepUps = false, nil
	if code, out, _ := run("update", "dns-provider", "cf", "--name", "cloudflare"); code != cli.ExitOK || len(a.stepUps) != 0 ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"name"}) || a.updated.GetEtag() != "3" ||
		a.updated.GetDnsProvider().GetName() != "cloudflare" || !strings.Contains(out, "Updated dns provider dnp_1") {
		t.Fatalf("rename: %d %q %v", code, out, a.updated)
	}

	// A rotation needs the step-up and replaces the token by its mask, nothing else.
	stdinReader = strings.NewReader(theToken)
	code, out, errOut = run("rotate", "dns-provider-token", "--token-file", "-", "cf")
	if code != cli.ExitOK || !slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"cloudflare.api_token"}) ||
		a.updated.GetDnsProvider().GetCloudflare().GetApiToken() != theToken || a.updated.GetEtag() != "3" ||
		len(a.stepUps) != 1 || sawToken(out, errOut) || !strings.Contains(out, "Replaced the token of dns provider dnp_1") {
		t.Fatalf("rotate: %d %q %q %v", code, out, errOut, a.updated)
	}
	if code, _, _ := run("rotate", "dns-provider-token", "--token-file", file, "--account-id", "acc2", "dnp_1"); code != cli.ExitOK ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"cloudflare.api_token", "cloudflare.account_id"}) {
		t.Fatalf("rotate with an account: %d %v", code, a.updated)
	}

	// A delete asks for the step-up, sends the etag it read, and --force sends none.
	a.stepUpAPI.stepped, a.stepUps = false, nil
	if code, out, _ := run("delete", "dns-provider", "cf"); code != cli.ExitOK || len(a.stepUps) != 1 || a.deleted.GetDnsProviderId() != "dnp_1" ||
		a.deleted.GetEtag() != "3" || !strings.Contains(out, "Deleted dns-provider dnp_1") {
		t.Fatalf("delete: %d %q %v", code, out, a.deleted)
	}
	if code, _, _ := run("delete", "dns-provider", "dnp_1", "--force"); code != cli.ExitOK || a.deleted.GetEtag() != "" {
		t.Fatalf("a forced delete: %d %v", code, a.deleted)
	}

	// A wrong factor changes nothing.
	a.stepUpAPI.stepped, a.deleted = false, nil
	stepUpPrompt = func() (string, error) { return "wrong", nil }
	if code, _, errOut := run("delete", "dns-provider", "cf"); code != cli.ExitError || a.deleted != nil || !strings.Contains(errOut, "step-up failed") {
		t.Fatalf("a wrong factor: %d %q %v", code, errOut, a.deleted)
	}
}

// TestDNSZoneCommands (docs/16-cli.md, #674): list what a provider offers, import a zone by its
// name, list, get, change the gates and remove it; a zone the provider does not offer is refused
// before the import; a zone whose token lacks permission shows it.
func TestDNSZoneCommands(t *testing.T) {
	a, run, _ := dnsEnv(t, "")

	code, out, _ := run("list", "provider-zone", "cf")
	if code != cli.ExitOK || !strings.Contains(out, "example.org") || !strings.Contains(out, "pending") {
		t.Fatalf("list provider-zone: %d %q", code, out)
	}
	if code, _, errOut := run("list", "provider-zone", "nope"); code != cli.ExitError || !strings.Contains(errOut, "no dns-provider named") {
		t.Errorf("an unknown provider: %d %q", code, errOut)
	}

	if code, _, errOut := run("import", "zone", "--provider", "cf", "example.net"); code != cli.ExitError || a.imported != nil ||
		!strings.Contains(errOut, `offers no zone "example.net"`) {
		t.Fatalf("a zone the provider does not offer: %d %q %v", code, errOut, a.imported)
	}
	if code, _, _ := run("import", "zone", "example.com"); code != cli.ExitUsage {
		t.Errorf("import without a provider: %d", code)
	}
	code, out, errOut := run("import", "zone", "--provider", "cf", "Example.COM.")
	if code != cli.ExitOK || a.imported.GetDnsProviderId() != "dnp_1" || a.imported.GetProviderZoneId() != "pz1" ||
		!strings.Contains(out, "Imported zone dnz_1 (example.com); it is held (imported)") || !strings.Contains(out, "domain dom_1, which is verified") {
		t.Fatalf("import: %d %q %q %v", code, out, errOut, a.imported)
	}
	if code, _, _ := run("import", "zone", "--provider", "dnp_1", "pz2"); code != cli.ExitOK || a.imported.GetProviderZoneId() != "pz2" {
		t.Fatalf("import by the provider's zone ID: %d %v", code, a.imported)
	}

	for _, args := range [][]string{{"list", "zone"}, {"get", "zone", "example.com"}} {
		code, out, errOut := run(args...)
		for _, want := range []string{"dnz_1", "example.com", "HELD", "PERMISSION_DENIED"} {
			if code != cli.ExitOK || !strings.Contains(out, want) {
				t.Fatalf("%v lacks %q: %d %q %q", args, want, code, out, errOut)
			}
		}
	}

	// The gates: a bool, a number, a duration; only what the flags name goes in the mask.
	code, out, _ = run("update", "zone", "example.com", "--allow-wildcards", "--publish-route-hostnames=false", "--delete-threshold", "5", "--default-ttl", "10m")
	got := a.zoneUpdate.GetDnsZone()
	if code != cli.ExitOK || !slices.Equal(a.zoneUpdate.GetUpdateMask().GetPaths(), []string{"publish_route_hostnames", "allow_wildcards", "delete_threshold", "default_ttl"}) ||
		!got.GetAllowWildcards() || got.GetPublishRouteHostnames() || got.GetDeleteThreshold() != 5 || got.GetDefaultTtl() != 600 ||
		a.zoneUpdate.GetEtag() != "5" || got.GetId() != "dnz_1" || !strings.Contains(out, "Updated zone dnz_1") {
		t.Fatalf("update zone: %d %q %v", code, out, a.zoneUpdate)
	}
	if code, _, _ := run("update", "zone", "dnz_1", "--default-ttl", "300", "--force"); code != cli.ExitOK || a.zoneUpdate.GetEtag() != "" ||
		a.zoneUpdate.GetDnsZone().GetDefaultTtl() != 300 {
		t.Fatalf("a forced update: %d %v", code, a.zoneUpdate)
	}
	a.zoneUpdate = nil
	for name, args := range map[string][]string{
		"nothing to change":      {"update", "zone", "dnz_1"},
		"a negative number":      {"update", "zone", "dnz_1", "--delete-threshold", "-1"},
		"not a number":           {"update", "zone", "dnz_1", "--delete-threshold", "many"},
		"not a bool":             {"update", "zone", "dnz_1", "--allow-proxied=maybe"},
		"a fraction of a second": {"update", "zone", "dnz_1", "--default-ttl", "1500ms"},
		"a negative ttl":         {"update", "zone", "dnz_1", "--default-ttl", "-5m"},
		"no zone":                {"update", "zone", "--allow-proxied"},
	} {
		if code, _, _ := run(args...); code != cli.ExitUsage {
			t.Errorf("%s: %d", name, code)
		}
	}
	if a.zoneUpdate != nil {
		t.Fatalf("refused input reached the API: %v", a.zoneUpdate)
	}

	if code, out, _ := run("remove", "zone", "example.com"); code != cli.ExitOK || a.removed.GetDnsZoneId() != "dnz_1" || a.removed.GetEtag() != "5" ||
		!strings.Contains(out, "records stay at the provider") {
		t.Fatalf("remove: %d %q %v", code, out, a.removed)
	}
	if code, _, _ := run("remove", "zone", "dnz_1", "--force"); code != cli.ExitOK || a.removed.GetEtag() != "" {
		t.Fatalf("a forced remove: %d %v", code, a.removed)
	}
	if code, _, _ := run("remove", "zone"); code != cli.ExitUsage {
		t.Errorf("remove without a zone: %d", code)
	}
	if code, _, _ := run("delete", "zone", "dnz_1"); code != cli.ExitUsage {
		t.Errorf("a zone is removed, not deleted: %d", code)
	}
}

// TestDNSNameCommands (docs/16-cli.md, #674): create, list, get, update and delete a name; the
// group is given by name, the TTL as a duration or seconds; a name needs its group.
func TestDNSNameCommands(t *testing.T) {
	a, run, _ := dnsEnv(t, "")
	for name, args := range map[string][]string{
		"no name":           {"create", "dns-name", "--group", "edge"},
		"no group":          {"create", "dns-name", "--name", "www.example.com"},
		"a bad ttl":         {"create", "dns-name", "--name", "www.example.com", "--group", "edge", "--ttl", "soon"},
		"an unknown group":  {"create", "dns-name", "--name", "www.example.com", "--group", "nowhere"},
		"nothing to update": {"update", "dns-name", "dnn_1"},
	} {
		if code, _, _ := run(args...); code == cli.ExitOK {
			t.Errorf("%s was accepted", name)
		}
	}
	if a.nameMade != nil || a.nameUpdate != nil {
		t.Fatalf("refused input reached the API: %v %v", a.nameMade, a.nameUpdate)
	}
	code, out, errOut := run("create", "dns-name", "--name", "www.example.com", "--group", "edge", "--ttl", "2m")
	n := a.nameMade.GetDnsName()
	if code != cli.ExitOK || n.GetFqdn() != "www.example.com" || n.GetGatewayGroupId() != "gwg_1" || n.GetTtl() != 120 ||
		a.nameMade.GetOrgId() != "org_1" || !strings.Contains(out, "Created dns name dnn_1") {
		t.Fatalf("create: %d %q %q %v", code, out, errOut, a.nameMade)
	}
	if code, _, _ := run("create", "dns-name", "--name", "api.example.com", "--group", "gwg_1"); code != cli.ExitOK || a.nameMade.GetDnsName().GetTtl() != 0 {
		t.Fatalf("create without a ttl: %d %v", code, a.nameMade)
	}
	for _, args := range [][]string{{"get", "dns-name", "www.example.com"}, {"list", "dns-name"}} {
		if code, out, _ := run(args...); code != cli.ExitOK || !strings.Contains(out, "dnn_1") || !strings.Contains(out, "gwg_1") {
			t.Fatalf("%v: %d %q", args, code, out)
		}
	}
	if code, out, _ := run("update", "dns-name", "www.example.com", "--ttl", "300"); code != cli.ExitOK ||
		!slices.Equal(a.nameUpdate.GetUpdateMask().GetPaths(), []string{"ttl"}) || a.nameUpdate.GetDnsName().GetTtl() != 300 ||
		a.nameUpdate.GetEtag() != "2" || !strings.Contains(out, "Updated dns name dnn_1") {
		t.Fatalf("update: %d %q %v", code, out, a.nameUpdate)
	}
	if code, _, _ := run("update", "dns-name", "dnn_1", "--ttl", "0", "--group", "edge", "--force"); code != cli.ExitOK ||
		!slices.Equal(a.nameUpdate.GetUpdateMask().GetPaths(), []string{"gateway_group_id", "ttl"}) && !slices.Equal(a.nameUpdate.GetUpdateMask().GetPaths(), []string{"ttl", "gateway_group_id"}) ||
		a.nameUpdate.GetEtag() != "" {
		t.Fatalf("a forced update: %d %v", code, a.nameUpdate)
	}
	if code, out, _ := run("delete", "dns-name", "www.example.com"); code != cli.ExitOK || a.nameGone.GetDnsNameId() != "dnn_1" || a.nameGone.GetEtag() != "2" ||
		!strings.Contains(out, "Deleted dns-name dnn_1") {
		t.Fatalf("delete: %d %q %v", code, out, a.nameGone)
	}
}
