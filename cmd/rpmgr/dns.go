// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// stdinReader is where a token comes from with --token-file -; a test replaces it.
var stdinReader io.Reader = os.Stdin

// maxTokenBytes bounds what is read as a token: a provider's API token is far shorter.
const maxTokenBytes = 4096

// readToken reads a provider's API token from a file, or from standard input for "-". A token is a
// secret, so it is never an argument, which the shell history and the process list would keep,
// and no message of an error holds it ([04](docs/04-security.md#secrets-at-rest-and-in-logs)).
func readToken(path string, stdin io.Reader) (string, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(stdin, maxTokenBytes+1))
	} else {
		var f *os.File
		if f, err = os.Open(path); err == nil { //nolint:gosec // G304: the user's file
			b, err = io.ReadAll(io.LimitReader(f, maxTokenBytes+1))
			_ = f.Close()
		}
	}
	if err != nil {
		return "", fmt.Errorf("read --token-file: %w", err)
	}
	defer clear(b)
	tok := strings.TrimSpace(string(b))
	switch {
	case tok == "":
		return "", cli.Usagef("--token-file holds no token")
	case len(b) > maxTokenBytes:
		return "", cli.Usagef("--token-file holds more than a token")
	}
	return tok, nil
}

// dnsCommands are connect dns-provider, rotate dns-provider-token, import zone and remove zone,
// and the writes of the DNS kinds that the generic commands do not make: update dns-provider
// (a rename), update zone, and create and update dns-name (docs/16-cli.md). Get, list and delete
// are the generic ones.
func dnsCommands() map[string][]*cli.Command {
	_, updateProvider := resourceCommands("dns-provider", []field{{flag: "name", name: "name", usage: "the provider's name, unique in the org", update: true}})
	_, updateZone := resourceCommands("zone", []field{
		{flag: "publish-route-hostnames", name: "publish_route_hostnames", usage: "publish the hostnames of the org's routes in the zone (true or false)", update: true},
		{flag: "allow-proxied", name: "allow_proxied", usage: "allow Cloudflare-proxied records in the zone (true or false)", update: true},
		{flag: "allow-wildcards", name: "allow_wildcards", usage: "allow wildcard names in the zone (true or false)", update: true},
		{flag: "delete-threshold", name: "delete_threshold", usage: "the most records one pass may delete without an approval", update: true},
		{flag: "default-ttl", name: "default_ttl", usage: "the TTL of records that name none, as a duration (5m) or seconds", update: true, seconds: true},
	})
	createName, updateName := resourceCommands("dns-name", []field{
		{flag: "name", name: "fqdn", usage: "the fully qualified name to publish, under a verified domain of the org"},
		{flag: "group", name: "gateway_group_id", usage: "the gateway group it points at, by name or ID", ref: "gateway-group", update: true},
		{flag: "ttl", name: "ttl", usage: "its TTL as a duration (5m) or seconds; 0 is the zone's default", update: true, seconds: true},
	})
	// Both the name and the group are needed; the API refuses a name without either.
	var nameFlags *flag.FlagSet
	flags, run := createName.Flags, createName.Run
	createName.Flags = func(fs *flag.FlagSet) { nameFlags = fs; flags(fs) }
	createName.Run = func(ctx context.Context, env *cli.Env, args []string) error {
		if set := setFlags(nameFlags); !set["name"] || !set["group"] {
			return cli.Usagef("give --name and --group")
		}
		return run(ctx, env, args)
	}
	return map[string][]*cli.Command{
		"connect": {connectProvider()},
		"rotate":  {rotateToken()},
		"import":  {importZone()},
		"remove":  {removeZone()},
		"update":  {updateProvider, updateZone, updateName},
		"create":  {createName},
	}
}

// tokenFlags are the flags a command that takes a token has.
func tokenFlags(fs *flag.FlagSet, tokenFile, accountID *string) {
	fs.StringVar(tokenFile, "token-file", "", "a file holding the provider's API token, or - for standard input (required); write-only, never an argument")
	fs.StringVar(accountID, "account-id", "", "the Cloudflare account, for a token that belongs to an account")
}

func connectProvider() *cli.Command {
	var name, kind, tokenFile, accountID string
	return &cli.Command{
		Name: "dns-provider", Summary: "connect a DNS provider of the org with a step-up; its token is read from a file or standard input",
		NoArgEcho: true,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "the provider's name, unique in the org (required)")
			fs.StringVar(&kind, "kind", "", "the kind of provider: cloudflare (required)")
			tokenFlags(fs, &tokenFile, &accountID)
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 || name == "" || tokenFile == "" {
				return cli.Usagef("give --name, --kind cloudflare and --token-file, and no argument")
			}
			if kind != "cloudflare" {
				return cli.Usagef("--kind is cloudflare, not %q", kind)
			}
			tok, err := readToken(tokenFile, stdinReader)
			if err != nil {
				return err
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			req := &rpmgrv1.ConnectDnsProviderRequest{OrgId: s.creds.Org, DnsProvider: &rpmgrv1.DnsProvider{Name: name,
				Kind: &rpmgrv1.DnsProvider_Cloudflare{Cloudflare: &rpmgrv1.CloudflareProvider{ApiToken: tok, AccountId: accountID}}}}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			var resp *connect.Response[rpmgrv1.ConnectDnsProviderResponse]
			if err := s.withStepUp(ctx, func() error {
				var err error
				resp, err = rpmgrv1connect.NewDnsProviderServiceClient(s.hc, s.creds.Controller).ConnectDnsProvider(ctx, connect.NewRequest(req))
				return err
			}); err != nil {
				return apiError(err)
			}
			return printProvider(env, "Connected", resp.Msg.GetDnsProvider())
		},
	}
}

// printProvider says what the provider's token check found.
func printProvider(env *cli.Env, verb string, p *rpmgrv1.DnsProvider) error {
	status := strings.ToLower(strings.TrimPrefix(p.GetStatus().String(), "PROVIDER_STATUS_"))
	if _, err := fmt.Fprintf(env.Stdout, "%s dns provider %s (%s); its token is %s.\n", verb, p.GetId(), p.GetName(), status); err != nil {
		return err
	}
	if p.GetTokenExpiresAt() != nil {
		warn := ""
		if p.GetTokenExpiring() {
			warn = ", soon: rotate it with rpmgr rotate dns-provider-token"
		}
		if _, err := fmt.Fprintf(env.Stdout, "The token expires %s%s.\n", p.GetTokenExpiresAt().AsTime().UTC().Format("2006-01-02"), warn); err != nil {
			return err
		}
	}
	return nil
}

func rotateToken() *cli.Command {
	var tokenFile, accountID string
	k := kindOf("dns-provider")
	return &cli.Command{
		Name: "dns-provider-token", Summary: "replace a provider's token with a step-up; its zones and records stay", Args: "<id or name>",
		Flags: func(fs *flag.FlagSet) { tokenFlags(fs, &tokenFile, &accountID) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 || tokenFile == "" {
				return cli.Usagef("give --token-file and the provider's ID or name")
			}
			tok, err := readToken(tokenFile, stdinReader)
			if err != nil {
				return err
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			id, err := s.ref(ctx, k, args[0])
			if err != nil {
				return err
			}
			cur, err := s.get(ctx, k, id)
			if err != nil {
				return err
			}
			paths := []string{"cloudflare.api_token"}
			cf := &rpmgrv1.CloudflareProvider{ApiToken: tok}
			if accountID != "" {
				cf.AccountId, paths = accountID, append(paths, "cloudflare.account_id")
			}
			req := &rpmgrv1.UpdateDnsProviderRequest{DnsProvider: &rpmgrv1.DnsProvider{Id: id, Kind: &rpmgrv1.DnsProvider_Cloudflare{Cloudflare: cf}},
				UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}, Etag: cur.Get(cur.Descriptor().Fields().ByName("etag")).String()}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			var resp *connect.Response[rpmgrv1.UpdateDnsProviderResponse]
			if err := s.withStepUp(ctx, func() error {
				var err error
				resp, err = rpmgrv1connect.NewDnsProviderServiceClient(s.hc, s.creds.Controller).UpdateDnsProvider(ctx, connect.NewRequest(req))
				return err
			}); err != nil {
				return apiError(err)
			}
			return printProvider(env, "Replaced the token of", resp.Msg.GetDnsProvider())
		},
	}
}

func importZone() *cli.Command {
	var provider string
	pk := kindOf("dns-provider")
	return &cli.Command{
		Name: "zone", Summary: "import a zone of a provider as managed; it starts held, so nothing is published until a plan is approved",
		Args: "--provider <id or name> <zone name or provider zone ID>",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&provider, "provider", "", "the provider that offers the zone, by name or ID (required)")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 || provider == "" {
				return cli.Usagef("give --provider and the zone's name")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			id, err := s.ref(ctx, pk, provider)
			if err != nil {
				return err
			}
			offered, err := rpmgrv1connect.NewDnsProviderServiceClient(s.hc, s.creds.Controller).ListProviderZones(ctx,
				connect.NewRequest(&rpmgrv1.ListProviderZonesRequest{DnsProviderId: id}))
			if err != nil {
				return apiError(err)
			}
			want := strings.TrimSuffix(strings.ToLower(args[0]), ".")
			zoneID := ""
			for _, z := range offered.Msg.GetZones() {
				if z.GetId() == args[0] || strings.ToLower(z.GetName()) == want {
					zoneID = z.GetId()
				}
			}
			if zoneID == "" {
				return fmt.Errorf("provider %s offers no zone %q; rpmgr list provider-zone %s shows what it offers", provider, args[0], provider)
			}
			resp, err := rpmgrv1connect.NewDnsZoneServiceClient(s.hc, s.creds.Controller).ImportZone(ctx,
				connect.NewRequest(&rpmgrv1.ImportZoneRequest{DnsProviderId: id, ProviderZoneId: zoneID}))
			if err != nil {
				return apiError(err)
			}
			z, d := resp.Msg.GetDnsZone(), resp.Msg.GetDomain()
			_, err = fmt.Fprintf(env.Stdout, "Imported zone %s (%s); it is held (%s) and publishes nothing yet.\n"+
				"Its name is claimed as domain %s, which is %s.\n", z.GetId(), z.GetName(), z.GetHeldReason(), d.GetId(),
				strings.ToLower(strings.TrimPrefix(d.GetStatus().String(), "DOMAIN_STATUS_")))
			return err
		},
	}
}

func removeZone() *cli.Command {
	var force, deleteRecords bool
	var hash string
	k := kindOf("zone")
	return &cli.Command{
		Name: "zone", Summary: "stop managing a zone: the records stay at the provider and only the ledger is dropped, or with --delete-records they are deleted too", Args: "[--delete-records --plan-hash <hash>] <id or name>",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&force, "force", false, "remove without checking that the zone is unchanged since this command read it")
			fs.BoolVar(&deleteRecords, "delete-records", false, "also delete the records rpmgr owns in the zone at the provider; needs --plan-hash and a step-up")
			fs.StringVar(&hash, "plan-hash", "", "with --delete-records: the hash of the plan you read with rpmgr plan zone --delete-records")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the zone's ID or name")
			}
			switch {
			case deleteRecords && hash == "":
				return cli.Usagef("--delete-records needs --plan-hash, the hash that rpmgr plan zone --delete-records shows")
			case !deleteRecords && hash != "":
				return cli.Usagef("--plan-hash goes with --delete-records")
			case deleteRecords && (len(hash) != 64 || strings.Trim(hash, "0123456789abcdef") != ""):
				return cli.Usagef("--plan-hash is the 64 lower-case hexadecimal characters that rpmgr plan zone shows")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			id, err := s.ref(ctx, k, args[0])
			if err != nil {
				return err
			}
			req := &rpmgrv1.RemoveZoneRequest{DnsZoneId: id}
			if !force {
				cur, err := s.get(ctx, k, id)
				if err != nil {
					return err
				}
				req.Etag = cur.Get(cur.Descriptor().Fields().ByName("etag")).String()
			}
			if deleteRecords {
				return removeWithRecords(ctx, env, s, id, hash, req.Etag)
			}
			if _, err := rpmgrv1connect.NewDnsZoneServiceClient(s.hc, s.creds.Controller).RemoveZone(ctx, connect.NewRequest(req)); err != nil {
				return apiError(err)
			}
			_, err = fmt.Fprintf(env.Stdout, "Removed zone %s; its records stay at the provider.\n", id)
			return err
		},
	}
}
