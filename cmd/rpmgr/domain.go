// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// domainCommands are create domain, verify domain and trust domain, upload and renew certificate,
// and create and update ca-bundle.
func domainCommands() (create, update, more map[string][]*cli.Command) {
	createDomain, _ := resourceCommands("domain", []field{
		{flag: "fqdn", name: "fqdn", usage: "the name to claim, e.g. example.com"},
		{flag: "wildcard", name: "wildcard", usage: "claim the names under it as well"},
		{flag: "method", name: "method", usage: "how to prove it: txt (a DNS TXT record, the default) or http (a token the org's gateways serve)"},
	}, proofSteps)
	createBundle, updateBundle := resourceCommands("ca-bundle", []field{
		{flag: "name", name: "name", usage: "the bundle's name, unique in the org", update: true},
		{flag: "pem-file", name: "pem", usage: "a file of 1 to 100 PEM certificates, each a trust anchor", update: true, file: true},
	})
	create = map[string][]*cli.Command{"create": {createDomain, createBundle}}
	update = map[string][]*cli.Command{"update": {updateBundle}}
	more = map[string][]*cli.Command{
		"verify": {domainAction("verify", "check a domain claim's proof now", false)},
		"trust":  {domainAction("trust", "mark a domain claim verified without a proof (Instance Admin)", true)},
		"upload": {uploadCertificate()},
		"renew":  {renewCertificate()},
	}
	return create, update, more
}

// proofSteps says how to prove a new claim.
func proofSteps(env *cli.Env, res protoreflect.Message) error {
	var d rpmgrv1.Domain
	b, err := proto.Marshal(res.Interface())
	if err == nil {
		err = proto.Unmarshal(b, &d)
	}
	if err != nil {
		return err
	}
	c := d.GetChallenge()
	if d.GetMethod() == rpmgrv1.DomainMethod_DOMAIN_METHOD_HTTP {
		_, err = fmt.Fprintf(env.Stdout, "To prove the claim, point %s at a gateway of the org, which then serves %s with the body %s.\n",
			d.GetFqdn(), c.GetHttpUrl(), c.GetValue())
	} else {
		_, err = fmt.Fprintf(env.Stdout, "To prove the claim, add this TXT record at the domain's DNS:\n  %s  TXT  %q\n", c.GetTxtName(), c.GetValue())
	}
	if err == nil {
		_, err = fmt.Fprintf(env.Stdout, "The controller checks it on its own; to check now: rpmgr verify domain %s\n", d.GetId())
	}
	return err
}

// domainAction is verify domain or trust domain.
func domainAction(verb, summary string, trust bool) *cli.Command {
	return &cli.Command{
		Name: "domain", Summary: summary, Args: "<id>",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the domain's ID")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			dc := rpmgrv1connect.NewDomainServiceClient(s.hc, s.creds.Controller)
			var d *rpmgrv1.Domain
			if trust {
				err = s.withStepUp(ctx, func() error {
					r, err := dc.MarkDomainTrusted(ctx, connect.NewRequest(&rpmgrv1.MarkDomainTrustedRequest{DomainId: args[0]}))
					if err == nil {
						d = r.Msg.GetDomain()
					}
					return err
				})
			} else {
				var r *connect.Response[rpmgrv1.VerifyDomainResponse]
				if r, err = dc.VerifyDomain(ctx, connect.NewRequest(&rpmgrv1.VerifyDomainRequest{DomainId: args[0]})); err == nil {
					d = r.Msg.GetDomain()
				}
			}
			if err != nil {
				return apiError(err)
			}
			msg := fmt.Sprintf("Domain %s (%s) is %s", d.GetId(), d.GetFqdn(), d.GetStatus().String()[len("DOMAIN_STATUS_"):])
			if d.GetLastError() != "" && d.GetStatus() != rpmgrv1.DomainStatus_DOMAIN_STATUS_VERIFIED {
				msg += ": " + d.GetLastError()
			}
			_, err = fmt.Fprintln(env.Stdout, msg+".")
			return err
		},
	}
}

func uploadCertificate() *cli.Command {
	var chainFile, keyFile string
	return &cli.Command{
		Name: "certificate", Summary: "upload a certificate chain and its key for http routes",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&chainFile, "chain", "", "the PEM chain, leaf first")
			fs.StringVar(&keyFile, "key", "", "the leaf's PEM private key")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 || chainFile == "" || keyFile == "" {
				return cli.Usagef("give --chain and --key and no argument")
			}
			chain, err := os.ReadFile(chainFile) //nolint:gosec // G304: the user's file
			if err != nil {
				return err
			}
			if st, err := os.Stat(keyFile); err == nil && st.Mode().Perm()&0o077 != 0 {
				_, _ = fmt.Fprintf(env.Stderr, "warning: the key file %s is open to other users (mode %04o); make it 0600\n", keyFile, st.Mode().Perm())
			}
			key, err := os.ReadFile(keyFile) //nolint:gosec // G304: the user's file
			if err != nil {
				return err
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			resp, err := rpmgrv1connect.NewCertificateServiceClient(s.hc, s.creds.Controller).UploadCertificate(ctx,
				connect.NewRequest(&rpmgrv1.UploadCertificateRequest{OrgId: s.creds.Org, ChainPem: string(chain), PrivateKeyPem: string(key)}))
			clear(key)
			if err != nil {
				return apiError(err)
			}
			c := resp.Msg.GetCertificate()
			_, err = fmt.Fprintf(env.Stdout, "Uploaded certificate %s for %v, valid until %s.\n", c.GetId(), c.GetSans(), c.GetNotAfter().AsTime().UTC().Format("2006-01-02"))
			return err
		},
	}
}

func renewCertificate() *cli.Command {
	return &cli.Command{
		Name: "certificate", Summary: "renew an ACME certificate now, or obtain it if it failed", Args: "<id>",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the certificate's ID")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			resp, err := rpmgrv1connect.NewCertificateServiceClient(s.hc, s.creds.Controller).RenewCertificate(ctx,
				connect.NewRequest(&rpmgrv1.RenewCertificateRequest{CertificateId: args[0]}))
			if err != nil {
				return apiError(err)
			}
			state := "The renewal of certificate %s started; rpmgr get certificate %s shows its outcome.\n"
			if !resp.Msg.GetStarted() {
				state = "A renewal of certificate %s runs already; rpmgr get certificate %s shows its outcome.\n"
			}
			_, err = fmt.Fprintf(env.Stdout, state, args[0], args[0])
			return err
		},
	}
}
