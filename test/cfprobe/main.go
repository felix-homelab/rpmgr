// SPDX-License-Identifier: Apache-2.0

// Command cfprobe checks the open questions VB-09 to VB-12 of docs/13-roadmap.md against a real
// Cloudflare zone. The maintainer runs it by hand (D110, docs/14-open-decisions.md): no token goes
// into CI and no assistant sees one. test/cfprobe/README.md is the run sheet.
//
// Tokens are read only from a file or from standard input, never from an argument or the
// environment, and every output line is scrubbed of them. The probe creates records only under one
// random label, "_rpmgr-probe-<random>", plus, with -apex-cname, one CNAME at the apex of an empty
// zone, and it deletes exactly those records before it ends, also when a check fails.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// maxBurst is the most requests -burst accepts: a bound, not a target.
const maxBurst = 2000

const usage = `usage: cfprobe -zone <name> -token-file <path|-> -under-scoped-token-file <path> [options]

  -zone                      the spare zone to probe, such as example.org
  -token-file                user token with Zone Read and DNS Edit on that zone; a path, or - for
                             standard input
  -under-scoped-token-file   a token that must NOT be allowed to write the zone; the probe expects
                             it to fail
  -account-id                account ID of the account-owned token (with -account-token-file)
  -account-token-file        account-owned token with the same permissions (optional)
  -apex-cname                also probe a CNAME at the zone apex (only if the apex has no records)
  -burst N                   VB-09: send up to N read requests to provoke a 429 (needs -confirm-burst)
  -confirm-burst             confirm that the burst may block this Cloudflare user's API for minutes
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(runMain(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// runMain parses the command line, reads the tokens and runs the probe. It returns the exit status:
// 0 all checks passed, 1 a check failed or a record is left behind, 2 usage or input error.
func runMain(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cfprobe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	zone := fs.String("zone", "", "")
	tokenFile := fs.String("token-file", "", "")
	underFile := fs.String("under-scoped-token-file", "", "")
	acctFile := fs.String("account-token-file", "", "")
	acctID := fs.String("account-id", "", "")
	apex := fs.Bool("apex-cname", false, "")
	burst := fs.Int("burst", 0, "")
	confirm := fs.Bool("confirm-burst", false, "")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(stderr, "cfprobe: %v\n%s", err, usage)
		return 2
	}
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "cfprobe: "+format+"\n", a...)
		return 2
	}
	zoneName := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(*zone)), ".")
	switch {
	case fs.NArg() > 0:
		return fail("unexpected argument (not echoed: tokens are never passed as arguments)")
	case idPattern.MatchString(zoneName):
		return fail("-zone takes the zone name (e.g. example.org), not its ID")
	case zoneName == "" || *tokenFile == "" || *underFile == "":
		return fail("-zone, -token-file and -under-scoped-token-file are required\n%s", usage)
	case (*acctFile == "") != (*acctID == ""):
		return fail("-account-token-file and -account-id go together")
	case *burst < 0 || *burst > maxBurst:
		return fail("-burst must be between 0 and %d", maxBurst)
	case *burst > 0 && !*confirm:
		return fail("-burst blocks this Cloudflare user's API calls for minutes once the limit is " +
			"hit; add -confirm-burst to run it")
	case *confirm && *burst == 0:
		return fail("-confirm-burst needs -burst N")
	}
	stdinUsers := 0
	for _, p := range []string{*tokenFile, *underFile, *acctFile} {
		if p == "-" {
			stdinUsers++
		}
	}
	if stdinUsers > 1 {
		return fail("only one token can come from standard input")
	}
	cfg := config{zone: zoneName, accountID: *acctID, apexCNAME: *apex, burst: *burst}
	var err error
	rep := &report{w: stdout}
	for _, t := range []struct {
		path string
		dst  *secret.Value
		what string
	}{{*tokenFile, &cfg.token, "token"}, {*underFile, &cfg.underScoped, "under-scoped token"},
		{*acctFile, &cfg.accountToken, "account-owned token"}} {
		if t.path == "" {
			continue
		}
		if *t.dst, err = readToken(t.path, stdin, rep); err != nil {
			return fail("%s: %v", t.what, err)
		}
		rep.hide(*t.dst)
	}
	e := env{
		newProvider: func(tok secret.Value, account string) (dns.Provider, error) {
			return cloudflare.New(cloudflare.Config{Token: tok, AccountID: account})
		},
		raw:   newRaw(cloudflare.BaseURL, nil),
		sleep: sleepCtx,
		now:   time.Now,
	}
	return run(ctx, cfg, e, rep)
}

// readToken reads a token from path, or from stdin for "-". The error never holds the content.
func readToken(path string, stdin io.Reader, rep *report) (secret.Value, error) {
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			var pe *os.PathError
			if errors.As(err, &pe) {
				err = pe.Err
			}
			return secret.Value{}, fmt.Errorf("cannot read %s: %w", path, err)
		}
		defer func() { _ = f.Close() }()
		if fi, err := f.Stat(); err == nil && fi.Mode().Perm()&0o077 != 0 {
			rep.add(info, "SETUP", "%s is readable by other users; chmod 600 it", path)
		}
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil {
		return secret.Value{}, errors.New("cannot read the token")
	}
	s := strings.TrimSpace(string(b))
	if len(b) > 4096 || s == "" || strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return secret.Value{}, errors.New("not a token: empty, longer than 4096 bytes or containing white space")
	}
	return secret.New(s), nil
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
