// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// auditCommands are `rpmgr audit export` and `rpmgr audit verify-export` (docs/16-cli.md).
func auditCommands() *cli.Command {
	return group("audit", "export the audit log with its proofs, and verify an export offline", auditExport(), auditVerifyExport())
}

// auditExport is `rpmgr audit export`: the org's chain, or the instance chain, into a file.
func auditExport() *cli.Command {
	var out string
	var instance bool
	return &cli.Command{
		Name: "export", Summary: "export an audit chain with its proofs as JSON Lines, after a step-up (Owner or Admin; the instance chain for the Instance Admin)",
		Args: "--out <file or ->",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&out, "out", "", "the file to write, mode 0600, never overwriting one; - for standard output (required)")
			fs.BoolVar(&instance, "instance", false, "export the instance chain instead of the org's")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 || out == "" {
				return cli.Usagef("give --out <file or ->, and no argument")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			ac := rpmgrv1connect.NewAuditServiceClient(s.hc, s.creds.Controller)
			open := func() (*exportStream, error) {
				if instance {
					st, err := ac.ExportInstanceAudit(ctx, connect.NewRequest(&rpmgrv1.ExportInstanceAuditRequest{}))
					if err != nil {
						return nil, err
					}
					return &exportStream{receive: st.Receive, lines: func() []string { return st.Msg().GetLines() }, err: st.Err, close: st.Close}, nil
				}
				req := &rpmgrv1.ExportAuditRequest{OrgId: s.creds.Org}
				if err := protovalidate.Validate(req); err != nil {
					return nil, cli.Usagef("the credentials name no org; run rpmgr login again or give --instance: %v", err)
				}
				st, err := ac.ExportAudit(ctx, connect.NewRequest(req))
				if err != nil {
					return nil, err
				}
				return &exportStream{receive: st.Receive, lines: func() []string { return st.Msg().GetLines() }, err: st.Err, close: st.Close}, nil
			}
			var lines int
			// A step-up is asked for before the first line comes, so a retry starts the file again.
			if err := s.withStepUp(ctx, func() error {
				var err error
				lines, err = writeExport(env, out, open)
				return err
			}); err != nil {
				return apiError(err)
			}
			if out != "-" {
				_, err = fmt.Fprintf(env.Stdout, "Wrote %s: %d lines. Verify it away from the controller with: rpmgr audit verify-export --ca-pin <pin> %s\n", out, lines, out)
			}
			return err
		},
	}
}

// exportStream is a server stream of an export, of either kind.
type exportStream struct {
	receive func() bool
	lines   func() []string
	err     func() error
	close   func() error
}

// writeExport streams the export into out, a new file or, for "-", standard output. A file is
// written beside its name and linked in when complete, so that a failure leaves none and a file
// that exists is never replaced. It returns the number of lines.
func writeExport(env *cli.Env, out string, open func() (*exportStream, error)) (int, error) {
	if _, err := os.Lstat(out); out != "-" && err == nil { // before the export is recorded
		return 0, fmt.Errorf("%s exists; rpmgr never overwrites a file", out)
	}
	st, err := open()
	if err != nil {
		return 0, err
	}
	defer func() { _ = st.close() }()
	w := io.Writer(env.Stdout)
	var tmp *os.File
	if out != "-" {
		if tmp, err = os.CreateTemp(filepath.Dir(out), ".rpmgr-audit-export-*"); err != nil { // mode 0600
			return 0, err
		}
		defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
		w = tmp
	}
	n := 0
	for st.receive() {
		for _, l := range st.lines() {
			if _, err := io.WriteString(w, l+"\n"); err != nil {
				return n, err
			}
			n++
		}
	}
	if err := st.err(); err != nil {
		return n, err
	}
	if tmp == nil {
		return n, nil
	}
	if err := tmp.Sync(); err != nil {
		return n, err
	}
	if err := os.Link(tmp.Name(), out); err != nil { // fails if out appeared meanwhile
		return n, err
	}
	return n, nil
}

// auditVerifyExport is `rpmgr audit verify-export`: no controller, no credentials.
func auditVerifyExport() *cli.Command {
	var pin string
	return &cli.Command{
		Name: "verify-export", Summary: "verify an audit export offline against the CA's pin: links, hashes, checkpoint signatures, nothing removed or edited",
		Args: "--ca-pin sha256:<base64> <file or ->",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&pin, "ca-pin", "", "pin of the controller's root CA, sha256:<base64> (required)")
		},
		Run: func(_ context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 || pin == "" {
				return cli.Usagef("give --ca-pin and the export file, or - for standard input")
			}
			if !pki.ValidPin(pin) {
				return cli.Usagef("--ca-pin must be sha256:<base64 of 32 bytes>")
			}
			var r io.Reader = os.Stdin
			if args[0] != "-" {
				f, err := os.Open(args[0])
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				r = f
			}
			res, err := audit.VerifyExport(r, pin)
			if err != nil {
				if errors.Is(err, audit.ErrBroken) {
					return fmt.Errorf("NOT VERIFIED: %w", err)
				}
				return err
			}
			if _, err := fmt.Fprintf(env.Stdout, "Verified the chain %s: %d entries (seq %d to %d), %d checkpoints, signed by keys the pinned CA certified.\n",
				res.Chain, res.Entries, res.FirstSeq, res.LastSeq, res.Checkpoints); err != nil {
				return err
			}
			if res.Unanchored > 0 {
				_, err = fmt.Fprintf(env.Stdout, "The last %d entries come after the newest checkpoint (seq %d): no signature covers them yet. A later export anchors them.\n",
					res.Unanchored, res.AnchoredSeq)
			}
			return err
		},
	}
}
