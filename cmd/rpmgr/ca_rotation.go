// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
)

// newRootCommand is `rpmgr ca new-root`: the rotation of the root by cross-signing (docs/04-security.md,
// "Root rotation").
func newRootCommand() *cli.Command {
	var csrOut, tokensOut string
	var abort, compromised, yes bool
	var tokenTTL time.Duration
	return localCommand("new-root", "rotate the root by cross-signing, or replace a compromised one: make the new root and its intermediate", func(fs *flag.FlagSet) {
		fs.BoolVar(&compromised, "compromised", false, "the root leaked: replace it within the trust domain with no cross-certificate, end every old CA key, revoke every certificate and "+
			"write a re-enrollment token per connector and gateway to --tokens-out; every agent must enroll again (a hard cut of the data plane). Needs every controller stopped")
		fs.StringVar(&tokensOut, "tokens-out", "", "with --compromised: the new file (mode 0600, never overwritten) that receives the re-enrollment tokens")
		fs.DurationVar(&tokenTTL, "token-ttl", 0, "with --compromised: how long the tokens last (default "+controller.DefaultCompromiseTokenTTL.String()+")")
		fs.BoolVar(&yes, "yes", false, "with --compromised: do not ask for the confirmation")
		fs.StringVar(&csrOut, "csr-out", "", "with an offline old root: write the request for the new root to this new file, and the one for the new intermediate to the file with the suffix "+controller.IntermediateSuffix+" (never overwritten)")
		fs.BoolVar(&abort, "abort", false, "give up a rotation that waits for the offline root's signatures and has not moved issuing: remove the new root and intermediate")
	}, func(ctx context.Context, env *cli.Env, path string) error {
		if compromised {
			if abort || csrOut != "" {
				return cli.Usagef("--compromised excludes --abort and --csr-out")
			}
			return replaceCompromised(ctx, env, path, tokensOut, tokenTTL, yes)
		}
		if tokensOut != "" || tokenTTL != 0 || yes {
			return cli.Usagef("--tokens-out, --token-ttl and --yes go with --compromised")
		}
		if abort {
			if csrOut != "" {
				return cli.Usagef("--abort and --csr-out exclude each other")
			}
			if _, err := controller.AbortNewRoot(ctx, path, time.Now); err != nil {
				return err
			}
			_, err := fmt.Fprintln(env.Stdout, "The new root and its intermediate are removed; the old root issues as before. The request files can be deleted: "+
				"a signature for them is not accepted any more. rpmgr ca new-root starts again.")
			return err
		}
		res, err := controller.NewRoot(ctx, path, csrOut, env.Getenv, time.Now)
		if err != nil {
			return err
		}
		if r := res.Requests; r != nil {
			_, err = fmt.Fprintf(env.Stdout, "Wrote the request for the new root to %[1]s (key SHA-256 %[2]s) and the one for the new intermediate to %[1]s%[4]s (key SHA-256 %[3]s).\n"+
				"Carry both to the offline host and sign them with the old root:\n"+
				"  rpmgr ca sign-intermediate --kind cross-root --csr %[1]s --key-sha256 %[2]s --root-file <file> --out <x.crt>\n"+
				"  rpmgr ca sign-intermediate --csr %[1]s%[4]s --key-sha256 %[3]s --root-file <file> --out <y.crt>\n"+
				"then bring both certificates back and run rpmgr ca import-intermediate --in <file> for each. Issuing moves to the new root within\n"+
				"the hour after both are imported (the rotation job); rpmgr ca status shows where the rotation stands.\n"+
				"The new root's key is online (sealed) until you take it offline again: once issuing has moved, run rpmgr ca offline-root.\n",
				csrOut, r.CrossKeyHash, r.InterKeyHash, controller.IntermediateSuffix)
			return err
		}
		_, err = fmt.Fprintf(env.Stdout, "The new root issues from now on; the old root stays in the trust bundle until the overlap has passed.\n"+
			"New root pin (use it only after the old root is dropped): %s\n"+
			"Until the old root is dropped, install commands and rpmgr ca status keep showing the old pin: an agent enrolled meanwhile holds both roots.\n"+
			"Running controllers load it within a minute and send every agent the bundle in a snapshot; rpmgr ca status lists the agents that\n"+
			"have not learned the new root, and the date the old one can be dropped (rpmgr ca drop-root, or the rotation job).\n", res.Pin)
		return err
	})
}

// dropRootCommand is `rpmgr ca drop-root`.
func dropRootCommand() *cli.Command {
	var force, strand, yes bool
	return localCommand("drop-root", "drop the old root of a rotation from the trust bundle", func(fs *flag.FlagSet) {
		fs.BoolVar(&force, "force", false, "drop before the overlap has passed; accepted only while no enabled agent lacks the new root, "+
			"counting every one seen within the longest a leaf and the Reauth grace reach back, so one that was offline across the switch counts too")
		fs.BoolVar(&strand, "strand-stragglers", false, "after the overlap, drop the old root although enabled agents still lack the new one; they have to re-enroll, and it asks first")
		fs.BoolVar(&yes, "yes", false, "do not ask for the confirmation --strand-stragglers needs")
	}, func(ctx context.Context, env *cli.Env, path string) error {
		if force && strand {
			return cli.Usagef("--force and --strand-stragglers exclude each other")
		}
		if strand && !yes {
			st, err := controller.CARotationStatus(ctx, path, time.Now)
			if err != nil {
				return err
			}
			fmt.Fprintf(env.Stdout, "%d enabled agent(s) seen since the switch do not hold the new root: %s\n"+
				"Dropping the old root strands them: they cannot connect again until they are re-enrolled.\n",
				len(st.Stragglers), strings.Join(st.Stragglers, ", "))
			ok, err := confirmPrompt("Drop the old root anyway")
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("the old root was not dropped: not confirmed")
			}
		}
		res, err := controller.DropRoot(ctx, path, force, strand, time.Now)
		var early *castore.DropEarlyError
		if errors.As(err, &early) {
			return fmt.Errorf("%w (--force drops earlier, but only while no enabled agent seen within the longest a leaf and the Reauth grace reach back lacks the new root)", err)
		}
		if err != nil {
			return err
		}
		if _, err = fmt.Fprintln(env.Stdout, "The old root is dropped: the bundle is the new root alone. Running controllers load it within a minute and send every agent\n"+
			"a snapshot that carries it; certificates under the old root stop verifying."); err != nil {
			return err
		}
		if n := len(res.Stranded); n > 0 {
			fmt.Fprintf(env.Stdout, "Stranded, to re-enroll: %d enabled agent(s): %s\n", n, strings.Join(res.Stranded, ", "))
		}
		if n := len(res.Disabled); n > 0 {
			fmt.Fprintf(env.Stdout, "Warning: %d disabled agent(s) do not hold the new root and have to re-enroll before they can connect again: %s\n",
				n, strings.Join(res.Disabled, ", "))
		}
		return nil
	})
}

// onlineRootWarning is what `ca status` says while the root that issues is online although the deployment
// had an offline root, as a rotation leaves it.
const onlineRootWarning = "WARNING: issuing root online: the new root's key is in the database. Once issuing has moved, take it offline " +
	"again with rpmgr ca offline-root (docs/10-operations.md, \"Rotate the root\")."

// rotationText is what `ca status` says during a root rotation, and while the new root of one that had an
// offline root is still online; empty when neither holds.
func rotationText(st controller.RotationStatus) string {
	text := rotationBody(st)
	switch {
	case !st.IssuingRootOnline:
		return text
	case text == "":
		return onlineRootWarning
	}
	return text + "\n" + onlineRootWarning
}

// rotationBody is the part of rotationText about the rotation itself.
func rotationBody(st controller.RotationStatus) string {
	text := rotationProgress(st)
	if st.IntermediateExpiring {
		text += "\n  WARNING: the active intermediate expires on " + st.IntermediateExpires.UTC().Format(time.RFC3339) +
			" and cannot be rotated during a root rotation: finish this one" + abortHint(st) + "."
	}
	return text
}

// abortHint names the way out of a rotation that has not moved issuing.
func abortHint(st controller.RotationStatus) string {
	if st.Waiting {
		return ", or give it up with rpmgr ca new-root --abort"
	}
	return ""
}

// rotationProgress is where the rotation stands.
func rotationProgress(st controller.RotationStatus) string {
	if !st.Waiting && !st.Overlap {
		return ""
	}
	var b strings.Builder
	if !st.Overlap {
		b.WriteString("Root rotation: the new root waits for the old root's signatures (rpmgr ca new-root --abort gives it up).")
		if st.NeedsCross {
			b.WriteString(" The cross-certificate of the new root is missing (rpmgr ca sign-intermediate --kind cross-root, then rpmgr ca import-intermediate).")
		}
		if st.NeedsInter {
			b.WriteString(" The certificate of the new intermediate is missing (rpmgr ca sign-intermediate, then rpmgr ca import-intermediate).")
		}
		if !st.NeedsCross && !st.NeedsInter {
			b.WriteString(" Both are imported; the rotation job moves issuing to the new root within the hour.")
		}
		b.WriteString("\n  Key SHA-256 of the requests: " + strings.Join(st.KeyHashes, ", "))
		return b.String()
	}
	fmt.Fprintf(&b, "Root rotation: issuing moved to the new root on %s; the old root stays in the trust bundle and can be dropped from %s.",
		st.IssuingSince.UTC().Format(time.RFC3339), st.DropAfter.UTC().Format(time.RFC3339))
	for _, r := range st.Roots {
		role := "old, still trusted"
		if r.Issuing {
			role = "issuing"
		}
		fmt.Fprintf(&b, "\n  Root %s (%s), valid until %s", r.Pin, role, r.NotAfter.UTC().Format("2006-01-02"))
	}
	if n := len(st.Stragglers); n > 0 {
		fmt.Fprintf(&b, "\n  %d enabled agent(s) seen since do not hold the new root: %s\n"+
			"  Update them, re-enroll them or decommission them; rpmgr ca drop-root --strand-stragglers drops the old root all the same.",
			n, strings.Join(st.Stragglers, ", "))
	} else {
		b.WriteString("\n  Every enabled agent seen since holds the new root.")
	}
	if n := len(st.Disabled); n > 0 {
		fmt.Fprintf(&b, "\n  Warning: %d disabled agent(s) do not hold the new root and will have to re-enroll before they connect again: %s",
			n, strings.Join(st.Disabled, ", "))
	}
	return b.String()
}

// replaceCompromised is `rpmgr ca new-root --compromised` (docs/04-security.md, "Root compromise").
func replaceCompromised(ctx context.Context, env *cli.Env, path, tokensOut string, ttl time.Duration, yes bool) error {
	if tokensOut == "" {
		return cli.Usagef("--compromised needs --tokens-out <file>: the tokens are how the agents enroll again")
	}
	if !yes {
		fmt.Fprintln(env.Stdout, "This replaces the root with a new one in the same trust domain and ends the old one: every certificate is revoked, so every\n"+
			"connector and gateway stops until it has enrolled again with the new pin and its token. Public traffic stops with the gateways.\n"+
			"Stop the agents you can reach first, and every controller must be stopped (rpmgr ca new-root --compromised refuses otherwise).")
		ok, err := confirmPrompt("Replace the compromised root")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("the root was not replaced: not confirmed")
		}
	}
	res, err := controller.ReplaceCompromisedRoot(ctx, controller.CompromiseOptions{ConfigPath: path, TokensOut: tokensOut, TokenTTL: ttl,
		Getenv: env.Getenv, Now: time.Now})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(env.Stdout, "The root is replaced. %d CA keys ended, %d certificates revoked, %d unused enrollment tokens invalidated.\n"+
		"Wrote %d re-enrollment tokens (%d connectors, %d gateways) to %s, one single-use token per line with its agent; %d agents (all-in-one's own, ephemeral connectors) have none.\n"+
		"New --ca-pin: %s\n"+
		"Start the controller, then enroll every agent, gateways first: rpmgr enroll --controller <url> --ca-pin <new pin> --token-file <its token> --replace\n"+
		"Then investigate how the KEK and the database were exposed, and rotate the KEK. Delete %s when the agents have enrolled.\n",
		res.Keys, res.Certificates, res.InvalidatedTokens, res.Connectors+res.Gateways, res.Connectors, res.Gateways, tokensOut, res.Skipped, res.Pin, tokensOut)
	for _, w := range res.Warnings {
		fmt.Fprintln(env.Stdout, "Warning: "+w)
	}
	return err
}
