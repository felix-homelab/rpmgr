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
	var csrOut string
	return localCommand("new-root", "rotate the root by cross-signing: make the new root and its intermediate", func(fs *flag.FlagSet) {
		fs.StringVar(&csrOut, "csr-out", "", "with an offline old root: write the request for the new root to this new file, and the one for the new intermediate to the file with the suffix "+controller.IntermediateSuffix+" (never overwritten)")
	}, func(ctx context.Context, env *cli.Env, path string) error {
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
				"the hour after both are imported (the rotation job); rpmgr ca status shows where the rotation stands.\n",
				csrOut, r.CrossKeyHash, r.InterKeyHash, controller.IntermediateSuffix)
			return err
		}
		_, err = fmt.Fprintf(env.Stdout, "The new root issues from now on; the old root stays in the trust bundle until the overlap has passed. New root pin: %s\n"+
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

// rotationText is what `ca status` says during a root rotation; empty when none runs.
func rotationText(st controller.RotationStatus) string {
	if !st.Waiting && !st.Overlap {
		return ""
	}
	var b strings.Builder
	if !st.Overlap {
		b.WriteString("Root rotation: the new root waits for the old root's signatures.")
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
