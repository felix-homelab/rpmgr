// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
)

// DefaultCompromiseTokenTTL is how long the re-enrollment tokens of a replaced root last unless the
// operator says otherwise (docs/04-security.md, "Root compromise"); the longest is enroll.MaxTokenTTL.
const DefaultCompromiseTokenTTL = 7 * 24 * time.Hour

// CompromiseOptions are the inputs of ReplaceCompromisedRoot.
type CompromiseOptions struct {
	ConfigPath string
	// TokensOut is the new file the re-enrollment tokens are written to, mode 0600; an existing one is never
	// overwritten.
	TokensOut string
	// TokenTTL is how long the tokens last; zero is DefaultCompromiseTokenTTL.
	TokenTTL time.Duration
	Getenv   func(string) string
	Now      func() time.Time
}

// CompromiseResult is what `rpmgr ca new-root --compromised` reports. It holds no token.
type CompromiseResult struct {
	Pin          string
	Keys         int // CA keys ended
	Certificates int // certificates revoked
	// InvalidatedTokens are the enrollment tokens that were unused and are invalid now.
	InvalidatedTokens int
	Connectors        int // tokens written, one per connector ...
	Gateways          int // ... and per gateway
	// Skipped are the agents with no token: all-in-one's own, and ephemeral connectors, which enroll anew.
	Skipped int
	// Warnings say what the run could not finish after it committed.
	Warnings []string
}

// ReplaceCompromisedRoot is `rpmgr ca new-root --compromised`: it replaces a root that leaked by a new one in
// the same trust domain, with no cross-certificate, in one configuration transaction (castore.CompromisePlan)
// that also writes the re-enrollment token of every connector and gateway to o.TokensOut, appends the audit
// entry of every audit chain, anchors the chains with checkpoints of the new key, and logs the
// `root_compromised` markers last. It needs the KEK and refuses while a controller runs (ErrStopController).
// The tokens file is written inside the transaction, before its commit: if the transaction fails, the file
// is removed and nothing else changed, and the file is never present without its tokens being valid. The
// keys are sealed before the transaction.
func ReplaceCompromisedRoot(ctx context.Context, o CompromiseOptions) (CompromiseResult, error) {
	var res CompromiseResult
	if o.Now == nil {
		o.Now = time.Now
	}
	ttl := o.TokenTTL
	switch {
	case o.TokensOut == "":
		return res, errors.New("controller: --tokens-out <file> is needed: the tokens are the way the agents enroll again")
	case ttl == 0:
		ttl = DefaultCompromiseTokenTTL
	case ttl < 0 || ttl > enroll.MaxTokenTTL:
		return res, enroll.ErrTokenTTL
	}
	cfg, err := loadController(o.ConfigPath)
	if err != nil {
		return res, err
	}
	kek, err := localWrapper(ctx, cfg, o.Getenv)
	if err != nil {
		return res, err
	}
	sealer, err := secret.NewSealerWith(kek.Wrapper)
	if err != nil {
		return res, err
	}
	if err := mustNotExist(o.TokensOut); err != nil {
		return res, err
	}
	unlock, err := store.HoldLock(cfg.Database.DSN)
	if errors.Is(err, store.ErrLocked) {
		return res, ErrStopController
	}
	if err != nil {
		return res, err
	}
	defer func() { _ = unlock() }()
	_, db, sys, err := openLocal(ctx, o.ConfigPath, "rpmgr ca new-root --compromised")
	if err != nil {
		return res, err
	}
	defer func() { _ = db.Close() }()
	rl, err := openRevLog(cfg, o.Now)
	if err != nil {
		return res, err
	}
	now := o.Now()
	// Planned and sealed before the transaction: sealing may wait for a key service.
	plan, err := castore.PlanCompromisedRoot(sys, db.ReadClient().CAKey, sealer, now)
	if err != nil {
		return res, err
	}
	if err := fault("planned", o.TokensOut); err != nil {
		return res, err
	}
	var cps []audit.Checkpoint
	var created, marked bool
	newHash := pki.PublicKeyHash(plan.NewRoot().RawSubjectPublicKeyInfo)
	_, err = store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
		created, marked, res = false, false, CompromiseResult{}
		applied, err := plan.Apply(sys, tx)
		if err != nil {
			return nil, err
		}
		res.Keys, res.Certificates, res.InvalidatedTokens = applied.Keys, applied.Certificates, applied.Tokens
		lines, err := mintReEnrollment(sys, tx, ttl, now, &res)
		if err != nil {
			return nil, err
		}
		file := "# rpmgr re-enrollment tokens of " + now.UTC().Format(time.RFC3339) + ", each single-use and valid for " + ttl.String() + ".\n" +
			"# role, org, id, name, token (tab-separated); keep the file private and delete it when the agents have enrolled.\n" +
			strings.Join(lines, "\n") + "\n"
		if err := writeNew(o.TokensOut, []byte(file), 0o600); err != nil {
			// A write that failed partway leaves a file of ours; one that exists already is not ours to remove.
			if !errors.Is(err, os.ErrExist) {
				_ = os.Remove(o.TokensOut)
			}
			return nil, err
		}
		created = true
		if err := fault("written", o.TokensOut); err != nil {
			return nil, err
		}
		if cps, err = anchorAuditChains(sys, tx, plan, now, res); err != nil {
			return nil, err
		}
		if err := fault("before-marker", o.TokensOut); err != nil {
			return nil, err
		}
		// From here on a marker may be in the log even if the append or the commit fails: a restore of an
		// archive older than the replacement refuses either way, and a current one refuses until the command
		// has run again.
		marked = true
		for _, h := range plan.Replaced() {
			if err := markRoot(rl, revlog.RootCompromised, h, newHash, "local-cli"); err != nil {
				return nil, err
			}
		}
		if err := fault("appended", o.TokensOut); err != nil {
			return nil, err
		}
		return []string{"pki"}, fault("commit", o.TokensOut)
	})
	switch {
	case errors.Is(err, castore.ErrRotated):
		err = fmt.Errorf("controller: the CA's keys changed while the replacement was planned, so nothing was replaced: look at `rpmgr ca status` and run the command again: %w", err)
	case err != nil && marked:
		err = fmt.Errorf("controller: the replacement did not commit, so the old root is still the CA's and nothing changed in the database; its marker "+
			"is in the revocation log, so a restore of a backup of this controller refuses until you run the command again: %w", err)
	}
	if err != nil {
		if created {
			// The tokens were never valid: the transaction rolled back.
			_ = os.Remove(o.TokensOut)
		}
		return CompromiseResult{}, err
	}
	res.Pin = pki.RootPin(plan.NewRoot())
	res.Warnings = appendCheckpointLog(filepath.Join(filepath.Dir(cfg.Database.DSN), BackupCheckpoints), cps)
	return res, nil
}

// mintReEnrollment mints, in tx, one single-use token for each connector and gateway that is not
// decommissioned, built in or ephemeral, bound to it so that the host cannot choose which identity it
// replaces, and returns one line each for the tokens file. It counts them in res.
func mintReEnrollment(ctx context.Context, tx *ent.Tx, ttl time.Duration, now time.Time, res *CompromiseResult) ([]string, error) {
	var lines []string
	mint := func(role, org, id, name string, m enroll.Mint) error {
		m.Org, m.CreatedBy, m.TTL = org, "local-cli", ttl
		tok, _, err := enroll.MintToken(ctx, tx, m, now)
		if err != nil {
			return fmt.Errorf("controller: the token of %s %s: %w", role, id, err)
		}
		lines = append(lines, strings.Join([]string{role, org, id, name, tok}, "\t"))
		return nil
	}
	gws, err := tx.Gateway.Query().Where(gateway.DecommissionedAtIsNil()).Order(ent.Asc(gateway.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range gws {
		if g.BuiltIn {
			res.Skipped++
			continue
		}
		if err := mint("gateway", g.OrgID, g.ID, g.Name, enroll.Mint{GatewayID: g.ID}); err != nil {
			return nil, err
		}
		res.Gateways++
	}
	cons, err := tx.Connector.Query().Where(connector.DecommissionedAtIsNil()).Order(ent.Asc(connector.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range cons {
		if c.BuiltIn || c.Ephemeral {
			res.Skipped++
			continue
		}
		if err := mint("connector", c.OrgID, c.ID, c.Name, enroll.Mint{ConnectorID: c.ID}); err != nil {
			return nil, err
		}
		res.Connectors++
	}
	return lines, nil
}

// anchorAuditChains records the replacement in every audit chain that has entries, and in the instance
// chain, and signs a checkpoint of each with the new key. The seq of an entry is the cutoff that the
// checkpoints under the replaced roots are held to (audit.Compromise), and the new checkpoint covers
// everything up to it, so that history before the replacement stays anchored under a key that did not leak.
func anchorAuditChains(ctx context.Context, tx *ent.Tx, plan *castore.CompromisePlan, now time.Time, res CompromiseResult) ([]audit.Checkpoint, error) {
	heads, err := audit.Heads(ctx, tx)
	if err != nil {
		return nil, err
	}
	orgs := []string{""} // the instance chain, always
	for chain := range heads {
		if o := audit.OrgOf(chain); o != "" {
			orgs = append(orgs, o)
		}
	}
	reason := fmt.Sprintf("the root was replaced as compromised: %d CA keys ended, %d certificates revoked, %d unused enrollment tokens invalidated",
		res.Keys, res.Certificates, res.InvalidatedTokens)
	for _, org := range orgs {
		if _, err := audit.AnchorCompromise(ctx, tx, org, plan.Replaced(), reason); err != nil {
			return nil, err
		}
	}
	return audit.WriteCheckpoints(ctx, tx, plan.AuditSigner(), now, audit.Pending)
}

// appendCheckpointLog adds the checkpoints to the local log after the commit; a failure is a warning, as the
// database holds them and the job's next run is not affected.
func appendCheckpointLog(path string, cps []audit.Checkpoint) []string {
	if len(cps) == 0 {
		return nil
	}
	if err := (&audit.CheckpointLog{Path: path}).Append(cps); err != nil {
		return []string{fmt.Sprintf("the checkpoints that anchor the audit chains are in the database but not in %s: %v", path, err)}
	}
	return nil
}

// notEnrolledAgain is the warning of `rpmgr ca status` after a root was replaced as compromised: the
// connectors and gateways, other than all-in-one's own and ephemeral connectors, that hold no certificate
// that is neither revoked nor expired, so have not enrolled again; "" when none, or no replacement.
func notEnrolledAgain(ctx context.Context, db *store.DB, now time.Time) (string, error) {
	c := db.ReadClient()
	root, err := c.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusCompromised)).
		Order(ent.Desc(cakey.FieldRotatedAt)).First(ctx)
	if ent.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	holders, err := c.IssuedCertificate.Query().Where(issuedcertificate.RevokedAtIsNil(), issuedcertificate.NotAfterGT(now)).
		Select(issuedcertificate.FieldSubjectID).Strings(ctx)
	if err != nil {
		return "", err
	}
	enrolled := map[string]bool{}
	for _, id := range holders {
		enrolled[id] = true
	}
	var waiting []string
	gws, err := c.Gateway.Query().Where(gateway.DecommissionedAtIsNil(), gateway.BuiltIn(false)).Order(ent.Asc(gateway.FieldID)).All(ctx)
	if err != nil {
		return "", err
	}
	for _, g := range gws {
		if !enrolled[g.ID] {
			waiting = append(waiting, g.ID)
		}
	}
	cons, err := c.Connector.Query().Where(connector.DecommissionedAtIsNil(), connector.BuiltIn(false), connector.Ephemeral(false)).
		Order(ent.Asc(connector.FieldID)).All(ctx)
	if err != nil {
		return "", err
	}
	for _, k := range cons {
		if !enrolled[k.ID] {
			waiting = append(waiting, k.ID)
		}
	}
	if len(waiting) == 0 {
		return "", nil
	}
	shown := waiting
	if len(shown) > maxAuditedAgents {
		shown = shown[:maxAuditedAgents]
	}
	since := ""
	if root.RotatedAt != nil {
		since = " on " + root.RotatedAt.UTC().Format(time.RFC3339)
	}
	more := ""
	if len(waiting) > len(shown) {
		more = fmt.Sprintf(" and %d more", len(waiting)-len(shown))
	}
	return fmt.Sprintf("the root was replaced as compromised%s and %d connector(s) and gateway(s) have not enrolled again: %s%s", since, len(waiting),
		strings.Join(shown, ", "), more), nil
}
