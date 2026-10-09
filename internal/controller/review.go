// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/instance"
	entorg "github.com/felix-homelab/rpmgr/internal/store/ent/org"
)

// ErrNoReview is returned by ConfirmRestore for an instance or org that is not in restore review.
var ErrNoReview = errors.New("controller: not in restore review")

// ConfirmRestore is `rpmgr restore confirm` on the controller host: the Instance Admin ends the
// instance-wide restore review, or with org, an org's ID or slug, confirms that org for its Owner
// (docs/10-operations.md, "Backup and restore"). No API call ends the instance-wide review: the
// restored Owners and Instance Admins are what is in doubt. It runs beside the controller and
// returns the slugs of the orgs still in review.
func ConfirmRestore(ctx context.Context, path, org string) ([]string, error) {
	cfg, err := loadController(path)
	if err != nil {
		return nil, err
	}
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	sys, err := authz.System(ctx, "local-cli", "rpmgr restore confirm", audit.SystemScopes(db))
	if err != nil {
		return nil, err
	}
	var pending []string
	err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
		e := audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Result: audit.Success}
		if org == "" {
			n, err := tx.Instance.Update().Where(instance.RestoreReviewSinceNotNil()).ClearRestoreReviewSince().Save(sys)
			if err != nil || n == 0 {
				return errors.Join(err, errIf(n == 0, fmt.Errorf("%w: the instance", ErrNoReview)))
			}
			e.Action, e.TargetType, e.TargetID, e.Reason = "instance.restore_review_end", "instance", "1", "ended on the controller host"
		} else {
			o, err := tx.Org.Query().Where(entorg.Or(entorg.ID(org), entorg.Slug(org))).Only(sys)
			if ent.IsNotFound(err) {
				return fmt.Errorf("controller: no org %q", org)
			}
			if err != nil {
				return err
			}
			if o.RestoreReviewSince == nil {
				return fmt.Errorf("%w: the org %s", ErrNoReview, o.Slug)
			}
			if err := tx.Org.UpdateOne(o).ClearRestoreReviewSince().Exec(sys); err != nil {
				return err
			}
			e.OrgID, e.Action, e.TargetType, e.TargetID, e.Reason = o.ID, "org.restore_review_confirm", "org", o.ID, "confirmed on the controller host"
		}
		if _, err := audit.Append(sys, tx, e); err != nil {
			return err
		}
		left, err := tx.Org.Query().Where(entorg.RestoreReviewSinceNotNil()).Order(ent.Asc(entorg.FieldSlug)).All(sys)
		for _, o := range left {
			pending = append(pending, o.Slug)
		}
		return err
	})
	return pending, err
}
