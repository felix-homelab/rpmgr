// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
)

// Link is a one-time link for the operator.
type Link struct {
	URL   string
	Valid string // how long it works
}

// ErrEmailNeeded is returned by ResetPasswordLink without an e-mail address once a user exists.
var ErrEmailNeeded = errors.New("controller: users exist; name one with --email")

// ResetPasswordLink creates, on the controller host, a one-time link that sets the password of the
// user with email, or, before any user exists and without email, the first-user link. It reads the
// controller's or all-in-one's boot file at path and needs no KEK; a running controller may hold
// the database meanwhile.
func ResetPasswordLink(ctx context.Context, path, email string) (Link, error) {
	var cfg config.Controller
	if err := config.Load(path, &cfg); err != nil {
		var a config.AllInOne
		if config.Load(path, &a) != nil {
			return Link{}, err
		}
		cfg = a.Controller()
	}
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		return Link{}, err
	}
	defer func() { _ = db.Close() }()
	sys, err := authz.System(ctx, "local-cli", "rpmgr user reset-password", audit.SystemScopes(db))
	if err != nil {
		return Link{}, err
	}
	acc := accounts.New(db, sys, nil)
	if email == "" {
		tok, err := acc.FirstUserLink("local-cli")
		if errors.Is(err, accounts.ErrHasUsers) {
			return Link{}, ErrEmailNeeded
		}
		if err != nil {
			return Link{}, err
		}
		return Link{URL: accounts.SetupURL(cfg.PublicURL, tok), Valid: "7 days, to create the first user"}, nil
	}
	norm, err := accounts.NormalizeEmail(email)
	if err != nil {
		return Link{}, err
	}
	u, err := db.Client().User.Query().Where(user.Email(norm)).Only(sys)
	if err != nil {
		return Link{}, fmt.Errorf("controller: no user %s: %w", norm, accounts.ErrNoUser)
	}
	tok, err := acc.ResetLink(u.ID, "local-cli")
	if err != nil {
		return Link{}, err
	}
	return Link{URL: accounts.LinkURL(cfg.PublicURL, tok), Valid: "24 hours"}, nil
}
