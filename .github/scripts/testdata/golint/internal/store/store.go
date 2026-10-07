// Package store may use privacy.DecisionContext.
package store

import (
	"context"

	"github.com/felix-homelab/rpmgr/internal/privacy"
)

// Allow skips the privacy policies inside the store.
func Allow(ctx context.Context) context.Context { return privacy.DecisionContext(ctx, nil) }
