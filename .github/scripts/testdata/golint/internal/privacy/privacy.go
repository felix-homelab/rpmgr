// Package privacy mimics Ent's privacy package.
package privacy

import "context"

// DecisionContext mimics privacy.DecisionContext.
func DecisionContext(ctx context.Context, _ error) context.Context { return ctx }
