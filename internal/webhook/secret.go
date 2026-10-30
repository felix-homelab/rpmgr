// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// SecretPrefix starts every endpoint secret; the HMAC is keyed with the secret as shown, prefix
// included (docs/04-security.md, "Webhooks and the egress guard").
const SecretPrefix = "rpmgr_whs_" //nolint:gosec // G101: a prefix, not a credential

// NewSecret returns a new endpoint secret: the prefix and 256 random bits.
func NewSecret() (secret.Value, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return secret.Value{}, fmt.Errorf("webhook: a new secret: %w", err)
	}
	return secret.New(SecretPrefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}
