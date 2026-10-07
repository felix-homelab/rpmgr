// SPDX-License-Identifier: Apache-2.0

package audit

// Exported for the tests that forge entries the way an attacker with database access would.
var (
	ChainHash = chainHash
	Genesis   = genesis
	Canonical = canonical
)
