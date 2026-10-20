// SPDX-License-Identifier: Apache-2.0

package pki

// Exported for the tests that build certificate requests an agent's code never would.
var (
	ReadBinding = readBinding
	NewCSR      = newCSR
	SignRequest = signRequest
)
