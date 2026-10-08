// SPDX-License-Identifier: Apache-2.0

package pki

// Exported for the tests that build certificate requests an agent's code never would.
var (
	ReadBinding = readBinding
	NewCSR      = newCSR
	SignRequest = signRequest
	// ReplaceIntermediate is the step both rotations share, for a test of two at once.
	ReplaceIntermediate = replaceIntermediate
)
