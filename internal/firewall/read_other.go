// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package firewall

import "errors"

// readChecked is unavailable here: the helper runs on Linux hosts only.
func readChecked(string, int64, bool, uint32) ([]byte, error) {
	return nil, errors.New("firewall: the helper runs on Linux hosts only")
}
