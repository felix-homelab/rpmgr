// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package store

import "errors"

// lockFile is not available: the controller runs on Linux (and macOS for development only).
func lockFile(string) (func() error, error) {
	return nil, errors.New("store: the controller lock needs Linux or macOS")
}
