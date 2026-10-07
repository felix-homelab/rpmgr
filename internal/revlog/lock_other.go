// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package revlog

import (
	"errors"
	"os"
)

// lock is not available: the controller runs on Linux (and macOS for development only).
func lock(*os.File) (func(), error) {
	return nil, errors.New("revlog: the revocation log needs Linux or macOS")
}
