// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package gateway

import (
	"errors"
	"syscall"
)

// killProcess: there is no hand-off where there is no kill(2), so there is no old process.
func killProcess(int, syscall.Signal) error { return errors.New("gateway: no signals on this system") }
