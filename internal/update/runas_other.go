// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package update

import (
	"context"
	"errors"
	"io"
)

// OwnerOf is not available where files have no Unix owners.
func OwnerOf(string) (uint32, uint32, error) {
	return 0, 0, errors.New("update: not available on this platform")
}

func runAs(context.Context, uint32, uint32, io.Writer, string, ...string) ([]byte, error) {
	return nil, errors.New("update: not available on this platform")
}
