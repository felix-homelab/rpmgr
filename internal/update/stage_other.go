// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package update

import "errors"

// staged is the agent's staging directory; only Linux has the root updater (D29).
type staged struct{}

func openStaged(string) (*staged, error) {
	return nil, errors.New("update: the root updater runs on Linux only")
}

func (*staged) Close() error { return nil }

func (*staged) read(string, int64) ([]byte, error) { return nil, errors.ErrUnsupported }

func (*staged) copy(string, string, int64) error { return errors.ErrUnsupported }
