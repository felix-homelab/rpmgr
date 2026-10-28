// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package handoff

import "fmt"

// Inherited returns nil after a plain start; a hand-off is refused here: Windows and macOS
// restart without one.
func Inherited(getenv func(string) string) (*Handoff, error) {
	if getenv(Env) == "" {
		return nil, nil
	}
	return nil, fmt.Errorf("%w: %w", ErrRefused, ErrUnsupported)
}

// Notify does nothing here: there is no systemd.
func Notify(func(string) string) error { return nil }

func notify(string, string) error { return nil }

func closeFD(int) {}
