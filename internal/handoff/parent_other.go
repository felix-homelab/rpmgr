// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package handoff

import "context"

// Start is not supported here: Windows and macOS restart without a hand-off.
func Start(context.Context, Config, []Socket) (*Child, error) { return nil, ErrUnsupported }
