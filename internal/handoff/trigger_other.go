// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package handoff

import "context"

// Start does nothing here.
func (t *Trigger) Start(context.Context) (stop func()) { return func() {} }

// WriteOutcome is not supported here.
func WriteOutcome(string, Outcome) error { return ErrUnsupported }

// ReadOutcome is not supported here.
func ReadOutcome(string) (Outcome, error) { return Outcome{}, ErrUnsupported }

// Signal is not supported here.
func Signal(int) error { return ErrUnsupported }
