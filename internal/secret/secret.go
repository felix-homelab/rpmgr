// SPDX-License-Identifier: Apache-2.0

// Package secret holds secrets so that they never reach a log, an error message or an API
// response by accident (docs/04-security.md, "Secrets at rest and in logs"). Only Reveal returns
// the value, and lint allows Reveal only in the packages listed in .golangci.yml.
package secret

import (
	"fmt"
	"log/slog"
)

// Redacted is what every textual form of a Value shows.
const Redacted = "[REDACTED]"

// Value holds a secret. The zero Value is an empty secret. Values are not comparable with ==.
//
// The secret is captured by an unexported function instead of being stored in a field: when fmt
// cannot call Value's methods (an unexported struct field, a bad verb), it falls back to
// reflection, which prints a function only as an address. A pointer or a byte slice would be
// printed with its contents.
type Value struct {
	get func() []byte
}

// New returns a Value holding s.
func New(s string) Value {
	b := []byte(s)
	return Value{get: func() []byte { return b }}
}

// FromBytes returns a Value holding a copy of b; later changes to b do not change the Value.
func FromBytes(b []byte) Value {
	c := append([]byte(nil), b...)
	return Value{get: func() []byte { return c }}
}

// Reveal returns the secret. Its use is restricted by lint; every caller is reviewed.
func (v Value) Reveal() string {
	if v.get == nil {
		return ""
	}
	return string(v.get())
}

// IsZero reports whether the secret is empty.
func (v Value) IsZero() bool { return v.get == nil || len(v.get()) == 0 }

// String returns Redacted.
func (v Value) String() string { return Redacted }

// GoString returns Redacted, so %#v shows no secret either.
func (v Value) GoString() string { return Redacted }

// Format writes Redacted for every verb and flag, including %x, %q and %+v.
func (v Value) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(Redacted))
}

// MarshalJSON encodes the Value as the string Redacted.
func (v Value) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText encodes the Value as Redacted, which also covers encoders that use text marshalling.
func (v Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue makes log/slog record Redacted.
func (v Value) LogValue() slog.Value { return slog.StringValue(Redacted) }
