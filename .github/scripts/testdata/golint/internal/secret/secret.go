// Package secret mimics rpmgr's secret.Value, whose Reveal is allowed only in listed packages.
package secret

// Value holds a secret.
type Value struct{ v string }

// New wraps s.
func New(s string) Value { return Value{v: s} }

// Reveal returns the secret.
func (v Value) Reveal() string { return v.v }

// Length may call Reveal: this package is on the allow-list.
func Length(v Value) int { return len(v.Reveal()) }
