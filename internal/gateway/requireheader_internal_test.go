// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"reflect"
	"testing"
)

// TestRequireHeaderPasses_ConstantTime is the constant-time clause of
// TestRequireHeader_StrippedAndConstantTime: a value is compared with every accepted hash through
// crypto/subtle, as many times whether it matches the first, the last or none, so the time taken
// tells a client nothing about which hash came close.
func TestRequireHeaderPasses_ConstantTime(t *testing.T) {
	if reflect.ValueOf(compareHashes).Pointer() != reflect.ValueOf(subtle.ConstantTimeCompare).Pointer() {
		t.Fatal("hashes are not compared with subtle.ConstantTimeCompare")
	}
	values := []string{"first-value-of-at-least-thirty-two-chars", "second-value-of-at-least-thirty-two-chars",
		"third-value-of-at-least-thirty-two-chars"}
	rule := RequireHeaderRule{Name: "X-Origin-Token"}
	for _, v := range values {
		rule.Sums = append(rule.Sums, sha256.Sum256([]byte(v)))
	}
	calls := 0
	compareHashes = func(x, y []byte) int { calls++; return subtle.ConstantTimeCompare(x, y) }
	t.Cleanup(func() { compareHashes = subtle.ConstantTimeCompare })
	for _, tc := range []struct {
		value string
		pass  bool
	}{{values[0], true}, {values[2], true}, {"a-wrong-value-of-at-least-thirty-two-characters", false}} {
		calls = 0
		if got := requireHeaderPasses([]RequireHeaderRule{rule}, http.Header{"X-Origin-Token": {tc.value}}); got != tc.pass {
			t.Errorf("%q: passes %t, want %t", tc.value, got, tc.pass)
		}
		if calls != len(values) {
			t.Errorf("%q: %d comparisons, want %d whatever matches", tc.value, calls, len(values))
		}
	}
	if requireHeaderPasses([]RequireHeaderRule{rule}, http.Header{}) {
		t.Error("a request without the header passed")
	}
	if !requireHeaderPasses(nil, http.Header{}) {
		t.Error("a route without rules refused a request")
	}
}
