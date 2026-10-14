// SPDX-License-Identifier: Apache-2.0

package setup

import "testing"

// SetPolicyEdits replaces the edits of the connector-local policy for one test, which must not run
// in parallel with others.
func SetPolicyEdits(t testing.TB, allow, deny func(path, target string) (bool, error)) {
	oldAllow, oldDeny := allowTarget, denyTarget
	allowTarget, denyTarget = allow, deny
	t.Cleanup(func() { allowTarget, denyTarget = oldAllow, oldDeny })
}
