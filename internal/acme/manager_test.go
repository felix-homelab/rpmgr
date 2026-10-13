// SPDX-License-Identifier: Apache-2.0

package acme_test

import (
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/acme"
)

// TestRetryWait: after one failure the wait is the first one, and each further failure doubles
// it, up to RetryMax and no further, however many failures follow; a shorter first wait doubles
// alike.
func TestRetryWait(t *testing.T) {
	for _, c := range []struct {
		failures    int
		first, want time.Duration
	}{
		{1, acme.RetryFirst, time.Minute},
		{2, acme.RetryFirst, 2 * time.Minute},
		{3, acme.RetryFirst, 4 * time.Minute},
		{9, acme.RetryFirst, 256 * time.Minute},
		{10, acme.RetryFirst, acme.RetryMax},
		{1000, acme.RetryFirst, acme.RetryMax},
		{1, time.Millisecond, time.Millisecond},
		{4, time.Millisecond, 8 * time.Millisecond},
	} {
		if got := acme.RetryWait(c.failures, c.first); got != c.want {
			t.Errorf("after %d failures from %s: %s, want %s", c.failures, c.first, got, c.want)
		}
	}
}
