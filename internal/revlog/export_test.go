// SPDX-License-Identifier: Apache-2.0

package revlog

import "testing"

// SetMaxListPages shortens the page limit of an S3 listing for one test.
func SetMaxListPages(t testing.TB, n int) {
	old := maxListPages
	maxListPages = n
	t.Cleanup(func() { maxListPages = old })
}
