// SPDX-License-Identifier: Apache-2.0

package tunnel

// WithMaxStreams lowers the connector's stream limit, for tests.
func WithMaxStreams(w H2Windows, n int) H2Windows {
	w.maxStreams = n
	return w
}
