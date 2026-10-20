// SPDX-License-Identifier: Apache-2.0

package release

import "io"

// WrapWrites makes m wrap the writer of each file it keeps, as a full disk would fail it.
func WrapWrites(m *Mirror, wrap func(name string, w io.Writer) io.Writer) { m.wrap = wrap }
