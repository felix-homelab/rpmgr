// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package revlog

// Non-unix builds are not released (.github/scripts/check-build.sh), so a link is followed there.
const openExtra = 0
