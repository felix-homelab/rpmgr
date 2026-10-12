// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package secret

import "io/fs"

// ownGroup reports whether a file belongs to this process's group; without Unix groups, never.
func ownGroup(fs.FileInfo) bool { return false }
