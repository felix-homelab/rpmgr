// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package controller

import "os"

func hardLinks(os.FileInfo) bool { return false }

func dirOwner(string) (uid, gid int, ok bool) { return 0, 0, false }

const openNoFollow = 0
