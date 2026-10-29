// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package controller

import "io/fs"

// ownLike does nothing where files have no Unix owners.
func ownLike(string, string) error { return nil }

// giveTo does nothing where files have no Unix owners.
func giveTo(string, string) error { return nil }

// ownedByCaller: files have no Unix owners here.
func ownedByCaller(fs.FileInfo) bool { return true }
