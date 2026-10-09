// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package controller

// ownLike does nothing where files have no Unix owners.
func ownLike(string, string) error { return nil }
