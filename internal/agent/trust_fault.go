// SPDX-License-Identifier: Apache-2.0

//go:build !rpmgrtest

package agent

// rootsFault is the fault point of the write of roots.pem; it is a no-op outside rpmgrtest builds.
func rootsFault(string) error { return nil }
