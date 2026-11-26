// SPDX-License-Identifier: Apache-2.0

//go:build !rpmgrtest

package controller

// fault is where a test makes the ceremony fail (faults_rpmgrtest.go); a release build has none.
func fault(string, string) error { return nil }
