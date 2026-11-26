// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package controller

// CeremonyFault, when set, is called at the stages of `rpmgr ca offline-root` ("planned", "written",
// "before-marker", "appended", "commit") with the output path; an error it returns fails the stage.
// `rpmgr ca rotate-intermediate --csr-out` calls it with "planned" after each plan, before its
// transaction, which is where a test makes another writer come first.
var CeremonyFault func(stage, path string) error

func fault(stage, path string) error {
	if CeremonyFault == nil {
		return nil
	}
	return CeremonyFault(stage, path)
}
