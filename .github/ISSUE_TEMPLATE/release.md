---
name: Release
about: Checklist for cutting a release (maintainer only)
title: "Release vX.Y.Z"
labels: "type:release"
---

Process: `RELEASING.md`, section "Release process".

- [ ] Milestone `vX.Y.Z` closed or remaining issues moved
- [ ] `main` (or `release/X.Y`) green, including the last nightly run
- [ ] Benchmark matrix run on the reference testbed; no regression > 10 % against the last release
- [ ] `Unreleased` complete and checked against `git log --oneline --no-merges vPREVIOUS..HEAD`
- [ ] Upgrade notes for breaking changes and long migrations
- [ ] Release candidate tagged and tested: fresh install, upgrade from the previous minor with live traffic
- [ ] Release PR `chore(release): vX.Y.Z` merged on green CI
- [ ] Signed tag `vX.Y.Z` pushed; tag build reproducible, SBOM, provenance, signatures
- [ ] Release manifest signed with the current signing key; `seq`, `floor`, `channel` and artifact `variant`s checked
- [ ] GitHub release, container image tags and manifest published (v1.0.0: notes state whether an external security review took place)
- [ ] Staged rollout on the maintainer's homelab installation (canary) completed
- [ ] Patch from a maintenance branch: changelog section merged back into `main`
- [ ] Release announced; this issue closed
