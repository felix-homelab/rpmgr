# ADR-0020: rpmgr ships no Linux distribution packages

Status: Accepted (decided by the product owner, D99, 2026-10-19) · Date: 2026-10-19 · Supersedes
the package-install clause of [ADR-0013](0013-signed-ota.md)

## Context

- **The plan.** [ADR-0013](0013-signed-ota.md) and the documents planned `.deb` and `.rpm`
  packages for Phase 2, for high-assurance installs: built with nfpm, served from a signed apt/yum
  repository on GitHub Pages, and updated by the package manager instead of OTA. The updater was
  to refuse to replace a binary that a package owns, because the next package run would revert it.
- **Two ways to update one host.** A package install stays outside the controller's staged
  rollout, needs a repository with its own signing key, and needs its own tests on every supported
  distribution, beside the install scripts that already install every Linux role.
- **What already covers the need.** The install scripts verify every download against the root
  keys compiled into the release ([04](../04-security.md#install-scripts)). A release download can
  be verified by hand, with its signed manifest and `gh attestation verify`
  ([04](../04-security.md#release-signing)). The OCI image serves containers
  ([10](../10-operations.md#install-paths)).
- **One maintainer** ([D26](../14-open-decisions.md#project-and-process)) keeps every path that
  ships.

## Decision

**No Linux distribution packages**
- rpmgr publishes no `.deb` or `.rpm` package and runs no apt or yum repository. Linux hosts
  install with the global or the controller-hosted install script, the OCI image, or a verified
  release download ([10](../10-operations.md#install-paths)).
- The connectors for Windows and macOS keep winget/MSI and a Homebrew tap (Phase 2).

**The updater**
- The updater replaces the binary at the path that `install.json` records. It has no case for a
  binary that a package manager owns, and the security regression test
  `TestOTA_PackageOwnedBinaryRefused` is removed ([10](../10-operations.md#hardened-systemd-units)).

## Consequences

**Positive**

- One install and update path per Linux host: the install scripts, then OTA or the global script's
  `--upgrade`.
- No package repository, repository key or packaging tests to keep.

**Negative**

- Hosts managed with apt or dnf, or with configuration management built on them, get no native
  install or update path: they run the install script, and their updates do not arrive with the
  system's.
- A high-assurance install has no package-manager trust path: it verifies the release by hand
  before running anything ([04](../04-security.md#install-scripts)).
- The updater does not recognise a binary that a third party packages. On a host where an rpmgr
  install script also ran, OTA replaces the binary at the recorded path, and the next package
  update may revert it.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| `.deb` and `.rpm` from a signed repository in Phase 2 (ADR-0013) | A second install and update path, with a repository and its key, for one maintainer |
| Packages attached to the release, without a repository | Still a package-owned binary beside OTA, and no updates through the package manager |
| Drop the packages, but keep the updater's refusal, for any binary that `install.json` does not record | It guards a case that rpmgr itself no longer creates; the product owner chose to drop it (D99) |
