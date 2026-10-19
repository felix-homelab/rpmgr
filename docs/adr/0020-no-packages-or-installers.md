# ADR-0020: rpmgr ships no OS packages or installers, for now

Status: Accepted (decided by the product owner, D99, 2026-10-19) · Date: 2026-10-19 · Supersedes
the package-install clause and the Windows and macOS installers of [ADR-0013](0013-signed-ota.md)

## Context

- **The plan.** [ADR-0013](0013-signed-ota.md) and the documents planned for Phase 2:
  - `.deb` and `.rpm` packages for high-assurance Linux installs, built with nfpm, served from a
    signed apt/yum repository on GitHub Pages, and updated by the package manager instead of OTA.
    The updater was to refuse to replace a binary that a package owns, because the next package
    run would revert it;
  - a Homebrew tap for macOS connectors and winget/MSI for Windows connectors, which also updated
    them until OTA reaches those platforms in Phase 3
    ([D29](../14-open-decisions.md#project-and-process)).
- **One more channel each.** Every package or installer is a channel to build, sign, test on its
  platform and keep current: a repository with its own key, a tap, a winget manifest, an MSI with
  its signing. A Linux package also stays outside the controller's staged rollout, beside the
  install scripts that already install every Linux role.
- **What already covers the need.** The install scripts verify every download against the root
  keys compiled into the release ([04](../04-security.md#install-scripts)). A release download can
  be verified by hand, with its signed manifest and `gh attestation verify`
  ([04](../04-security.md#release-signing)). The OCI image serves containers
  ([10](../10-operations.md#install-paths)).
- **One maintainer** ([D26](../14-open-decisions.md#project-and-process)) keeps every channel that
  ships.

## Decision

**No OS packages or installers, for now**
- rpmgr publishes no `.deb` or `.rpm` package, runs no apt or yum repository, and publishes no
  Homebrew tap, no winget manifest and no MSI.
- Linux hosts install with the global or the controller-hosted install script, the OCI image, or
  a verified release download ([10](../10-operations.md#install-paths)).
- Windows and macOS connectors (Phase 2) are installed and updated by hand from the verified
  release download, until OTA reaches them in Phase 3
  ([10](../10-operations.md#windows-and-macos-connectors-phase-2)).
- A package or installer comes back only by a decision of its own.

**The updater**
- The updater replaces the binary at the path that `install.json` records. It has no case for a
  binary that a package manager owns, and the security regression test
  `TestOTA_PackageOwnedBinaryRefused` is removed ([10](../10-operations.md#hardened-systemd-units)).

## Consequences

**Positive**

- One install and update path per Linux host: the install scripts, then OTA or the global script's
  `--upgrade`.
- No repository, repository key, tap, winget manifest, MSI signing or packaging tests to keep.

**Negative**

- Hosts managed with apt, dnf, Homebrew or winget, or with configuration management built on them,
  get no native install or update path: Linux hosts run the install script, and their updates do
  not arrive with the system's.
- Windows and macOS connectors are updated only by hand until Phase 3.
- A high-assurance install has no package-manager trust path: it verifies the release by hand
  before running anything ([04](../04-security.md#install-scripts)).
- The updater does not recognise a binary that a third party packages. On a host where an rpmgr
  install script also ran, OTA replaces the binary at the recorded path, and the next package
  update may revert it.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| `.deb`, `.rpm`, Homebrew and winget/MSI in Phase 2 (ADR-0013, D29) | Four more channels to build, sign and keep current, for one maintainer |
| Drop the Linux packages, keep Homebrew and winget/MSI | Still two channels for platforms whose connectors are not released yet; the product owner dropped them for now (D99) |
| Packages attached to the release, without a repository | Still a package-owned binary beside OTA, and no updates through the package manager |
| Drop the packages, but keep the updater's refusal, for any binary that `install.json` does not record | It guards a case that rpmgr itself no longer creates; the product owner chose to drop it (D99) |
