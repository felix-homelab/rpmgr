# Releasing rpmgr

How rpmgr is versioned, how the changelog is kept, and how a release is cut, published, supported
and, if necessary, withdrawn. Branch, commit and review rules are in
[CONTRIBUTING.md](CONTRIBUTING.md).

Nothing has been released yet: rpmgr is in its design phase. These rules apply from the first
tagged build on.

## Contents

- [Versioning](#versioning)
- [Tags](#tags)
- [Changelog](#changelog)
- [Release process](#release-process)
- [Patch releases](#patch-releases)
- [Maintenance branches](#maintenance-branches)
- [Supported versions](#supported-versions)
- [Security releases](#security-releases)
- [Withdrawing a release](#withdrawing-a-release)
- [Roles](#roles)

## Versioning

rpmgr has **one version** for the whole product: the `rpmgr` binary in every role, the container
images, the packages and the release manifest. It follows
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html): `MAJOR.MINOR.PATCH`.

| Bump | When | Examples |
|---|---|---|
| **MAJOR** | Upgrading needs action from users, or something they rely on stops working | Removing or changing a public API method or field, or removing an old API package (changes go into a new `rpmgr.v2` package, [07](docs/07-api.md#versioning-and-compatibility)); a new protocol major version in the ALPN ([03](docs/03-connections.md#versioning-and-capabilities)); a configuration key removed or renamed without automatic migration; dropping support for agents one minor behind; removing a feature; changing a default so existing installations behave differently |
| **MINOR** | Backwards-compatible additions | New features, route types, API fields and methods, a new API package next to the old one, settings with safe defaults; deprecations; database migrations |
| **PATCH** | Backwards-compatible fixes only | Bug and security fixes. No new features or settings, and no database migrations unless a security fix needs one |

- **Before 1.0.0** (`0.y.z`) a minor release may contain breaking changes; they are still marked
  as breaking in commits and the changelog. 1.0.0 is released at the end of Phase 2
  ([13](docs/13-roadmap.md#phase-2--production)).
- **Pre-releases** are `X.Y.Z-alpha.N`, `X.Y.Z-beta.N` and `X.Y.Z-rc.N`, with N counting from 1.
  After `rc.1` only fixes are merged for that release. Pre-releases are published with
  `"channel": "prerelease"` in their signed manifest; hosts on the default
  `update_channel: stable` refuse them, whatever the controller offers
  ([04](docs/04-security.md#release-signing)).
- The **public API package** (`rpmgr.v1`) and the **protocol major** (`rpmgr-tunnel/1`) have their
  own version numbers. A new protocol major changes only with a MAJOR release. A new API package
  (`rpmgr.v2`) may be **added** in a MINOR release and served next to `rpmgr.v1`; **removing**
  `rpmgr.v1` is a MAJOR release, at least two minor releases after `rpmgr.v2` appeared
  ([07](docs/07-api.md#versioning-and-compatibility)).
- Compatibility between controller and agents (N and N−1 of the same major) is defined in
  [10](docs/10-operations.md#upgrades-and-version-skew).

## Tags

- **Release tags** are `v` plus the version: `v1.4.2`, `v1.5.0-rc.1`. Inside artifacts and the
  release manifest the version has no `v` (`"version": "1.4.2"`).
- Release tags are **annotated and signed** (`git tag -s`), created on a commit of `main` or of a
  `release/<major>.<minor>` branch whose CI is green. The tag message is the version's changelog
  section.
- **Tags are immutable.** A tag is never moved or deleted, not even for a broken release; a broken
  release gets a new patch version ([Withdrawing a release](#withdrawing-a-release)).
- Release tooling accepts only tags that match the release pattern, so no other tag can trigger a
  release build:

  ```
  ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.[1-9][0-9]*)?$
  ```

- The only other tags are the archive tags `spike/sx` of Phase 0 spikes
  ([CONTRIBUTING.md](CONTRIBUTING.md#spikes)); they are immutable too and never trigger a build.

## Changelog

[CHANGELOG.md](CHANGELOG.md) at the repository root is the release history for the people who run
rpmgr or use its API. It follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

**Who writes it**

- The author of a PR adds its entry under `## [Unreleased]`, **in the same PR** as the change.
- A PR without a user-visible change carries the `no-changelog` label instead. CI fails a PR that
  neither changes `CHANGELOG.md` nor carries the label.
- When cutting a release, the maintainer only moves, groups and tidies entries.

**What goes in.** Everything a user notices: new features, changed behaviour, deprecations,
removals, fixes, security fixes, changed defaults, new required steps when upgrading. **What stays
out:** refactoring, tests, CI, internal tooling, design-document changes (their history is in git
and in the ADRs).

**Sections** per version, in this order, each only if it has entries:

| Section | For | Usual commit type |
|---|---|---|
| `### Added` | New features | `feat` |
| `### Changed` | Changes to existing behaviour or defaults | `feat`, `perf` |
| `### Deprecated` | Features that will be removed; name the version that removes them | `feat`, `refactor` |
| `### Removed` | Features removed in this version | `feat!` |
| `### Fixed` | Bug fixes | `fix` |
| `### Security` | Vulnerability fixes and security-relevant changes | `fix` |

**Entries**

- One bullet per change, written for a user: what changes for them, in the present tense. Start
  with the affected part when it helps (`Gateway:`, `Connector:`, `API:`, `UI:`, `CLI:`).
- End with the PR reference, e.g. `(#123)`. A change made in several PRs is one entry with all
  references.
- **Breaking changes** start with `**Breaking:**` and say what the user has to do.
- **Security** entries name the advisory or CVE, the severity and the affected versions.
- **Deprecated** entries name the version in which the feature is removed.
- English, with the same spelling rules as the documents
  ([CONTRIBUTING.md](CONTRIBUTING.md#writing-rules)).

Example:

```markdown
## [1.5.0] - 2027-05-04

### Added

- Gateway: `http` routes can require a client certificate. (#311)

### Changed

- **Breaking:** API: `ListRoutes` returns at most 500 routes per page; clients that relied on
  larger pages must follow `next_page_token`. (#320)

### Security

- Connector: a crafted `StreamOpen` could exhaust memory; fixed. GHSA-xxxx-xxxx-xxxx, high,
  affects 1.3.0–1.4.2. (#331)
```

**Versions and links**

- Version headings are `## [X.Y.Z] - YYYY-MM-DD`, the date of the tag in UTC.
- Sections are ordered by version, highest first. `## [Unreleased]` is always on top, even when
  it is empty.
- Pre-releases get no section of their own; their release notes are the `Unreleased` content at
  the time of the tag.
- Every version heading is a reference link, defined at the bottom of the file:
  `[Unreleased]: <repo>/compare/vX.Y.Z...HEAD` and `[X.Y.Z]: <repo>/compare/vPREVIOUS...vX.Y.Z`.
- A withdrawn version is marked `## [X.Y.Z] - YYYY-MM-DD [YANKED]` with a line saying why and
  which version to use instead.
- Released sections are not edited, except to fix mistakes or to mark a version yanked.

## Release process

For a minor or major release. A patch release is the same, starting from the branch described in
[Patch releases](#patch-releases).

1. **Open the release issue** from the *Release* issue template (`Release vX.Y.0`, label
   `type:release`). The issue holds this checklist.
2. **Check readiness.**
   - `main` is green, including the last nightly run: full end-to-end matrix, chaos tests, long
     fuzzing ([12](docs/12-testing-and-quality.md)).
   - The benchmark matrix has run on the reference testbed, with no regression of more than 10 %
     against the last release ([12](docs/12-testing-and-quality.md#benchmarks)).
   - Every issue in the `vX.Y.0` milestone is closed or moved out.
   - `Unreleased` is complete: compare it with `git log --oneline --no-merges vPREVIOUS..main`
     (every `feat` and `fix` commit maps to an entry or was labelled `no-changelog` deliberately).
   - Breaking changes and long-running database migrations have upgrade notes.
3. **Pre-release (recommended for minor and major releases).** Tag `vX.Y.0-rc.1` on `main`,
   publish it to the pre-release channel, and test:
   - a fresh install;
   - an upgrade from the latest release of the previous minor, with live traffic, in the upgrade
     order of [10](docs/10-operations.md#upgrades-and-version-skew).

   Fixes go to `main` as normal PRs, followed by `rc.2` if needed.
4. **Release PR** from `improvement/release-vX.Y.0`, titled `chore(release): vX.Y.0`:
   - rename `## [Unreleased]` to `## [X.Y.0] - YYYY-MM-DD` and add a new empty `## [Unreleased]`
     above it;
   - update the compare links at the bottom;
   - update version references in documentation, if any.

   Green CI ([CONTRIBUTING.md](CONTRIBUTING.md#reviews)), then merge it with a merge commit.
5. **Tag** the merge commit: `git tag -s vX.Y.0` with the changelog section as the message, and
   push the tag.
6. **Build** runs on the tag in CI ([12](docs/12-testing-and-quality.md#continuous-integration)):
   - two independent, reproducible builds whose SHA-256 must match;
   - SBOM, SLSA provenance, cosign signatures;
   - container images.
7. **Sign the release manifest** with the current signing key, which is held on a hardware token
   outside CI: raise `seq`, set `floor` and `channel` (`stable`, or `prerelease` for a
   pre-release), and list every artifact with its `variant`
   ([04](docs/04-security.md#release-signing), [D10](docs/14-open-decisions.md#security-defaults)).
8. **Publish.**
   - GitHub release: the changelog section, upgrade notes, verification instructions,
     `SHA256SUMS`. For v1.0.0 the notes also state whether an external security review took
     place ([D28](docs/14-open-decisions.md#project-and-process)).
   - Image tags `X.Y.0`, `X.Y` and `X`, plus `latest` for the highest stable release only.
   - The signed manifest as a release asset. Controllers fetch it from there in their daily
     release check ([D4](docs/14-open-decisions.md#product-and-project)); agents never contact the
     release source and download only from their controller's `/dl/` mirror.
9. **Roll out and close.**
   - Run the staged rollout on the maintainer's homelab installation first, which is the canary:
     canary → percentage → all ([04](docs/04-security.md#over-the-air-updates)).
   - Close the milestone and the release issue, and announce the release.

## Patch releases

- If `main` contains only fixes since the last release, the patch is released from `main` exactly
  as above (without the release candidate).
- Otherwise the patch is released from the [maintenance branch](#maintenance-branches) of that
  minor, so that unreleased features on `main` do not ship in a patch.

## Maintenance branches

- `release/<major>.<minor>` is created from the latest tag of that minor when its first backport is
  needed: `git switch -c release/1.4 v1.4.2`. It has the same protection as `main`.
- **Fix `main` first.** A fix is merged to `main` through a normal `bugfix/` PR. It is then
  backported by cherry-picking the PR's commits (`git cherry-pick -x <first>^..<last>`) in a PR
  that targets the release branch, from a branch like
  `bugfix/57-etag-mismatch-on-retry-1.4`. The title repeats the original title, and the body says
  `Backport of #<PR>`.
- A fix only goes directly to a release branch when the code no longer exists on `main`. The PR
  says so.
- The patch's changelog section is written on the release branch. After the release it is copied
  into `main`'s `CHANGELOG.md` through a `merge/release-1.4-into-main` PR, so `main` holds the
  complete history.
- Maintenance branches are kept as long as the minor is supported, then left as they are (not
  deleted, because tags point into them).

## Supported versions

| Version | Gets |
|---|---|
| Latest minor | All fixes |
| Previous minor (N−1) | Security fixes and fixes for critical defects (data loss, outages), because a controller at N still supports agents at N−1 ([10](docs/10-operations.md#upgrades-and-version-skew)) |
| Older | Nothing; upgrade |
| Before 1.0.0 | Only the latest `0.y` release |

## Security releases

- Vulnerabilities are reported privately ([SECURITY.md](SECURITY.md)) and fixed in a GitHub private
  security advisory, not in a public PR.
- The fix is released **at the same time** for every supported minor. The advisory, with a CVE
  where applicable, is published when the releases are out.
- The changelog's `### Security` entry names the advisory, severity and affected versions.
- If installed versions must not stay in use, the next release manifest raises `floor` above them,
  so agents refuse to install or roll back to them ([04](docs/04-security.md#release-signing)).

## Withdrawing a release

When a release turns out to be broken:

1. Stop its staged rollout ([04](docs/04-security.md#over-the-air-updates)).
2. Mark it: changelog heading `[YANKED]` with the reason, and the GitHub release's title and
   notes say "withdrawn — use vX.Y.Z+1".
3. Release a fixed patch version, and raise `floor` in its manifest above the broken version.
4. Never delete or move the tag, the artifacts or the images: installations and audits refer to
   them.

## Roles

rpmgr has one maintainer ([D27](docs/14-open-decisions.md#project-and-process)), who holds every
role:

- **Release manager:** creates `v*` tags, runs the checklist and owns the release issue.
- **Signer:** holds the two offline root keys on two hardware tokens (one kept off-site; either
  root alone can sign a signing-key statement) and the current signing key on a third token.
  Signing-key statements are valid for 12 months
  ([D10](docs/14-open-decisions.md#security-defaults), [04](docs/04-security.md#release-signing)).
  No key ever enters CI.
