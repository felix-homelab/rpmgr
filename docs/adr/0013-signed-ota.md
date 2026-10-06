# ADR-0013: Signed releases and staged OTA, verified by keys compiled into the binary

Status: Accepted (decided by the product owner on 2026-10-06) · Date: 2026-10-06

## Context

Over-the-air updates replace the binary that enforces every other control, so they need their own
requirements:

- **Real verification.** An update is installed only if it is signed by the project; a file-type or
  checksum check from the same source proves nothing.
- **No third parties in the download path.** Downloads must not go through third-party proxies or
  mirrors chosen at runtime.
- **The Controller does not choose where agents download from**, nor where the binary is installed.

Under rpmgr's threat model ([04](../04-security.md#threat-model)), updates must stay safe even when
the download path, the mirror, or the Controller itself is compromised. A signed binary is also
what makes the connector-local policy trustworthy ([ADR-0009](0009-connector-local-policy.md)).

The product owner also asked for install scripts served from the Controller's own endpoint.

## Decision

**Release signing** ([04](../04-security.md#release-signing))
- An **Ed25519** signing hierarchy, minisign-compatible if the hardware token can produce that
  format [V VB-13]; otherwise rpmgr's own documented Ed25519 signature format.
- **Two offline root keys** on two hardware tokens, held by the project's one maintainer, one of
  them off-site ([D10](../14-open-decisions.md#security-defaults)). Either root alone signs
  **signing-key statements** (1-of-2), which are valid for 12 months. The current signing key is
  on a third token and never enters CI.
- The current signing key signs each **release manifest**:
  `{seq, version, floor, channel, issued_at, artifacts[{os, arch, variant, sha256, size}]}`.
- `channel` is `stable` or `prerelease`; `variant` is `full` or `connector`. The root updater
  installs a manifest only if its channel matches the policy file's `update_channel` (default
  `stable`) and only the variant recorded at install time.
- `seq` is **monotonic and signed**. The root updater persists the highest `seq` seen and the
  version floor in `/var/lib/rpmgr-update/`; a manifest is accepted only if its `seq` ≥ the highest
  seen, and the floor can be lowered only by a manifest with a higher `seq`. Replaying an old,
  genuinely signed manifest therefore cannot lower the floor.
- Floor and `seq` are **initialised at install time** from the running version and its release
  `seq`; afterwards the running version plays no role. A fresh host that never updated therefore
  refuses replayed old manifests (lower `seq`). A manifest with a higher `seq` may lower the floor,
  which makes **signed downgrades** possible. The automatic rollback to `.prev` after a failed
  health check is exempt, because floor and `seq` are only raised after success.
- **Package installs** (deb/rpm) are updated by the package manager from the signed repository,
  **not by OTA**: the updater refuses to replace a package-owned binary, because the next package
  run would silently revert it. OTA is for script installs and standalone binaries.
- The root public keys are **compiled into `rpmgr`**.

**OTA** ([04](../04-security.md#over-the-air-updates))
1. The Controller verifies and mirrors releases under `/dl/`.
2. An admin approves a **staged rollout**: canary, then a percentage, then all.
3. The agent (service user) downloads from the mirror and **only stages** the artifact and manifest
   into `/var/lib/rpmgr/update/`. **The signature is trusted, not the URL.**
4. A **root-owned updater** (`rpmgr-update.path` + oneshot `rpmgr-update.service`) reads
   `auto_update` from `policy.yaml` **itself** (it does not trust the agent) and refuses to act on a
   package-owned binary. It opens the staging directory through a directory fd with
   `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`, requires regular files (`fstat` → `S_ISREG`),
   checks each size ≤ the manifest's size and ≤ a hard cap of 256 MiB before and while copying,
   **copies** the files into the root-only `/var/lib/rpmgr-update/staging/`, and verifies **the
   copy**: signature, manifest `seq`, version floor, OS/arch, size and SHA-256. Verifying in place
   would let the service user swap a file, plant a symlink (also a symlinked directory) or stage a
   FIFO or device between check and install.
5. The updater copies the verified file into the target directory as `.rpmgr.new` (same filesystem,
   so no cross-filesystem `rename`), fsyncs it, re-hashes it, and `rename`s it over the binary at
   the path recorded by the installer in `/var/lib/rpmgr-update/install.json`
   (`/usr/local/bin/rpmgr` for script installs), keeps the previous one as `.prev`, and restarts the
   role service. **The service user can never write the binary**, so a compromised agent process
   cannot persist a build that ignores the local policy.
6. The updater polls the agent's admin `/readyz` — ready only when the control session is
   established and a snapshot is applied — for up to 5 minutes; otherwise it **rolls back**.
7. The floor and the highest `seq` are raised only after success.

**Install scripts**
- `/install.sh` (Linux) is served by the Controller from an embedded template.
- It downloads from the Controller's mirror and verifies root key → signing-key statement →
  manifest → SHA-256 with OpenSSL ≥ 3.0, refusing to install without it
  ([04](../04-security.md#install-scripts)) [V VB-15].
- Windows and macOS connectors (Phase 2) are installed and updated through winget/MSI and
  Homebrew; there is no `/install.ps1` ([D29](../14-open-decisions.md#project-and-process)).
- No third-party proxy; no runtime-chosen download URLs.

**Ecosystem artifacts**
- Releases also carry **cosign** signatures, **SLSA provenance** and an **SBOM** [V VB-05].
- The build is reproducible: `CGO_ENABLED=0`, `-trimpath`, pinned toolchain, reproducibility
  check in CI.

## Consequences

**Positive**

- A compromised mirror, network path or Controller cannot install an unsigned or older binary on
  agents, nor replay an old manifest to lower the floor.
- Works fully offline: air-gapped installs upload the manifest and artifacts.
- Signing keys rotate without a new binary. Root keys are touched rarely.
- Rollouts are gradual and roll back automatically.

**Negative**

- **Key custody is a personal duty.** One maintainer holds both root tokens, in two places.
  Losing both means shipping a new binary through an out-of-band trust path
  ([D10](../14-open-decisions.md#security-defaults)).
- A compromised Controller can still serve a malicious **install script** to new hosts. The
  mitigation is distribution packages or verifying the GitHub release with
  `cosign verify-blob` first ([04](../04-security.md#install-scripts)).
- **Downgrades need a new signature.** The anti-rollback floor prevents a downgrade by replay.
  Downgrading needs a newly signed manifest with a **higher `seq`** that lowers the floor
  deliberately; replaying an older manifest is refused. Only the automatic rollback to `.prev`
  after a failed health check bypasses the floor.
- **Package installs do not get OTA.** They follow the package manager's update cycle from the
  signed repository, so the Controller's staged rollout does not cover them.
- **A second unit to install.** The root-owned updater adds a systemd path/service pair to every
  Linux host ([10](../10-operations.md#install)). Windows and macOS connectors get OTA only in
  Phase 3 ([D29](../14-open-decisions.md#project-and-process)).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Checksums only | A compromised mirror serves matching checksums |
| cosign/Sigstore verification inside the binary | Needs a transparency-log trust root and a large dependency tree; harder offline |
| TUF (The Update Framework) | The right model, but heavy for one artifact family; the manifest design adopts its key ideas (offline roots, rollback protection) [R] revisit if more artifact types appear |
| OS package managers only | Not available on every platform (containers, standalone binaries); no staged rollout from the Controller |
| Unsigned OTA | Anyone who controls the download path or the Controller can install their own binary |
