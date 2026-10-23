# ADR-0021: The release keys stay encrypted files on offline media

Status: Accepted (decided by the product owner, D126, 2026-10-23) · Date: 2026-10-23 · Supersedes
the key custody of [ADR-0013](0013-signed-ota.md): the hardware tokens and VB-13

## Context

- **The plan.** [ADR-0013](0013-signed-ota.md) and
  [D10](../14-open-decisions.md#security-defaults) put the two root keys on two hardware tokens
  and the signing key on a third. The v0.x releases of Phase 1, which have no OTA, were signed
  with interim keys instead: two root keys and a signing key, generated on an offline machine and
  kept as passphrase-encrypted minisign files on offline media
  ([D48](../14-open-decisions.md#security-defaults)). The hardware tokens were to take over with
  the first release with OTA, v0.2.0, whose binary would carry new roots.
- **What a token adds.** A token's private key cannot be copied out of it. A file key can: anyone
  who reads the medium and learns its passphrase holds the key, and nothing shows that it was
  copied. Signing on a token also needs minisign-format signatures from the token, which VB-13 was
  still to verify ([13](../13-roadmap.md#verification-backlog)).
- **What a file key already has.** The interim keys exist, their roots are in every build since
  v0.1.0 ([04](../04-security.md#release-signing)), and the key ceremony made them on a live
  system booted from read-only media with networking off
  ([RELEASING](../../RELEASING.md#release-signing-keys)). Each private key is encrypted with its
  own passphrase, kept apart from the media. Either root signs a statement for a new signing key,
  valid for at most 12 months, so a compromised signing key is replaced without a new binary.
- **One maintainer** ([D27](../14-open-decisions.md#project-and-process)) runs every key ceremony
  and every release.

## Decision

**Key custody** ([04](../04-security.md#release-signing))
- The two root keys and the signing key of the key ceremony are rpmgr's release keys, from v0.2.0
  on as before it: no hardware tokens, and no new roots in v0.2.0.
- Each private key is a minisign key file, encrypted with its own passphrase, on offline media:
  one medium at the maintainer's home with `root-1` and the signing key, one off-site with
  `root-2`. The passphrases are kept apart from the media.
- A medium is only ever read by the offline live system of the key ceremony, never by a machine
  that has been or will be online. Signing-key statements and release manifests are signed there.
- Either root alone signs a signing-key statement (1-of-2), valid for at most 12 months, as
  before.

**Everything else of ADR-0013 stands**
- The signature format (minisign, prehashed Ed25519), the manifest, `seq` and floor, the staged
  rollouts and the root updater are unchanged.

## Consequences

**Positive**

- v0.2.0 needs no key ceremony and no root change: controllers of v0.1.0 verify its releases,
  and no upgrade note warns that they cannot.
- One signing procedure from v0.1.0 on: minisign on the offline live system, the one
  [RELEASING](../../RELEASING.md#release-process) describes. VB-13 is not needed.
- No tokens to buy, initialise and keep in two places.

**Negative**

- A key file can be copied without a trace. If a medium is ever read on a compromised or online
  machine, and its passphrase is learnt, the key is lost without anyone noticing. The rule that
  only the offline live system reads the media is the whole protection.
- A stolen signing key signs manifests that every agent with OTA installs until a new statement
  replaces it. A stolen root key is worse: it signs statements for any signing key, and only a new
  binary, installed by hand, replaces it.
- Media age and fail. [R] Keep a second copy of each medium, in the same place as the first.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Hardware tokens for the roots and the signing key (ADR-0013, D10) | The product owner chose the file keys: they already exist, and the offline live system keeps them off every networked machine (D126) |
| Hardware tokens for the roots only, the signing key a file | Still a key ceremony and new roots in v0.2.0, for keys that sign a statement once a year |
| An online signing service (KMS, HSM) | A key reachable over a network, and a cloud account to keep, for one maintainer (D10) |
