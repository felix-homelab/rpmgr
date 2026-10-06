# ADR-0001: Name the project `rpmgr`

Status: Accepted (decided by the product owner) · Date: 2026-10-06

## Context

The product was first called **Reverse Proxy Manager (RPM)**, with its documentation in a folder
named `rpm/`.

"RPM" is also the name of the Red Hat package manager. Its binary, `/usr/bin/rpm`, is present on
Red Hat Enterprise Linux, Fedora, CentOS Stream, Rocky, Alma, openSUSE and SUSE Linux Enterprise.
Using `rpm` for the project would therefore:

- shadow or conflict with the system package manager, depending on `PATH` order or package file
  ownership. On those distributions a native package named `rpm` cannot be installed next to the
  real one;
- make support requests ambiguous ("`rpm` fails on my server");
- make the project hard to search for and its files hard to grep on affected hosts.

A first proposal kept "RPM" in prose and used `rpmgr` only for the binary, paths and images. That
left two names to learn and a mix of `rpm` and `rpmgr` prefixes in identifiers.

The name has to be settled before anything ships. Renaming later breaks install scripts, unit
files, configuration paths, image names, API package names, token prefixes and user habits.

## Decision

The project is called **`rpmgr`** everywhere: in prose, in the repository and folder name
(`rpmgr/`), and in every machine-facing identifier. **Reverse Proxy Manager** remains the
descriptive long name ("rpmgr — Reverse Proxy Manager").

| Thing | Name |
|---|---|
| Repository / folder | `rpmgr` |
| Binary | `rpmgr` |
| Configuration directory | `/etc/rpmgr/` |
| State directory | `/var/lib/rpmgr/` |
| systemd units | `rpmgr-controller.service`, `rpmgr-gateway.service`, `rpmgr-connector.service` |
| Container image | `ghcr.io/felix-homelab/rpmgr` |
| OS packages (later) | `rpmgr` (`.deb`, `.rpm`, `.apk`) |
| Protobuf packages | `rpmgr.v1`, `rpmgr.agent.v1` |
| ALPN identifiers | `rpmgr-tunnel/1`, `rpmgr-tunnel-h2/1`, `rpmgr-e2e/1`, `rpmgr-p2p/1` |
| Token prefixes | `rpmgr_enr_`, `rpmgr_pat_`, `rpmgr_sat_`, `rpmgr_ses_` |
| Trust domain | `rpmgr-<8 random base32 chars>` |
| Metrics, cookies, paths | `rpmgr_*` metrics, `__Host-rpmgr_session`, `/.well-known/rpmgr/`, `/.rpmgr/tunnel` |

The full list lives in [00](../00-vision-and-scope.md#naming).

## Consequences

**Positive**

- One name for people and machines; no collision with the system package manager on RPM-based
  distributions.
- One distinctive, searchable string for binaries, logs, processes, file paths, API packages and
  leaked-token scanning.

**Negative**

- Identifiers are two characters longer (`rpmgr_enr_…` instead of `rpm_enr_…`). Negligible.
- Shipping a `.rpm` package called `rpmgr` reads oddly ("the rpmgr rpm"), but it is unambiguous.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| `rpm` everywhere | Collides with `/usr/bin/rpm`; disqualifying on a large share of Linux servers |
| "RPM" in prose, `rpmgr` for machine identifiers only | The first proposal; two names to learn and mixed prefixes. Replaced by this decision |
| `revproxy`, `rproxy` | Generic; several unrelated tools already use these names |
| `rpm-manager` | Long, and still starts with `rpm`, so tab completion and `ps` output stay confusing |

## Verification

None needed. Before the first release, check that `rpmgr` is free as a package name in Debian,
Fedora, Alpine, Homebrew and on GitHub Container Registry; tracked as
[VB-14](../13-roadmap.md#verification-backlog).
