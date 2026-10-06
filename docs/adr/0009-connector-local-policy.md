# ADR-0009: A connector-local policy that the Controller cannot override

Status: Accepted (decided by the product owner on 2026-10-06) · Date: 2026-10-06

## Context

A Connector runs inside a private network and can reach whatever its host can reach. If its
instructions come only from the Controller, then whoever controls the Controller can turn every
connector into:

- a **pivot** into internal networks (dial arbitrary hosts);
- a **remote shell**.

The risk grows with every feature that lets the control plane act on a host: a remote shell that is
on by default, or reachable without per-host consent, turns a control-plane compromise into a
compromise of every host.

The threat model ([04](../04-security.md#threat-model)) treats a compromised controller (process,
or database plus KEK) as a real actor. Cryptography cannot help here, because the controller is
the CA and the configuration authority. The only control that survives a compromised controller is
one that lives on the host and that the controller cannot change.

## Decision

- Every connector host has a **local policy file**, `/etc/rpmgr/policy.yaml`:
  - owner root, mode 0644, read-only for the `rpmgr` service user (systemd `ReadOnlyPaths`);
  - **never written by the Controller** ([04](../04-security.md#connector-local-policy)).
- It defines:
  - `allow_targets` (CIDR + ports, or unix sockets);
  - `allow_listen` (visitor listener binds);
  - `allow_remote_shell`, `allow_functions`, `allow_vnet_routes`, `allow_p2p`,
    `allow_egress_proxy`;
  - `auto_update` (`auto` | `notify` | `off`) and `update_channel` (`stable` | `prerelease`).
- Windows and macOS connectors (Phase 2) keep the same file in a platform-specific location that
  only administrators can write ([10](../10-operations.md#install)).
- **Defaults:**
  - `allow_targets: []` — **nothing** — unless the installer is given `--allow-target`; the
    interactive installer prompts for targets. Loopback is not allowed by default: loopback-only
    services (databases, admin UIs, rpmgr's own admin listener) are often the least protected;
  - a missing file means no targets, every `allow_*` feature off, `auto_update: auto` and
    `update_channel: stable` ([D5, D6](../14-open-decisions.md#security-defaults)); the installer
    always writes `auto_update` and `update_channel` explicitly;
  - an unparseable file means **deny everything**: every target reports
    `not_ready(policy_invalid)`.
- **Enforcement at dial time:**
  - checks run on the resolved IP and port via `net.Dialer.Control`, which defeats DNS rebinding;
  - IPv4-mapped IPv6 addresses are unmapped before checking;
  - 169.254.0.0/16, fe80::/10, `fd00:ec2::254/128` (the AWS IPv6 metadata endpoint, inside ULA
    ranges admins often allow) and `100.100.100.200/32` (Alibaba Cloud ECS metadata) are always
    denied unless listed explicitly.
- **Effect on snapshots and routes:** a policy-blocked target is **resource-level**. The snapshot is
  still `Applied`; the affected route or target reports
  `not_ready(blocked_by_local_policy: <ip:port>)`, and gateways send it no traffic
  ([03](../03-connections.md#establishment)). `Rejected` is reserved for snapshots that are
  malformed, semantically invalid, wrongly signed, or contain unparsable certificates
  ([ADR-0007](0007-desired-state-reconciliation.md)). One unauthorised target therefore never
  freezes other changes for that connector.
- **Fixing a block:** the UI shows the reason and the exact host command, for example
  `sudo rpmgr policy allow-target 10.0.0.5:5432`. The installer accepts `--allow-target` flags.
- **Reload:** `rpmgr policy …` edits the file and triggers a reload (SIGHUP via
  `systemctl reload`); the connector also watches the file. On reload it re-evaluates the current
  snapshot and reports the readiness changes, so no new revision is needed.
- **Binary integrity:** the policy is only worth something if the binary enforcing it is genuine.
  OTA installs only signed binaries at or above a persisted version floor, through a root-owned
  updater (the service user can never write the binary), and `auto_update: off` lets a host refuse
  automatic updates. The **root updater reads `auto_update` from this file itself**; it does not
  trust the agent's decision ([ADR-0013](0013-signed-ota.md)).

## Consequences

**Positive**

- A compromised controller cannot use connectors to reach hosts or ports that the host owner did
  not allow, and cannot open shells on hosts that did not opt in.
- Dangerous features are off by default and need an action on the host itself.
- Blocked targets are explicit and actionable instead of silent failures, and they never block
  unrelated changes.

**Negative**

- **Usability cost.** Exposing a new target needs a change on the host, including loopback
  services. This is mitigated by:
  - clear `not_ready(blocked_by_local_policy: …)` messages;
  - copyable commands;
  - installer flags.
- **Limits of the protection.** The policy does not protect public users of a route: a compromised
  controller can still re-route a hostname. It also does not limit a shell once a host has allowed
  one. [R] For high-value hosts, prefer SSH over a private service
  ([14](../14-open-decisions.md)).
- Configuration-management tools (Ansible and similar) must manage the file. That is the intended
  owner.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Trust the controller completely | A single compromise reaches every internal network and every host shell |
| Signed policy pushed by the controller | The controller (or its key) is the threat; a signature from it proves nothing |
| Per-host approval prompts for each change | Unworkable for unattended hosts; the file plus CLI gives the same control asynchronously |
| Kernel-level egress firewall only | Valuable defence in depth, but cannot express "routes only"; does not gate shell or functions |
