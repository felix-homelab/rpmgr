# 05 — Features

> Status: design, not implemented. Tags: [F] fact · [R] recommendation · [T] target · [V] verify at
> implementation ([README](../README.md#how-to-read-these-documents)).
>
> **Phases** (details and exit criteria in [13-roadmap.md](13-roadmap.md)): **P1** MVP · **P2**
> production · **P3** advanced. "—" means not planned.

## Feature catalogue

### Publishing services (routes)

| Feature | Phase |
|---|---|
| `http` routes: hostnames (incl. wildcards under a verified domain), longest path prefix, header matching | P1 (header matching: P2) |
| `tcp` routes on an explicit or randomly allocated port from a port pool | P1 |
| `udp` routes, carried as QUIC datagrams ([03](03-connections.md#udp-routes)) | P1 |
| `tls_passthrough` routes, routed by SNI without terminating TLS | P1 |
| `tcp` routes in `http_connect` mode (HTTP CONNECT multiplexer on one port) | P2 |
| Port pools per gateway group and port quotas per org and gateway group | P1 |
| Route enable/disable with one switch, applied without touching other routes | P1 |
| Route preview: compile and show what agents would receive, without saving | P1 |

### TLS and domains

| Feature | Phase |
|---|---|
| Automatic certificates via ACME: HTTP-01, TLS-ALPN-01 | P1 |
| ACME DNS-01 (needed for wildcard certificates) for hostnames in managed zones, using the zone's DNS-provider credential ([15](15-dns.md#acme-dns-01)) [V S6] | P2 |
| Uploaded certificates | P1 |
| Domain ownership verification per org (DNS TXT or HTTP token); domains marked trusted by the Instance Admin need no proof ([D13](14-open-decisions.md#tenancy-and-data)) | P1 |
| Delegated labels under the instance base domain (`<org-slug>.<base>`) and Instance-Admin approval of nested claims ([D23](14-open-decisions.md#tenancy-and-data)) | P2 |
| Connect a Cloudflare account (API token, per org; instance-level in the system org) and import its zones as managed zones ([15](15-dns.md)) | P2 |
| Automatic DNS records for route hostnames in managed zones, pointing at the gateway group's DNS target; removed with the route | P2 |
| DNS names: explicit names and wildcards pointing at a gateway group, e.g. for tcp/udp routes | P2 |
| Challenge TXT records for pending domain claims published automatically | P2 |
| Owned records only: conflicts shown, adopt and release (with restore of the original), drift correction, plan approval for held zones | P2 |
| Cloudflare proxy as a per-route opt-in for `http` routes, with the client address from `CF-Connecting-IP` | P2 |
| Further DNS providers; per-gateway addresses with health-aware records; DNS for gateway tunnel and WSS hostnames; Authenticated Origin Pulls | P3 |
| HTTP → HTTPS redirect (per route: redirect, serve plain HTTP, or off), optional HSTS | P1 |
| HTTP/1.1 and HTTP/2 on the public side | P1 |
| HTTP/3 on the public side (shared UDP/443, [03](03-connections.md#port-443-multiplexing)) | P3 |

### Targets and load balancing

| Feature | Phase |
|---|---|
| Target kinds: `host:port`, unix socket | P1 |
| Upstream protocols: TCP, HTTP, HTTPS **with certificate verification** (custom CA, server name), h2c | P1 |
| PROXY protocol v1/v2 to the target | P1 |
| Several targets per route: weights, priorities (failover) | P2 |
| Active health checks (TCP, HTTP) run by the connector next to the target | P2 |
| Passive health: gateway marks a target unhealthy after consecutive upstream failures | P2 |
| Targets on different connectors (multi-site redundancy) | P2 |

### Edge access control and limits

| Feature | Phase |
|---|---|
| Reusable access policies attached to routes, evaluated in order | P1 |
| IP allow/deny lists | P1 |
| HTTP basic auth (credentials stored as argon2id hashes) | P1 |
| OIDC single sign-on in front of a route (forward-auth style) | P2 |
| Per-route bandwidth limit, enforced on the gateway | P2 |
| Per-route connection limit and request rate limit | P2 |
| Require-header rule (e.g. shared secret header from a CDN) | P2 |

### HTTP features

| Feature | Phase |
|---|---|
| Set/remove request and response headers; host header preserve or rewrite | P1 |
| `Forwarded` / `X-Forwarded-*`, with untrusted incoming values stripped | P1 |
| WebSockets and gRPC pass-through | P1 |
| Request body size limit; per-route timeouts | P1 |
| Custom error pages (502/503/504/404) per gateway group | P2 |

### Private services

| Feature | Phase |
|---|---|
| TCP private services with visitor grants | P2 |
| UDP private services | P2 |
| End-to-end TLS between connectors; the gateway only relays ciphertext | P2 |
| P2P upgrade via hole punching, relay fallback | P3 |

### Fleet management

| Feature | Phase |
|---|---|
| Enrollment with a one-line install command, CA pin, single-use token | P1 |
| Connector and gateway lists: status, version, transport, RTT, last seen, labels | P1 |
| Ephemeral connectors, purged automatically | P1 |
| Decommission and revoke, with immediate effect | P1 |
| Gateway groups of at most 4 gateways; connectors keep a session to every gateway of the group | P1 |
| Data-session transport as a setting: instance default `auto` (QUIC first, TCP + h2 as fallback), `quic` or `h2`, overridable per connector and per route ([03](03-connections.md#transport-selection)) | P1 |
| WSS transport for networks with TLS-intercepting proxies ([03](03-connections.md#transports-and-fallback)) | P2 |
| Local-policy status per connector, with the reason for any blocked target | P1 |
| Staged, signed over-the-air updates with automatic rollback, with `stable` and `prerelease` channels (Linux script installs only; deb/rpm packages update from the signed repository; Windows and macOS connectors: no OTA before P3) | P2 |
| Connector-only build (`rpmgr-connector` artifact, installed as `rpmgr`) | P2 |

### Configuration management

| Feature | Phase |
|---|---|
| Desired-state model with revisions, apply status and last-known-good on agents | P1 |
| Runtime settings editable in the UI (instead of environment variables) | P1 |
| YAML view and export per resource | P1 |
| Declarative manifests: `rpmgr apply -f`, `Plan`/`Apply` in one revision | P2 |
| Importer for existing tunnel configurations ([11](11-migration.md)) | P2 |
| Terraform provider | P3 |

### Identity and access

| Feature | Phase |
|---|---|
| Local accounts, argon2id, TOTP, recovery codes | P1 |
| Roles: Owner, Admin, Operator, Viewer; Instance Admin | P1 |
| Members and invitations (one-time links; e-mail if SMTP is configured) | P1 |
| Password reset by one-time link or e-mail (SMTP optional) | P1 |
| Session management (list, revoke), step-up re-authentication | P1 |
| WebAuthn / passkeys | P2 |
| OIDC single sign-on for the UI, group → role mapping | P2 |
| Personal API tokens (scoped, expiring, revocable) | P1 |
| Service accounts and their tokens | P2 |
| Multi-org UI (org switcher, shared gateway groups with grants) | P2 |

### Observability

| Feature | Phase |
|---|---|
| Overview dashboard: route, connector and gateway health; apply status | P1 |
| Per-route traffic (bytes, connections, errors), hourly and daily | P1 |
| Prometheus metrics from every role; OpenTelemetry tracing | P1 |
| Audit log with hash chain and locally stored signed checkpoints | P1 |
| Audit export and external sinks (syslog, OTLP, webhook, object storage) | P2 |
| Live agent logs in the UI, redacted on the agent | P2 |
| Webhooks for events and alerts | P2 |
| Active connections view per route | P3 |

### Operations

| Feature | Phase |
|---|---|
| Single binary `rpmgr`; all-in-one mode | P1 |
| systemd units (hardened), OCI images | P1 |
| Windows service and macOS launchd connector (winget/MSI, Homebrew) | P2 |
| Install script (`/install.sh`, Linux) served by the controller from its own signed binary mirror | P1 |
| Distribution packages (`.deb`, `.rpm`) from a signed repository | P2 |
| Backup and restore (`rpmgr backup`/`restore`) | P1 |
| PostgreSQL and multiple controller replicas (HA) | P2 |
| `rpmgr migrate-db` (SQLite → PostgreSQL) | P2 |
| Helm chart | P3 |
| Socket hand-off for zero-downtime gateway restarts | P3 [V VB-08] |

### Advanced (Phase 3)

| Feature | Notes |
|---|---|
| Virtual networks (WireGuard between connectors, keys generated on agents, latency-aware routing) | Needs `allow_vnet_routes` |
| Edge functions (Cloudflare `workerd` on connectors) | Needs `allow_functions`; bundles signed and content-addressed |
| Remote shell | Off by default; needs host opt-in (`allow_remote_shell`), a per-user grant and step-up; sessions recorded in the audit log. [R] SSH over a private service is preferred ([14](14-open-decisions.md)) |
| SSH ad-hoc tunnels (`ssh -R` to a gateway, authenticated by users' registered SSH keys) | — |
| Egress proxy targets (SOCKS5, HTTP proxy) | Needs `allow_egress_proxy`; turns a connector into a proxy, so gated |
| Static file target | Path must be allowed in local policy |

## Platform support

| Role | Linux amd64/arm64 | Linux armv7, riscv64 | Windows | macOS | Notes |
|---|:-:|:-:|:-:|:-:|---|
| Controller | ✓ | best effort | — | dev only | The pure-Go SQLite driver works on all four Linux architectures ([S8](spikes/S8.md)); PostgreSQL is the alternative |
| Gateway | ✓ | best effort | — | — | Needs public ports; Linux for GSO/ECN performance |
| Connector | ✓ | ✓ | ✓ (P2) | ✓ (P2) | Virtual networks (P3): Linux first |

Phase 1 is Linux only; Windows and macOS connectors follow in Phase 2. The supported Linux
distributions and versions are listed in [10](10-operations.md#install).
