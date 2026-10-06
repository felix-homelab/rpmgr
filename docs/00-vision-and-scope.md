# 00 — Vision and scope

> Status: design, not implemented. Claim tags ([F] [R] [T] [V]) are explained in the
> [README](../README.md#how-to-read-these-documents).

## What rpmgr is

**rpmgr — Reverse Proxy Manager** publishes services that run on private networks: behind NAT, CGNAT,
firewalls, or on hosts with no public IP. It manages them from one control plane.

It is designed as **one product**: there is one identity system, one configuration model, one
protocol and one user interface. The tunnel engine and the control plane are designed together, so
every setting is a typed, validated field the control plane understands; there is no opaque
configuration blob between them.

## Who it is for

| Persona | Typical setup | What they need most |
|---|---|---|
| **Homelab operator** | One VPS with a public IP, a few machines at home | A single binary, a single-click install of a connector, automatic HTTPS, nothing to babysit |
| **Small company IT** | Several sites, a few gateways, an internal team of 2–10 admins | Roles, audit trail, SSO, safe defaults, upgrades that don't drop tunnels |
| **Service provider / multi-team** | Shared gateways, several organisations | Org isolation, quotas, per-org domains, delegated administration |

The default installation is **single-organisation, self-hosted**. Every record carries an
`org_id` from day one, so serving several organisations later needs no data migration
([06-data-model.md](06-data-model.md), [ADR-0012](adr/0012-org-scoped-tenancy.md)).

## Goals

1. **Secure by default.** Every connection is mutually authenticated with per-agent identities.
   Nothing ships with a shared secret, a default password, or `InsecureSkipVerify`. If the
   control plane is compromised, the damage is bounded by what each host allows locally
   ([04-security.md](04-security.md)).
2. **Fast by design.** A new user connection through a tunnel costs **no extra round trip**
   on an established session. Throughput is measured against a direct connection, not assumed
   ([03-connections.md](03-connections.md#performance-budget)).
3. **Changes are safe.** A configuration change is validated before it is applied, applied
   atomically, acknowledged, and leaves unchanged tunnels untouched. A bad change never takes
   working tunnels down ([03-connections.md](03-connections.md#configuration-reconciliation)).
4. **One model, everywhere.** The database schema, the API, the agent protocol and the UI forms
   all derive from the same protobuf definitions. A setting either exists in the model, or it
   does not exist.
5. **Operable.** Health, apply status, metrics, audit and logs are first-class. Settings live in
   the UI, not in environment variables ([10-operations.md](10-operations.md)).

## Non-goals

- **Wire compatibility with other tunnel tools.** rpmgr speaks only its own protocol
  ([ADR-0003](adr/0003-clean-slate-protocol.md)); existing configurations are converted by the
  importer ([11-migration.md](11-migration.md)).
- **A general-purpose VPN.** Virtual networks (Phase 3) connect rpmgr connectors. They don't
  replace a full mesh VPN product.
- **A CDN or WAF.** Gateways terminate TLS and apply access policies. They do not cache content
  or inspect payloads for attacks. A route can sit behind Cloudflare's proxy as an explicit opt-in
  ([15-dns.md](15-dns.md#proxied-http-routes)).
- **A DNS editor or DNS host.** rpmgr publishes the records for the names it serves in connected
  DNS-provider zones and touches no other record unless a user adopts it
  ([15-dns.md](15-dns.md)).
- **Kubernetes-first.** rpmgr runs well in containers, but the primary target is a plain Linux
  host with systemd. A Helm chart is planned for Phase 3.
- **Hosted SaaS.** The design allows multiple organisations; billing, sign-up flows and abuse
  handling for a public service are out of scope.

## Design principles

| # | Principle | Consequence |
|---|---|---|
| P1 | **Agents dial out; nothing dials in.** | Connectors work behind NAT with no inbound firewall rule. Only gateways need public ports. |
| P2 | **Identity, not shared secrets.** | Every agent holds its own private key and a short-lived certificate ([ADR-0008](adr/0008-internal-ca-mtls-spiffe.md)). |
| P3 | **Desired state, reconciled.** | The controller declares what should run; agents converge, report, and keep the last good state on error ([ADR-0007](adr/0007-desired-state-reconciliation.md)). |
| P4 | **The host has the last word.** | A root-owned local policy on each connector limits what any controller may make it do ([ADR-0009](adr/0009-connector-local-policy.md)). |
| P5 | **Data never crosses the controller.** | User traffic flows public client → gateway → connector → service. The controller can be down without dropping traffic. |
| P6 | **Measure, don't assume.** | Performance claims are targets with a benchmark plan, not facts ([12-testing-and-quality.md](12-testing-and-quality.md#benchmarks)). |
| P7 | **Fail closed, explain why.** | Unknown fields, unannotated API methods and unparseable policy are rejected, and the rejection reason is shown to the user. |

## Naming

The project is called **`rpmgr`** everywhere — in prose, in the repository name and in every
identifier; **Reverse Proxy Manager** is its descriptive long name. The short form `rpm` is not used,
because `rpm` is the package manager binary on Red Hat, Fedora and SUSE systems (`/usr/bin/rpm`) and
would collide with it ([ADR-0001](adr/0001-name-rpmgr.md)).

| Thing | Name |
|---|---|
| Repository / folder | `github.com/felix-homelab/rpmgr` / `rpmgr` |
| Go module path | `github.com/felix-homelab/rpmgr` |
| Binary | `rpmgr` |
| Config directory | `/etc/rpmgr/` |
| State directory | `/var/lib/rpmgr/` |
| systemd units | `rpmgr-controller.service`, `rpmgr-gateway.service`, `rpmgr-connector.service`, `rpmgr-all-in-one.service`; updater: `rpmgr-update.path`, `rpmgr-update.service` |
| Container image | `ghcr.io/felix-homelab/rpmgr` |
| Protobuf packages | `rpmgr.v1` (public API), `rpmgr.agent.v1` (agent protocol) |
| ALPN identifiers | `rpmgr-tunnel/1`, `rpmgr-tunnel-h2/1`, `rpmgr-e2e/1`, `rpmgr-p2p/1` |
| Token prefixes | `rpmgr_enr_`, `rpmgr_pat_`, `rpmgr_sat_`, `rpmgr_ses_` |
| Trust domain | `rpmgr-<8 random base32 chars>` |
| Metrics, cookie, well-known path | `rpmgr_*`, `__Host-rpmgr_session`, `/.well-known/rpmgr/` |

## Glossary

| Term | Meaning |
|---|---|
| **Controller** | The control plane: API, web UI, database, internal CA, ACME client, configuration compiler. |
| **Gateway** | A public ingress node. Accepts traffic from the internet and forwards it through tunnels. |
| **Connector** | An agent on a private network. Dials gateways, forwards traffic to local services, and acts as the visitor side of private services. |
| **Agent** | A Gateway or Connector, as seen from the Controller. |
| **Gateway group** | A set of gateways that serve the same routes, typically one region. |
| **Route** | A published service: how the public reaches it (hostname or port on a gateway group) and where it goes (one or more targets). |
| **Target** | One upstream of a route: a connector plus a local address (`host:port`, unix socket), with a weight and an optional health check. |
| **Private service** | A service reachable only by authorised connectors, not by the public. |
| **Visitor grant** | Permission for a connector to reach a private service, and where it binds the local listener. |
| **Control session** | The long-lived mTLS connection from an agent to the controller, carrying configuration and status. |
| **Data session** | The long-lived mTLS connection from a connector to a gateway, carrying user traffic. |
| **Snapshot** | The complete compiled configuration for one agent at one revision. |
| **Revision** | A configuration version, `(db_epoch, seq)`; `seq` increases within a `db_epoch`, and a restore starts a new epoch. |
| **Last-known-good (LKG)** | The newest snapshot an agent applied successfully. Agents keep running it when a newer one is rejected. |
| **Local policy** | A root-owned file on a connector host that limits what the connector may do, whatever the controller says. |
| **Trust domain** | The namespace of all rpmgr identities of one installation, e.g. `rpmgr-7f3k2q9m`. |
| **SPIFFE ID** | An agent's identity URI, e.g. `spiffe://rpmgr-7f3k2q9m/org/org_01J…/connector/con_01J…`. |
| **Enrollment token** | A short-lived, single-use secret that lets a new agent obtain its first certificate. |
| **KEK** | Key-encryption key. Protects the database's encrypted secrets; kept outside the database. |
| **Org** | Organisation; the tenancy boundary. Every configuration record belongs to exactly one org. |
| **Instance** | One rpmgr installation (one database, one trust domain). |
| **DNS provider** | A connected account at a DNS host (Cloudflare first) whose API rpmgr uses to publish records. Phase 2. |
| **Managed zone** | A DNS-provider zone imported into rpmgr; rpmgr publishes records for its routes there. |
| **DNS name** | A name created in rpmgr that points at a gateway group without a route, e.g. for tcp routes or as a wildcard. |
| **Owned record** | A DNS record rpmgr created or explicitly adopted, listed in its ledger. rpmgr changes no other record. |
