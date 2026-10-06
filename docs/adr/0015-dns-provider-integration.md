# ADR-0015: DNS automation through provider APIs, Cloudflare first, owned records only

Status: Accepted (decided by the product owner on 2026-10-06) · Date: 2026-10-06

## Context

Public DNS is entirely manual in the design so far:

- **Route hostnames.** Public DNS for a route's hostnames points at the gateway group, "operator's
  choice" ([02](../02-architecture.md#multi-region-gateway-groups)). Every new hostname means a
  trip to the DNS host.
- **Domain verification.** The operator copies the `_rpmgr-challenge` TXT value from the UI into
  the DNS host ([04](../04-security.md#route-and-hostname-ownership)).
- **Gateway changes and cutover.** Replacing a gateway and the migration cutover both end with
  "update public DNS" by hand ([10](../10-operations.md#runbooks),
  [11](../11-migration.md#cutover-plan)).
- **DNS-01.** ACME DNS-01, needed for wildcard certificates and for issuing certificates before DNS
  points at a gateway, is planned for Phase 2, but nothing defines how rpmgr talks to a DNS host
  ([05](../05-features.md#tls-and-domains)).

A DNS-provider credential is also one of the most powerful secrets rpmgr could hold. A Cloudflare
API token with DNS Write can change **every** record in the zones it covers, including MX, SPF and
third-party verification records [F cf:fundamentals/api/reference/permissions]. Whatever rpmgr
does with it has to be narrow, visible and reversible.

The goal is "changes are safe" ([00](../00-vision-and-scope.md#goals)), extended to DNS.

## Decision

rpmgr publishes DNS records through provider APIs, **Cloudflare first**, in Phase 2
([15](../15-dns.md)).

**Scope: owned records only**
- rpmgr writes records for route hostnames, for explicit **DNS names** (names that point at a
  gateway group without a route, including wildcards) and, while a domain claim is pending, the
  claim's `_rpmgr-challenge` TXT record.
- It never changes or deletes a record it did not create, unless a user explicitly **adopts** it.
  rpmgr is not a DNS editor.

**Providers and zones belong to orgs**
- Org Owners and Admins connect their own provider accounts. The Instance Admin connects providers
  for instance-level domains; these belong to the system org, like shared gateway groups (D14).
- A provider zone is **imported** as a managed zone. Only zones that Cloudflare reports as
  `active` and of type `full` can be imported.

**Publication rules**
- A record is published only in a managed zone of the **same org** as the thing that needs it. The
  one exception is the instance base domain's delegation to an org (D23). Without this rule, org B
  could make rpmgr publish org B's challenge TXT into org A's zone, with org A's token.
- Route hostnames and DNS names point at the gateway group's **DNS target**: a CNAME to a canonical
  name, or A/AAAA addresses (D22).
- **Cloudflare's proxy is opt-in per `http` route.** It applies only if every `http` route on the
  hostname opts in and the zone allows it. tcp, udp and `tls_passthrough` routes, DNS names and
  infrastructure names are always DNS-only.

**Ownership**
- The database ledger (`dns_records`) is authoritative. Each owned record also carries a comment
  marker naming the instance and the ledger row, as a hint.
- A ledger row is written **before** the provider call, so a crash in between is repaired on the
  next pass by matching the marker.
- A record carrying a marker but no ledger row is reported as orphaned. It is never deleted
  automatically.
- **Adopt** takes over a foreign record and stores its original content. **Release** hands a
  record back, optionally restoring the original.

**Reconciliation**
- A singleton **DNS job** compiles the desired record set per zone deterministically, lists the
  provider's records, and applies the difference, modelled on
  [ADR-0007](0007-desired-state-reconciliation.md).
- A record that fails is reported per name and does not block unrelated records.
- A provider is not an agent: it cannot validate a whole change or keep a last-known-good copy.
  That role is taken by:
  - **fail-static**: if the provider is unreachable or rejects the token, nothing is deleted and
    the published records keep serving;
  - **held zones with plan approval**: a zone is held after import, after a database restore and
    when a pass would remove more names than the zone's deletion threshold. A held zone writes
    nothing until an Owner or Admin approves the exact plan.

**Verification stays public**
- Domain ownership is proven only by the TXT record as seen by the zone's authoritative
  nameservers. A zone added to a Cloudflare account stays `pending` until the domain's nameservers
  point at Cloudflare [F cf:dns/zone-setups/reference/domain-status], and adding it needs no proof
  of ownership [V VB-12], so API access to a zone is never proof.

**ACME**
- Hostnames in managed zones obtain certificates via DNS-01, using the zone's provider credential.

**Client**
- rpmgr uses its own small Cloudflare REST client behind an internal `Provider` interface. The
  certmagic adapter implements the libdns interfaces that certmagic expects
  ([08](../08-software-stack.md#networking)).

## Consequences

**Positive**

- A route on a managed zone is reachable without visiting the DNS host, and deleting the route
  removes its record, so no dangling records are left behind.
- Domain verification, certificate pre-issuance and the migration cutover become actions in rpmgr,
  with rollback ([11](../11-migration.md#cutover-plan)).
- Wildcard certificates become possible.
- Every provider write is an audited, attributable change, and the UI shows which records rpmgr
  owns.

**Negative**

- A compromised controller can rewrite any record in the connected zones, not only rpmgr's. This
  is mitigated by zone-scoped, IP-restricted and expiring tokens, and by keeping public services on
  a dedicated domain. It is not prevented ([04](../04-security.md#threat-model)).
- Cloudflare's API budget is per Cloudflare user and shared with that user's dashboard, so rpmgr
  must stay well below it (VB-09).
- Cloudflare-specific behaviour (proxy, comments, batches) leaks into the design. A second provider
  will need its own capability flags, and may lack comment markers.
- Cloudflare sees plaintext for proxied routes. That is an explicit per-route opt-in, never a
  default.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| General DNS editor for imported zones | Duplicates the provider's dashboard and makes rpmgr responsible for records whose purpose it cannot know (mail, verification); widens what a bug or a compromised controller does by design |
| TXT ownership registry (as in Kubernetes external-dns) | Doubles the records, and a TXT record cannot sit next to a CNAME at the same name; the database ledger plus comment markers needs neither |
| Treat API access to a zone as proof of ownership | Pending zones can be added for any domain; proof must come from public DNS |
| `libdns/cloudflare` as the provider | Cannot set `proxied` [F libdns-cloudflare:models.go:293-295], has no comments, reads only the first page of zones [F libdns-cloudflare:provider.go:207], has no rate-limit handling [F libdns-cloudflare:provider.go:18] |
| `cloudflare-go` v7 | A generated SDK for the whole Cloudflare API, when rpmgr uses about seven endpoints |
| Per-gateway public addresses now | Needed for health-aware DNS and infrastructure names, which are Phase 3; a group-level target covers Phase 2 |
| DNS state inside the route status | Route status says whether gateways can serve a route; making it depend on Cloudflare would blur `wait=APPLIED`. DNS has its own `dns_status` |

## Verification

- **S6** (extended): DNS-01 for a managed zone through rpmgr's libdns adapter, with a second
  certmagic configuration for HTTP-01/TLS-ALPN-01 on the same storage; against Pebble with a fake
  Cloudflare API, then Let's Encrypt staging with a real test zone
  ([13](../13-roadmap.md#phase-0--spikes)).
- If S6 fails, the rule of [D17](../14-open-decisions.md#tenancy-and-data) applies (acmez with
  rpmgr's own solvers); the decisions in this ADR are unaffected.
- **VB-09–VB-12**: Cloudflare behaviour the documentation does not guarantee: rate-limit scope,
  comment and batch semantics, proxied CNAMEs across accounts, zone types and token scope
  ([13](../13-roadmap.md#verification-backlog)).
