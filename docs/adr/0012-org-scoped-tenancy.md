# ADR-0012: Every record is org-scoped from day one

Status: Accepted (decided by the product owner on 2026-10-06) · Date: 2026-10-06

## Context

The product owner chose **self-hosted, single-org by default, multi-org ready**. Adding tenancy
later usually means:

- a data migration;
- an audit of every query;
- years of cross-tenant leak risk.

The typical failure modes are tenant columns that exist but are never set, a permission layer
that is defined but never called, and sensitive endpoints (such as a remote shell) without any
ownership check. Tenancy has to be enforced in one place from the first record on, so that it
cannot be forgotten.

## Decision

**Data**
- An **org** is the tenancy boundary. Every configuration record belongs to exactly one org:
  `org_id NOT NULL` on every org-owned table.
- Foreign keys between org-owned tables are **composite `(org_id, id)`**, so a row cannot reference
  another org's row on SQLite or PostgreSQL
  ([06](../06-data-model.md#tenancy-enforcement)).
- Users are global: one account can be a member of several orgs, each membership with a role.

**One enforcement point, three layers**
([04](../04-security.md#one-enforcement-point-with-defence-in-depth))
1. **API.** Every RPC carries a proto `authz` annotation. One interceptor resolves the target's org
   and checks the caller's role. Unannotated methods fail at startup, and a test checks that every
   method is annotated.
2. **Store.** Queries on org-owned tables require an `OrgScope` that only the authorization layer
   can construct (Ent interceptor plus a deny-by-default privacy rule). System jobs use an
   explicit, audited system scope.
3. **Schema.** `NOT NULL` org columns and composite foreign keys.

**Org-scoped resources**
- **Shared infrastructure** (gateways that serve several orgs) belongs to a **system org**. Other
  orgs use it through explicit grants.
- **Domains** are verified per org and are globally unique within the instance
  ([04](../04-security.md#route-and-hostname-ownership)).
- **DNS providers and managed zones** belong to an org. A zone receives records only for its own
  org's routes, DNS names and pending claims, never for another org's, except names under the
  instance base domain that the Instance Admin delegated to an org
  ([ADR-0015](0015-dns-provider-integration.md)).
- **Identities** carry the org in the SPIFFE path
  (`spiffe://<td>/org/<org>/connector/<id>`, [ADR-0008](0008-internal-ca-mtls-spiffe.md)).

**Default install**
- A single-org install creates one org. The UI hides org switching until a second org exists.
- **PostgreSQL row-level security is not used in v1** ([14](../14-open-decisions.md)). The schema
  keeps it possible.

## Consequences

**Positive**

- Moving from single-org to multi-org needs no data migration.
- Cross-tenant access is prevented in three layers, and is testable in all three: a cross-tenant
  leak suite runs on both dialects ([12](../12-testing-and-quality.md#security-testing)).
- The same structure gives a homelab a clean home/lab/family split if wanted.

**Negative**

- Every table, query and test carries `org_id`, a small but permanent cost.
- Composite foreign keys make some schema changes more verbose.
- Instance-level concerns (CA, KEK, system gateways) need a separate **Instance Admin** role
  ([04](../04-security.md#roles)).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Single-org only | A later move to multi-org means migrating every row and auditing every query |
| Database per tenant | Operational overhead; shared gateways and a shared CA become cross-database problems |
| PostgreSQL RLS as the primary mechanism | Not available on SQLite (the default); `SET LOCAL` with pooled connections is error-prone |
| Ownership checks per handler | Easy to forget, typically on the endpoints that matter most, such as shells and log streams |
