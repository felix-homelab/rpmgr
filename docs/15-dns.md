# 15 — DNS automation

> Status: design for Phase 2, not implemented. Tags: [F] fact · [R] recommendation · [T] target ·
> [V] verify at implementation ([README](README.md#how-to-read-these-documents)).
>
> **This document is the single source of truth for DNS automation timers and limits.** The
> decision is [ADR-0015](adr/0015-dns-provider-integration.md). Tables live in
> [06](06-data-model.md#dns), RPCs in [07](07-api.md#services), permissions and threats in
> [04](04-security.md), the library choice in [08](08-software-stack.md#networking) and
> operations in [10](10-operations.md). All of it is Phase 2.

rpmgr can manage the public DNS records of the names it serves. An org connects a Cloudflare
account, imports zones, and from then on route hostnames in those zones are published, changed and
removed by rpmgr. The same credential lets ACME use DNS-01.

## Scope

- **In scope:** records for route hostnames, explicit DNS names, and the TXT record of a pending
  domain claim; adopting and releasing existing records; DNS-01; Cloudflare's proxy for `http`
  routes.
- **Not in scope:** editing arbitrary records (MX, SPF, other TXT); DNS hosting; registrar
  operations; changing zone settings. Phase 3 adds per-gateway addresses, health-aware records,
  infrastructure names and more providers ([05](05-features.md#tls-and-domains)).

## Concepts

| Term | Meaning |
|---|---|
| **DNS provider** | A connected account at a DNS host and its API credential. Phase 2 supports Cloudflare. Owned by an org; providers for instance-level domains belong to the system org |
| **Managed zone** | A provider zone imported into rpmgr. rpmgr publishes records only in managed zones |
| **Source** | Something that needs a record: a route hostname, a DNS name, or a pending domain claim |
| **DNS name** | A name created in rpmgr that points at a gateway group without a route, e.g. `ssh.example.com` for a tcp route or `*.apps.example.com` so that new routes need no new record. Always DNS-only |
| **DNS target** | Where a gateway group's names point: a CNAME to a canonical name, or A/AAAA addresses ([D22](14-open-decisions.md#tenancy-and-data)) |
| **Owned record** | A provider record listed in rpmgr's ledger. rpmgr may change or delete it |
| **Foreign record** | Every other record in the zone. rpmgr reads it, never writes it |

## Publication rules

1. **Same org.** A record is published only in a managed zone of the same org as its source. The
   one exception: names under the instance base domain that the Instance Admin has delegated to an
   org are published in the system org's zone ([D23](14-open-decisions.md#tenancy-and-data)). The
   base domain is the instance setting `base_domain` ([Base domain](#base-domain)). DNS-01 follows
   the same rule ([ACME DNS-01](#acme-dns-01)).
2. **Verified coverage.** The name must lie under a verified domain of that org
   ([04](04-security.md#route-and-hostname-ownership)). The exception is the challenge TXT of a
   **pending** claim of the same org: it is published while the claim is pending and deleted once
   the claim is verified or deleted.
3. **Sources and targets.**
   - Route hostnames (`http` and `tls_passthrough`) and DNS names point at the DNS target of their
     gateway group. A group without a DNS target publishes nothing.
   - The DNS target is either `cname` (one CNAME record) or `addresses` (one A record per IPv4 and
     one AAAA record per IPv6 address).
   - The API refuses a target that mixes both, a `cname` that is not a fully qualified name or is
     reserved (rule 6), an address list that is empty, over the limit
     ([Timers and limits](#timers-and-limits)) or holding a duplicate, and an address that others
     cannot reach or that is no plain address: IPv4-mapped IPv6 (the IPv4 form is asked for
     instead), loopback, unspecified, multicast, link-local, or with a zone. Names and addresses
     are stored in their canonical form.
   - A DNS name takes precedence over route hostnames with the same name. It is created only for
     a gateway group of its own org, and only under a verified domain of the org that covers it; a
     wildcard name needs a domain with the wildcard. Its `ttl` is 0, which is the zone's
     `default_ttl`, or lies within the bounds of that ([Timers and limits](#timers-and-limits)).
   - If routes in two gateway groups use the same hostname, which the data model allows
     ([06](06-data-model.md#routing)), and no DNS name decides, the name is `ambiguous` and its
     records stay as they are.
4. **Existence, not `enabled`.** Records follow the existence of their source. Disabling a route
   keeps its records, so toggling a route does not churn DNS caches.
5. **Zone gates**, set by the zone's Owner or Admin ([D24](14-open-decisions.md#tenancy-and-data)):

   | Gate | Default | Effect when off |
   |---|---|---|
   | `publish_route_hostnames` | on | Route hostnames are not published (`not_managed`); DNS names and challenge TXTs still are |
   | `allow_proxied` | off | `dns_proxied` on routes in this zone is refused |
   | `allow_wildcards` | off | Wildcard route hostnames and DNS names are not published (`held`) |

   Operators create routes; the gates are how Owners and Admins decide what an Operator's route may
   publish ([04](04-security.md#roles)).
6. **Reserved names are never written:**
   - the controller's public URL, its aliases and the controller endpoints advertised to agents. A
     wrong record there would lock operators out of the UI they need to fix it;
   - gateway tunnel and WSS hostnames (per gateway, Phase 3);
   - `_acme-challenge.*`, which belong to certmagic and to `tls_passthrough` backends that run their
     own DNS-01.
7. **Proxy.**
   - A name is proxied only if **every** `http` route on it has `dns_proxied` set and the zone
     allows it.
   - If the routes disagree, the name keeps its currently published proxy state and shows a warning.
     This lets routes be changed one at a time.
   - Everything else is DNS-only: tcp, udp and `tls_passthrough` routes, DNS names, challenge TXTs.

The result is shown per hostname as `dns_status`:

| Status | Meaning |
|---|---|
| `not_managed` | The name is not in a managed zone, or the zone does not publish route hostnames |
| `pending` | Change committed, not yet published |
| `published` | The provider holds exactly the desired records |
| `conflict` | A foreign record occupies the name ([Conflicts](#conflicts)) |
| `ambiguous` | Two gateway groups claim the name and no DNS name decides |
| `held` | The zone is held, or a gate holds this name |
| `error` | The provider refused the change; the reason is attached |

`dns_status` never changes the route status, which describes whether gateways can serve the route
([06](06-data-model.md#desired-vs-observed-state)).

### Compile result

The compiler (`internal/dns/compile`) is a pure function of the sources of one zone. It lists the
desired records and one result per name that has a source in the zone. Sources of another org, names
outside the zone, and tcp and udp routes (which have no published hostname) leave no trace.

- A name is `ok`, or it has the reason it publishes nothing: `not_managed`, `ambiguous`, `held`,
  `no_target` (its gateway group has no DNS target), `reserved` (rule 6) or `not_verified` (no
  verified domain of the org covers it, rule 2). `no_target`, `reserved` and `not_verified` are
  shown as `not_managed` with their reason.
- Records already at a name that is `not_managed`, `ambiguous`, `held`, `no_target` or `reserved`
  stay as they are: the plan neither changes nor deletes them. A name that is `not_verified`, or has
  no source any more, has its owned records deleted. In a `disabled` zone every name is
  `not_managed`.
- A route that is not `http` makes its name DNS-only, even if `http` routes on the name set
  `dns_proxied`, because the provider would end the TLS that the route needs.
- The result carries a warning `proxy_disagrees` for a name that keeps its published proxy state
  (rule 7).

## Conflicts

The address record set at a name — A, AAAA and CNAME — is owned as one unit.

| Found at the name (not owned) | rpmgr wants | Result |
|---|---|---|
| Nothing | Anything | Create |
| A, AAAA or CNAME | Address records | `conflict`: Adopt, or remove the record at the provider |
| Other types (TXT, MX, …) | A/AAAA | Coexist |
| Other types (TXT, MX, …) | CNAME | `conflict`: a CNAME cannot share a name with other data |
| NS delegation at or above the name, inside the zone | Anything | `conflict` (`delegated`): the records would not be served |
| Wildcard covering the name | Anything | Create; the plan notes that the name no longer follows the wildcard |
| A record with this instance's marker but no ledger row | — | `orphaned` ([Ownership ledger](#ownership-ledger)) |

Cloudflare itself refuses A/AAAA and CNAME at the same name
[F cf-api:openapi.json `POST /zones/{zone_id}/dns_records`].

## Ownership ledger

Every owned record has one row in `dns_records` ([06](06-data-model.md#dns)). The ledger is
controller-managed durable state: it is never rebuilt from the provider.

- **Write-ahead.** The ledger row is written in state `creating` **before** the provider call. A
  record about to be deleted has its row set to `deleting` first. The rows are committed in a
  transaction that checks the lease's fencing token, so a replica that lost the lease writes none.
  A `creating` row whose record was never written (the provider refused it, or the pass stopped) is
  reused by the next create of the same name and type, never duplicated.
- **Commit.** The provider's answer to a batch carries no record IDs, so after a pass that created
  records the job lists the zone and links each created record to its row by its marker. The row
  becomes `synced` with the provider's ID and `last_synced_at`, in one transaction that first checks
  the fencing token, with one audit entry per write: `dns_record.create`, `dns_record.update` or
  `dns_record.delete`, actor `dns`, in the chain of the zone's org, with the record before and
  after ([04](04-security.md#audit-log)). A write whose commit is lost (a crash, a lost lease)
  leaves its row `creating` or `deleting`, which the next pass repairs.
- **Marker.** Each owned record carries the comment `rpmgr <trust-domain> <ledger ID>`, e.g.
  `rpmgr rpmgr-7f3k2q9m dnr_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R` (51 characters). Comments are available on
  all plans, up to 100 characters on Free [F cf:dns/manage-dns-records/reference/record-attributes];
  that the comment round-trips unchanged through the API, also at 100 characters, was checked
  against a Free-plan zone [F VB-10, run 2026-11-04].
- **The ledger decides, the marker helps.**
  - A record whose marker names a ledger row in state `creating` is linked to it, before the pass
    plans, so that it is not taken for a foreign record in the way. The row takes the record's
    content, becomes `synced` and the link is audited (`dns_record.link`). This repairs a crash
    between the provider call and the database commit. In the same step, a `deleting` row whose
    record is gone is finished and removed, and a row that never got a record and that no desired
    record asks for any more is removed.
  - A record with this instance's marker and no ledger row is `orphaned`: reported by the pass,
    never deleted automatically, not even when the sources would delete a record at its name. The
    zone's Owner or Admin can delete or re-link it.
  - An owned record whose content, TTL, proxy flag or marker was edited at the provider has
    drifted: the provider's record differs from what the ledger says the job wrote. It is put back
    (the marker too), and the correction is audited: `dns_record.drift` with the provider's record
    and the ledger's, then the update. A change the sources made is no drift, and a record changed
    to what the sources want needs no write; the ledger takes it over. If the same record drifts
    again within the stop window ([Timers and limits](#timers-and-limits)), rpmgr stops correcting
    it, marks it `drifted` (`dns_record.drifted`) and the pass reports it: another tool is probably
    writing it. A `drifted` record is left alone, also after the window, until it matches the ledger
    again or is adopted or released; the removal of its source still deletes it.
  - The pass reports its orphans, corrections and `drifted` records to the controller, which logs
    them; the alert `dns.drifted` fires for a `drifted` record
    ([10](10-operations.md#suggested-alerts)). Orphans are shown in the zone's plan.
- **Adopt.** Turns a foreign record at a desired name into an owned one. An Owner or Admin, after a
  step-up, because it hands rpmgr control of the record, whatever its content, names
  the records; a name is desired if a source of the zone's own org publishes it, so a record at a
  name that only another org wants, or that nothing publishes, is not adopted. The call is all or
  none, and only A, AAAA, CNAME and TXT records are adopted. Its original content is stored in the
  ledger (`adopted_from`), and the next pass, which the adoption asks for, rewrites it to what the
  sources want and puts the marker on it; that first write is no drift. Adopt is how the migration
  cutover switches names from an old server to rpmgr ([11](11-migration.md#cutover-plan)).
- **Release.** Removes a record from the ledger; the CLI calls it `disown`
  ([D169](14-open-decisions.md#engineering)). Either the record stays as it is, with rpmgr's marker
  taken off, by a patch with an empty comment [V VB-27], so that it is not reported as an orphan, or it is restored to its adopted original,
  which needs the record to be of the type it was adopted with. Both are written to the provider
  before the row is dropped, by the DNS job under its lease and not by the API call: the call, which
  also needs a step-up, records the request on the row, and the job carries it out at its next pass
  of an active zone, so a held zone writes nothing. A restore of a record whose type changed since,
  or that was not adopted, is not carried out and the row says why. A restore warns when the original
  is older than the staleness limit, because an old address may now belong to someone else.
- **Who sees what.** Every member of the org lists a zone's owned records. The records of the zone
  that rpmgr does not own, read live, and the orphans are for an Owner or Admin: an Operator or
  Viewer who asks for them is refused, so one learns nothing of what else is in the zone.

A provider without record comments (none in Phase 2) has no marker, so the crash repair is
unavailable. The crashed record then shows as a `conflict` at its own name and is adopted.

## The DNS job

The DNS job reconciles managed zones. It is modelled on desired-state reconciliation
([ADR-0007](adr/0007-desired-state-reconciliation.md)), with the differences that an external API
forces.

### One pass

```mermaid
sequenceDiagram
  participant S as Store
  participant J as DNS job (lease holder)
  participant P as Cloudflare API
  S-->>J: dns_dirty(zone) · full-pass timer · lease takeover · "Sync now"
  J->>S: read sources in one read transaction, labelled with config_seq
  J->>J: compile the desired record set (deterministic)
  J->>P: list the zone's records (all pages)
  J->>J: diff → plan: creates, updates, deletes, conflicts
  alt zone held, or the deletion guard trips
    J->>S: store the plan and its hash · zone held
  else
    J->>S: ledger rows for creates (state creating)
    J->>J: lease valid for at least the safety margin?
    J->>P: one batch: deletes, patches, posts
    P-->>J: ok · or error → retry record by record
    J->>S: ledger and dns_name_status (fencing token checked)
  end
```

- **Triggers.** A configuration revision that changed a source (a route, a gateway group and its
  DNS target, a domain, a DNS name or a zone) marks the zones dirty. The replica that holds the
  lease reads the new revisions from the database
  ([Timers and limits](#timers-and-limits)), so no notification can be lost, in one process or in
  HA ([10](10-operations.md#high-availability)); a call inside the process, `dns_dirty`, marks
  zones the same way. Marks are debounced: the pass runs once the debounce has passed since the
  first. A pass for a trigger first compiles the zone and ends there when the compiled records and
  names equal those of its last clean pass, so a revision that changes nothing a zone publishes
  costs no request to the provider. A full pass over every zone, which does list the provider,
  runs on a timer, when a replica takes over the lease, and on "Sync now". A name's reserved
  status follows the instance settings only at the next full pass.
- **Determinism.** The desired set is a pure function of one read transaction, like a snapshot.
  Two replicas compute the same plan and the same plan hash.
- **One writer.** The job runs under the `dns` lease with a fencing token
  ([06](06-data-model.md#system)). The fencing token protects database commits, not Cloudflare. So
  the job checks right before every batch that its lease is valid for at least the safety margin.
  For that the lease handle carries its expiry: the time the lease ends, set when the lease is
  taken and moved on at every renewal, and read from the database row `leases.expires_at`
  ([06](06-data-model.md#system)). A handle whose renewal failed keeps its old expiry, so it runs
  out and the job sends no batch ([D164](14-open-decisions.md#engineering)). A handle that was
  not taken from the database has no expiry and sends none either. All writes are
  idempotent, and the next pass converges.
- **Names.** The pass records each name's `dns_status` in the transaction that commits it: a name
  is `published` once nothing is left to write at it, `pending` while a change is not sent or the
  provider could not be reached (a published name stays as it was then), `conflict` with the kind
  of conflict, `error` with the provider's reason, and `held`, `ambiguous` or `not_managed` as the
  compiler says. The zone's `provider_status` and `last_synced_at` are recorded with it. A pass that
  fails because the provider fails is not an error of the job: the zone is tried again at the next
  trigger or full pass.
- **Type changes** (CNAME ↔ A/AAAA, e.g. after the DNS target changed) are a delete and a create
  in the same batch.

### Batches, failures and the rate budget

- Changes are sent through the batch endpoint. Cloudflare applies a batch all-or-nothing, in the
  order deletes, patches, puts, posts; it propagates the records individually
  [F cf:dns/manage-dns-records/how-to/batch-record-changes].
- A plan of more than the limit in [Timers and limits](#timers-and-limits) is sent as several
  batches in order, deletes first.
- If the provider refuses a batch because of a record (an HTTP 4xx other than 401, 403, 404 and
  429, or a request the client refused before sending), the job retries its operations one by one,
  so one bad record does not block the others — the same rule as for agents
  ([03](03-connections.md#configuration-reconciliation)). The failing name gets `dns_status = error`
  with the provider's reason, and its ledger row `error` with the same reason; the next pass tries
  it again and reuses the row. Any other failure is [fail-static](#fail-static).
- **Rate budget.** Cloudflare allows 1 200 requests per 5 minutes **per Cloudflare user**, counting
  dashboard and API together; a 429 blocks all API calls of that user for the next 5 minutes, and
  the response carries `retry-after` [F cf:fundamentals/api/reference/limits]. rpmgr cannot see
  which Cloudflare user a token belongs to [V VB-09], so it budgets per provider well below the
  limit, honours `retry-after`, and marks the zone `rate_limited` meanwhile. The budget is one
  database row per provider, holding the request window and the `retry-after` block. The DNS job
  and the DNS-01 adapter take each request from it in a transaction, on whichever replica they
  run, so replicas never add up past it. DNS-01 may use at most half of the window
  ([D164](14-open-decisions.md#engineering)).
  - The provider client takes one request from the budget before each HTTP request it sends, a page
    of a listing as much as a batch. A request the budget does not lend is not sent: the call
    fails as rate-limited, until the end of the window or of the block.
  - A 429 sets the block for every replica and every taker from its `retry-after`, from the default
    block when there is none, and never shortens a block that holds. A block is cut to the longest
    block in [Timers and limits](#timers-and-limits).
  - The replicas' clocks differ a little, and the row holds times that one replica wrote and
    another reads. A window that started in the reader's future stays open, so the budget is never
    wider than it says, and one that started more than a window ahead is not honoured, so a clock
    far ahead never locks the others out.

  [R] Use an account-owned token, or a dedicated Cloudflare user, for rpmgr, so a burst never locks
  a human out of the dashboard.

### Fail-static

If the provider is unreachable, rate-limited or rejects the token, the job **deletes nothing and
changes nothing**. Published records keep serving; names show `pending`; the zone shows the
provider status, and an alert fires ([10](10-operations.md#suggested-alerts)). The next successful
pass catches up.

- **What counts.** A transport error, a timeout, an HTTP 5xx, 401, 403, 404 and 429 stop the pass
  at once, also in the middle of a batch series or of the retry record by record: the request
  after it is never sent. What was written before it is recorded in the ledger; the rows of the
  rest stay `creating` or `deleting`, and the provider's records stay as they are. A lost lease or a
  lease that will not outlast the next batch stops it the same way.

## Held zones and plan approval

A held zone computes plans but writes nothing until a plan is approved. Each pass of a held zone
reads the provider's records, plans, and stores the plan and its hash with the zone; the zone's
`held_reason` says why it is held: `imported`, `restored`, `deletion_guard` (below) or
`plan_changed`.

```mermaid
flowchart LR
  I[Zone imported] --> H[held<br/>plan stored with its hash]
  R[Database restored<br/>new db_epoch] --> H
  G[Pass would remove more names<br/>than delete_threshold] --> H
  H --> V[Owner or Admin reviews<br/>the plan · step-up]
  V -->|approve hash| A[active<br/>plan applied]
  V -->|plan changed meanwhile| H
```

- **Who approves.** An Owner or Admin of the zone's org, with step-up; the Instance Admin for
  system-org zones ([04](04-security.md#human-authentication-and-sessions)).
- **Approval is bound to the plan hash.** The plan is computed again when the approval comes in. If
  sources or provider records changed since the plan was shown, approval fails with `PLAN_CHANGED`,
  nothing changes and the new plan is shown ([07](07-api.md#errors)).
- **An approval is used once.** It makes the zone `active` and stores the approved hash. The next
  pass applies the plan only if it has that hash, whatever it removes, and then the approval is
  used up. A pass whose plan has another hash holds the zone again with `plan_changed` and the new
  plan. Later passes are subject to the deletion guard again.
- **Only a held zone is approved.** A `disabled` zone, such as after `restore --dns-disabled`, is
  refused with `ZONE_NOT_HELD`: approving there would fight production.
- **Enabling.** An Owner or Admin, with a step-up, moves a `disabled` zone to `held` (`enabled`).
  That writes nothing: the zone plans again and needs an approved plan like any held zone.
- **After import.** The first plan shows what rpmgr will create, the conflicts it found and which
  foreign wildcards it will shadow.
- **Deletion guard.** A pass that would remove all address records of more than the zone's
  `delete_threshold` names holds the zone with `deletion_guard`, writes nothing and stores the
  plan. Replacing records is not counted: a name that keeps an address record, or whose address
  record is replaced by another, is no removal. `delete_threshold = 0` makes every removal need
  approval.
- **After a restore.** A restore creates a new `db_epoch`
  ([10](10-operations.md#backup-and-restore)), and every zone starts held. The plan shows:
  - records created after the backup as `orphaned` (delete, or re-link);
  - records deleted after the backup as creates;
  - adopted records whose original content changed since (not shown yet, [#1113](https://github.com/felix-homelab/rpmgr/issues/1113)).

  `rpmgr restore --dns-disabled` sets every zone to `disabled`, for a clone restored into staging
  with the same trust domain and KEK. Otherwise approving there would fight production.

### The plan and its hash

The planner (`internal/dns/plan`) is a pure function of the desired records, the provider's records
and the ledger rows. The plan lists creates, updates, deletes, conflicts, orphans, wildcard shadows
and lost rows.

- **Only owned records are written.** An update or delete names a record that has a ledger row. A
  foreign record is never in a write list; where it is in the way, the name is a conflict and
  nothing is written at it ([Conflicts](#conflicts)). Names the compiler keeps
  ([Compile result](#compile-result)), reserved names and names at or below an NS delegation
  are left alone, including their owned records.
- **Lost rows** are ledger rows whose record is gone at the provider. A desired record is created
  again.
- **Matching.** Records are equal by type and content: addresses by value, a CNAME without case and
  trailing dot, a TXT without the quotes a provider may add. A changed TTL or proxy flag is an
  update. Unmatched records of one type are paired into updates; a change of type is a delete and a
  create. An update keeps the record's marker comment.
- **The hash** is the SHA-256, in lower-case hex, of the plan's canonical text: the line
  `rpmgr-dns-plan/1`, then one line per item (creates, updates, deletes, conflicts with their
  records, orphans, shadows, lost rows), each field written as a Go-quoted string, in the order name,
  type, content, ID. The same input in any order gives the same hash, and any change of a desired or
  provider record the plan shows changes it. The field list is in the package documentation of
  `plan.Plan.Encode`.

## Connecting, importing and disconnecting

1. **Connect.** An Owner or Admin (Instance Admin for the system org) enters an API token, with
   step-up. rpmgr accepts **API tokens only**; there is no field for an email and Global API Key.
   - The token is checked with `GET /user/tokens/verify`, or `GET /accounts/{id}/tokens/verify` for
     an account-owned token [F cf-api:openapi.json].
   - It needs **Zone Read** and **DNS Write** [F cf:fundamentals/api/reference/permissions].
   - [R] Restrict it to the zones rpmgr manages and to the controller's egress addresses, and give
     it an expiry [F cf:fundamentals/api/get-started/create-token].
   - The token is stored write-only, encrypted under the KEK
     ([04](04-security.md#secrets-at-rest-and-in-logs)). It is checked first, and a token the provider
     refuses, or reports as expired or disabled, is not stored.
   - [R] A value shaped like a Global API Key (37 hexadecimal characters) is refused before anything
     is sent, so that such a key never reaches the provider's API from rpmgr.
   - A token that expires within the warning period of [Timers and limits](#timers-and-limits) is
     flagged in the provider's view. The hourly token check records whether the provider still
     accepts the token and when it expires; a provider that cannot be reached or rate-limits the
     check gives no verdict and changes nothing.
2. **Import.**
   - rpmgr lists the account's zones, all pages (at most 50 per page)
     [F cf-api:openapi.json `GET /zones`].
   - Only zones with status `active` and type `full` can be imported. A newly added zone stays
     `pending` until the domain's nameservers point at Cloudflare
     [F cf:dns/zone-setups/reference/domain-status], and adding one needs no proof of ownership
     [V VB-12]. In a partial (CNAME) setup, Cloudflare is not authoritative
     [F cf:dns/zone-setups/partial-setup] [V VB-12].
   - Import creates the managed zone (held) and, unless the org already has a verified domain
     covering it, a domain claim for the apex with `wildcard = true`. A claim the org already made
     for the apex is reused if it has the wildcard and refused if it has not, because a claim's
     wildcard cannot change. The claim stays `pending` until it is verified like any other: a zone
     at the provider is no proof of ownership, and neither is a record that only the provider's API
     shows ([12](12-testing-and-quality.md#security-testing)).
   - The existing rules apply: global uniqueness, and Instance-Admin approval for nested claims
     ([04](04-security.md#route-and-hostname-ownership)). A zone claimed by another org cannot be
     imported.
3. **Disconnect or remove a zone.**
   - By default the records stay at the provider and the ledger rows are dropped, so nothing that
     works stops working.
   - Removing the records instead goes through a plan and approval: the plan deletes every record
     rpmgr owns in the zone and no others, and the removal needs its hash and a step-up. The zone is
     disabled when the removal is approved, so that the job does not write it again. The API call
     writes nothing to the provider: the DNS job, under its lease, deletes the records of the
     approved plan and only those, then removes the zone, and the zone shows the removal as
     pending until then. If the provider fails, the next full pass or "Sync now" goes on; if a
     record the plan did not name is owned by then, the job deletes nothing and the zone stays
     disabled.
   - Rotating the token keeps everything: the new token is checked first and replaces the old one in
     the same provider. Deleting a provider needs a step-up and is refused while zones are imported
     from it.

Permission errors are per zone, because one token can have different rights per zone and the
verify call does not list permissions: a zone where the provider refuses access shows
`permission_denied`.

## Base domain

The instance setting `base_domain` names the domain under which the Instance Admin hands out
names to orgs ([D165](14-open-decisions.md#engineering)).

- Only the Instance Admin changes it, with a step-up; the change is audited.
- It must be a domain of the system org that is verified or marked trusted
  ([04](04-security.md#route-and-hostname-ownership)); anything else is refused.
- The Instance Admin delegates `<org-slug>.<base domain>` to an org as a claim with the method
  `delegated` ([D23](14-open-decisions.md#tenancy-and-data)). The claim keeps its FQDN: renaming
  the org's slug later changes neither the claim nor the names and certificates under it.
- Records of delegated names are published in the system org's managed zone, by the same job and
  rules as every other zone (publication rule 1).

## Domain verification

- **Authoritative answers.** The `_rpmgr-challenge` TXT record is queried at the zone's
  authoritative nameservers, not through the controller's resolver. Split-horizon DNS and negative
  caching would otherwise give wrong answers. This applies to managed and manual domains alike.
  The zone's nameservers are the NS records of the closest name, from the claim upwards, that has
  any; only they are looked up through the resolver. Each is asked without recursion, and only an
  answer with the authority flag counts; the value may be split into several strings. A claim
  keeps the error of its last check, such as no authoritative answer or a wrong value.
- **HTTP tokens** (R17). For a pending claim with the method `http`, every enabled gateway of the
  claim's org answers `GET http://<fqdn>/.well-known/rpmgr-challenge/<claim ID>` on port 80 with
  the challenge value, for the claimed name only and before any redirect. The controller fetches
  that URL and compares the body. Pointing the name at the org's own gateways is the proof; a
  gateway of another org does not serve the token.
- **Managed zones publish the TXT themselves** for pending claims of the same org (publication rule
  2). The proof is still the public answer, so verification means the same thing with or without a
  provider.
- **Schedule.** Pending claims are checked automatically ([Timers and limits](#timers-and-limits)),
  and with "check now".
- **Trusted domains** ([D13](14-open-decisions.md#tenancy-and-data)). A domain the Instance Admin
  marked trusted (`method = trusted`, Phase 1, [04](04-security.md#route-and-hostname-ownership))
  needs no proof. If another org later proves control of it with a TXT record,
  global uniqueness blocks the second claim and the Instance Admin decides.

## ACME DNS-01

- Hostnames in managed zones get their certificates via DNS-01. Others keep HTTP-01 and
  TLS-ALPN-01 ([04](04-security.md#controller-certificates)).
- certmagic does not write DNS records itself. Its DNS-01 solver calls a provider that implements
  libdns `RecordAppender` and `RecordDeleter` [F certmagic:solvers.go:589-592]. rpmgr implements
  both in an adapter that finds the managed zone for the name and uses that zone's provider and
  rate budget; the marker is the adapter's.
- Enabling DNS-01 on a certmagic issuer disables its other challenge types
  [F certmagic:README.md:408-422]. rpmgr therefore runs two certmagic configurations on the same
  storage and picks one per name. One certificate cache serves both and picks the configuration
  by the certificate's name, so a renewal uses the same challenge type as the first issuance
  ([S6](spikes/S6.md)).
- This gives wildcard certificates, and certificates issued before DNS points at a gateway, which
  the cutover needs ([11](11-migration.md#cutover-plan)).
- The DNS job ignores `_acme-challenge.*` names.

Rules of the adapter ([D166](14-open-decisions.md#engineering),
[D167](14-open-decisions.md#engineering)):

| Case | Rule |
|---|---|
| Zone `active` | The challenge TXT is written |
| Zone `held` | Written too. A hold stops the DNS job's records for routes and names, not the one-off challenge of a certificate; the TXT is deleted after the order and changes no name |
| Zone `disabled` | Refused; the certificate shows `failed` with the reason. A disabled zone may be used by another installation of the trust domain |
| Zone of another org | Never used. The hostname must lie under a verified domain of the route's org, and the zone must be that org's, or the system org's for a delegated name (publication rule 1) |
| Wildcard hostname, `acme` mode | Accepted only in a managed zone, whatever its `allow_wildcards`: that gate governs published records, not certificates. Outside a managed zone Phase 1's refusal stands ([04](04-security.md#controller-certificates)) |
| Zone removed or provider disconnected | New and renewing orders of its names fail with the reason; the certificate in use keeps serving |
| The controller's own certificate | Stays on HTTP-01 and TLS-ALPN-01, never DNS-01, so the controller's name does not depend on a provider token |

- **Marker.** The challenge TXT at `_acme-challenge.<name>` carries the comment
  `rpmgr <trust-domain> acme`. The adapter deletes a record only if its type, name, content and
  comment all equal what it wrote. A TXT of a `tls_passthrough` backend that runs its own DNS-01,
  or one added by hand, is never deleted. The record has no ledger row; it lives for one order,
  and the next order of the name removes a leftover of a crash: a TXT at the name with the same
  type and marker, found when the order writes its own. An order that overlaps another order of
  the same name loses its TXT then, fails and is retried.
- **Budget.** Its requests come from the provider's budget row, at most half of the window
  ([Batches, failures and the rate budget](#batches-failures-and-the-rate-budget)). A write takes
  one listing of the zone and one batch, a delete likewise. An order that the budget refuses, or
  that the provider answers with a 429, fails with the reason; its retry waits until the block
  ends, if that is later than the retry's own wait ([03](03-connections.md#timeouts-keepalive-and-backoff)).
- **Choice per name.** The job takes DNS-01 for a name that lies in a managed zone of the route's
  org, and HTTP-01 and TLS-ALPN-01 for every other. It makes the choice again on every order, so
  a zone that is removed takes its names back to HTTP-01, and its wildcard names, which have no
  other challenge, to `failed`; the certificate in use keeps serving. The zone of a hostname is
  the longest managed zone of the org that holds it, and the provider must name that zone as the
  one that holds the name; if the name lies in a delegated sub-zone elsewhere, the order fails.

## Proxied HTTP routes

A proxied name resolves to Cloudflare. Cloudflare terminates TLS and connects to the gateway.

- **Client address.** For a route with `dns_proxied`, the gateway takes the client address from
  `CF-Connecting-IP` [F cf:fundamentals/reference/http-headers], but only when the TCP peer is in
  Cloudflare's published ranges. `X-Forwarded-*` from these peers is not trusted. IP rules and
  rate limits then see the real client ([03](03-connections.md#http-routes)). For every other
  route the gateway's trusted-proxy CIDRs apply as before.
- **Ranges.**
  - A daily job reads `GET https://api.cloudflare.com/client/v4/ips`
    [F cf:fundamentals/concepts/cloudflare-ip-addresses]. It stores the ranges as an instance
    setting in a configuration transaction, so snapshots stay deterministic across HA replicas.
  - A fetched list is accepted only within sanity bounds ([Timers and limits](#timers-and-limits)).
    Otherwise the last accepted list stays, and an alert fires.
  - The binary embeds a fallback list for installations without egress.
- **What the operator must know:**
  - Cloudflare sees the plaintext of proxied routes ([04](04-security.md#threat-model)).
  - Set the zone's SSL/TLS mode to **Full (strict)**. The gateway's ACME certificates satisfy it
    [F cf:ssl/origin-configuration/ssl-modes/full-strict]. rpmgr does not read zone settings, so
    the token does not need that permission.
  - Proxied records always have automatic TTL [F cf:dns/manage-dns-records/reference/ttl].
  - Cloudflare proxies HTTPS only on a fixed set of ports, 443 among them
    [F cf:fundamentals/reference/network-ports].
  - Proxy limits on request size and duration apply [V VB-11].
- **Phase 3:** Authenticated Origin Pulls, available on all plans
  [F cf:ssl/origin-configuration/authenticated-origin-pull], and "accept only from Cloudflare" per
  route. Until then, the require-header rule can demand a secret header set by a Cloudflare
  transform rule ([05](05-features.md#edge-access-control-and-limits)).

## Cloudflare specifics

| Topic | Fact | How rpmgr uses it |
|---|---|---|
| Authentication | Bearer API tokens; the Global API Key is legacy and carries all of the user's permissions [F cf:fundamentals/api/get-started/keys] | API tokens only |
| Token scope | Zone resources, client-IP filter and expiry are configurable [F cf:fundamentals/api/get-started/create-token]; narrowest scope is a zone: a token scoped to one zone sees exactly that zone, and an under-scoped token gets HTTP 403 (code 10000) on reads and writes [F VB-12, run 2026-11-04] | Recommended in the connect form; expiry shown and alerted |
| Zones | Status `initializing`, `pending`, `active`, `moved`; types `full`, `partial`, `secondary`, `internal`; `per_page` ≤ 50 [F cf-api:openapi.json `GET /zones`] | Import `active` + `full` only; all pages |
| Batch | All-or-nothing; deletes, patches, puts, posts in that order; 200 records per batch on Free, 3 500 on paid plans [F cf:dns/manage-dns-records/how-to/batch-record-changes] | One batch per pass, ≤ 200 operations; per-record retry on failure |
| Comments, tags | Comments on all plans, ≤ 100 characters on Free, no line breaks; tags only Pro and above [F cf:dns/manage-dns-records/reference/record-attributes] | Marker in the comment; tags unused |
| Proxy | Only A, AAAA and CNAME can be proxied [F cf:dns/proxy-status]; non-HTTP TCP/UDP needs Spectrum [F cf:spectrum/protocols-per-plan] | Proxy only for `http` routes |
| Apex CNAME | Flattened on all plans [F cf:dns/cname-flattening/set-up-cname-flattening] | A `cname` DNS target also works at the zone apex |
| CNAME across accounts | A proxied CNAME to a name in another Cloudflare account may be refused [V VB-11] | Use an `addresses` target for shared gateway groups if so |
| Rate limit | 1 200 requests / 5 min per user; 429 blocks for 5 min [F cf:fundamentals/api/reference/limits] | Budget per provider, `retry-after` honoured |

The API base URL is compiled in. Only tests override it, through a constructor of the `rpmgrtest`
build tag ([D60](14-open-decisions.md#engineering)); there is no runtime setting, so not even an
Instance Admin can point rpmgr at a server that collects other orgs' tokens. The client honours
`HTTPS_PROXY` ([10](10-operations.md#ports)), connects over TLS 1.2 or later against the system
roots as for other third-party servers ([04](04-security.md)), and follows no redirect, so the
token never goes elsewhere. It sends an identifier (zone, account, record) only if it is 32 lower-case hex characters
[V VB-26], and refuses any other before it sends anything. On a 429 without a usable `retry-after`
it waits the 5 minutes that Cloudflare blocks for. It refuses a batch above the limit below, and a record comment above
100 characters or with a line break, before it sends anything.

## Provider interface

```go
// internal/dns (sketch)
type Provider interface {
	Verify(ctx context.Context) (TokenInfo, error)            // validity, expiry
	ListZones(ctx context.Context) ([]Zone, error)            // all pages
	ListRecords(ctx context.Context, zoneID string) ([]Record, error)
	Apply(ctx context.Context, zoneID string, b Batch) error  // all-or-nothing if Caps().Batch
	Caps() Capabilities                                       // Comments, Proxy, Batch, ApexCNAME
}
```

- `internal/dns/cloudflare` implements it with `net/http` and about seven endpoints.
- The job, the certmagic adapter and the zone import use only this interface. Further providers are
  added natively, by demand: each is a new package plus its capability flags. A generic libdns-based
  provider is added only if it can be made safe without comment markers
  ([D25](14-open-decisions.md#tenancy-and-data)).
- The adapter implements libdns `RecordAppender` and `RecordDeleter` [F libdns:libdns.go:99,221].

## Timers and limits

| Item | Value |
|---|---|
| Debounce of `dns_dirty` notifications | 2 s |
| Full pass over every zone | 15 min, and on lease takeover |
| Lease safety margin before a batch | 30 s |
| Lease of the DNS job | TTL 90 s, renewed every 30 s: a lease of the default TTL ([03](03-connections.md#timeouts-keepalive-and-backoff)) could never outlast the margin, as the Cloudflare request timeout is as long |
| Look for new configuration revisions | every 1 s, by the replica that holds the lease |
| [R] Rate budget per provider | 300 requests / 5 min (Cloudflare allows 1 200 per user) |
| DNS-01 share of the budget | at most half |
| Default block after a 429 without `retry-after` | 5 min, as Cloudflare blocks |
| Longest block recorded | 1 h; a longer `retry-after` is cut to it |
| Operations per batch | ≤ 200 (Cloudflare Free limit) |
| Addresses in a DNS target | ≤ 16 |
| [R] Cloudflare API request | 30 s; answer at most 4 MiB; zones listed 50 per page |
| `delete_threshold` default | 10 names per pass and zone; 0 = every removal needs approval; [R] at most 1 000 |
| Drift stop window | a record corrected twice within 1 h is no longer corrected |
| Adopted-original staleness warning | 30 days |
| `default_ttl` | 300 s; [R] at least 60 s and at most 1 day; proxied records: automatic |
| Pending-claim checks | every 1 min for 15 min, then every 15 min; `failed` after 7 days; [R] by one controller node, 8 checks at once |
| [R] TXT proof query | 5 s per nameserver address, over UDP and again over TCP when truncated; at most 8 nameservers of a zone |
| [R] HTTP token fetch | 10 s; no redirect followed; at most 256 bytes; through the proxy the environment names |
| Token check | every 1 h; expiry warning 14 days ahead |
| Cloudflare IP ranges | refreshed every 24 h; accepted only if non-empty and at most half of the entries changed |
| DNS-01 propagation timeout | 2 min (certmagic default [F certmagic:solvers.go:532]) |
