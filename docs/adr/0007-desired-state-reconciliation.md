# ADR-0007: Desired-state reconciliation with versioned snapshots

Status: Accepted (decided by the product owner on 2026-10-06) · Date: 2026-10-06

## Context

A configuration path for distributed agents fails in predictable ways, and each one causes an
outage or misleading feedback. rpmgr's design must rule them out:

- **Success before the change is applied.** An API that answers "success" before any agent has
  applied the change leaves users guessing.
- **Stop before start.** An agent that stops its running configuration before the new one is built
  and started leaves no tunnels when anything fails in between.
- **Full restarts.** Restarting a whole gateway or connector for any change drops every tunnel on
  it, including the unchanged ones.
- **Unbounded waits.** Calls to agents without a deadline block forever when an agent is gone.
- **Polling.** Periodic full pulls add latency and load, and hide missed updates instead of
  repairing them.
- **Disagreeing state.** Storing a desired setting twice (for example an "enabled" flag) lets the
  copies disagree.

The design goal is "changes are safe" ([00](../00-vision-and-scope.md#goals)).

## Decision

Configuration flows by **desired-state reconciliation**, modelled on Envoy's xDS
([03](../03-connections.md#configuration-reconciliation)).

**Snapshots**
- The Controller compiles a **snapshot** per agent: the agent's complete configuration at one
  **revision**.
- The revision is `(db_epoch, seq)`. `seq` is an instance-wide `config_seq` single-row counter.
  Configuration transactions run at **READ COMMITTED** with `UPDATE config_seq … RETURNING` as their
  **first statement**; the row lock serialises all configuration writes (including store-enforced
  invariants), so commit order equals `seq` order. Revisions increase **within a `db_epoch`**;
  `db_epoch` is a fresh random UUIDv7 at init and on every restore
  ([03](../03-connections.md#revisions-and-ordering)).
- The compiler reads inside one **REPEATABLE READ** transaction (PostgreSQL) or one explicit read
  transaction (SQLite) and labels the snapshot with the `config_seq` it read in that transaction.
  Compilation is deterministic, so HA replicas produce identical bytes and hashes.
- Every resource in a snapshot carries a content hash. Large resources are referenced by hash.

**How an agent applies a snapshot**
1. **Validate.** Schema, semantics, signature and certificates are checked against the whole
   snapshot; the connector-local policy is evaluated per resource.
2. **Prepare.** The new runtime is built next to the old one.
3. **Swap.** The route table is exchanged in one atomic step.
4. **Acknowledge.** The agent replies `Applied{rev, resource_status[]}` right after the swap.
5. **Drain.** Removed resources drain asynchronously afterwards (30 s), so the acknowledgement
   never waits for a drain.

**Errors and last-known-good**
- `Rejected{rev, errors}` is **only** for snapshots that are malformed, semantically invalid, wrongly
  signed, or contain unparsable certificates. The agent then keeps running its **last-known-good**
  snapshot.
- The last-known-good snapshot is persisted on disk, signed by the controller.
- **Local-policy blocks are resource-level**, not rejections: the snapshot is `Applied`, and the
  affected route or target reports `not_ready(blocked_by_local_policy: <ip:port>)`. An unparsable
  policy file makes every target `not_ready(policy_invalid)` (deny all), and the snapshot is still
  `Applied` ([ADR-0009](0009-connector-local-policy.md)).
- Environmental errors (port in use, upstream down) are reported per resource and retried. They do
  not reject the snapshot.

**Revocation is not part of snapshot acceptance**
- The deny-list travels as a separate control message, `DenyListUpdate`, which carries the **full
  current set**. Entries are removed after the covered certificate's `NotAfter` (agents never accept
  expired certificates; `Reauth` checks the database, not the deny-list). Size: ~100 B per entry;
  with 1 000 ephemeral connectors per day and 7-day certificates that is ~7 000 entries ≈ 0.7 MB [T].
  [R] Above 1 MiB the controller sends deltas keyed by `(db_epoch, n)` with a periodic full set. It
  is applied unconditionally, independent of whether any snapshot was accepted; agents merge by
  **union** and drop an entry only after its own expiry, never because of a version number or a new
  `db_epoch`.
- Agents **persist** the deny-list next to the last-known-good snapshot (signed) and load it before
  accepting any session, so a gateway restarted while the controller is down still refuses revoked
  connectors. The deny-list digest is carried in the **control-session** `Hello` (gateways and
  connectors both have one); on mismatch the controller resends. `SessionHello` on data sessions
  does not carry it ([ADR-0008](0008-internal-ca-mtls-spiffe.md)).

**Ordering and change detection**
- Resources whose hashes are unchanged are not touched.
- An agent applies only revisions newer than its last applied one; when several are waiting, the
  newest wins.
- There is no polling. On reconnect, `Hello{last_applied}` lets the controller resend only if
  something differs.

**API**
- The API returns the revision immediately and tracks `apply_status` per agent: `pending`,
  `applied`, `rejected` or `apply_timeout` ([07](../07-api.md#writes-and-apply-status)).

**Data model**
- Desired state has exactly one `enabled` flag. Observed state lives in separate tables
  ([06](../06-data-model.md#desired-vs-observed-state)).

## Consequences

**Positive**

- A bad change never takes working tunnels down; the UI shows exactly why it was rejected, or which
  targets the host's local policy blocks.
- Unchanged routes keep their connections across any configuration change.
- "Saved" and "applied" are visibly different.
- Restarts and reconnects converge without polling.
- Agents can restart while the controller is down, from their signed last-known-good snapshot.

**Negative**

- Full snapshots are resent on every change. This is cheap at expected sizes. A delta protocol is
  deferred until snapshots approach the 4 MiB control-message limit.
- The single instance-wide revision counter (a row-locked counter row) serialises configuration
  writes. That is acceptable because configuration writes are rare, and it is what guarantees that
  commit order equals revision order.
- Agents must keep old and new runtime side by side during a swap, which briefly costs extra
  memory.
- The compiler must be deterministic. Map iteration order, timestamps and the like need care, and
  are covered by a golden-snapshot test ([12](../12-testing-and-quality.md)).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Imperative events | No ordering, no acknowledgement semantics, no recovery after missed events; needs polling as a crutch |
| Periodic full pull | Latency, load, and restart loops when the comparison of pulled and running configuration mismatches |
| Incremental xDS-style deltas from day one | More complex state machine; not needed at expected snapshot sizes |
| Kubernetes-style informers/watch on the database | Exposes database structure to agents; agents must not hold database credentials |
