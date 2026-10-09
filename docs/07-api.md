# 07 — API

> Status: Phase 1, being implemented. Tags: [F] fact · [R] recommendation · [T] target · [V] verify
> at implementation ([README](../README.md#how-to-read-these-documents)).

## Overview

| API | Package | Clients | Protocol |
|---|---|---|---|
| **Public API** | `rpmgr.v1` | Web UI, `rpmgr` CLI, scripts, Terraform provider (later) | ConnectRPC: Connect protocol (JSON or binary) over HTTP/1.1 or HTTP/2; gRPC and gRPC-Web on the same endpoints |
| **Agent protocol** | `rpmgr.agent.v1` | Gateways, connectors | gRPC over HTTP/2 with mutual TLS, grpc-go at both ends ([03](03-connections.md#control-session)) |

Both are defined in protobuf and managed with `buf` (lint, breaking-change detection, code
generation for Go and TypeScript); buf generates connect-go code for the public API and grpc-go
code for the agent protocol ([ADR-0016](adr/0016-connectrpc-public-api-grpc-go-agents.md)). The web
UI uses exactly the public API; there are no private UI endpoints.

The Connect protocol is plain HTTP: every unary method is `POST /<package>.<Service>/<Method>` with
a JSON body, so `curl` works without special tooling:

```sh
curl -s https://panel.example.com/rpmgr.v1.RouteService/GetRoute \
  -H "Authorization: Bearer $RPMGR_TOKEN" -H "Content-Type: application/json" \
  -d '{"id":"rte_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R"}'
```

## Authentication

| Client | Credential | Transport |
|---|---|---|
| Browser | `__Host-rpmgr_session` cookie | Same origin only; CSRF rules in [04](04-security.md#human-authentication-and-sessions) |
| CLI, scripts, integrations | API token: personal `rpmgr_pat_…` (Phase 1), service-account `rpmgr_sat_…` (Phase 2) | `Authorization: Bearer` header only |
| Agents | Client certificate | Mutual TLS; never a token |

Administrative commands run on the controller host itself (`rpmgr ca …`, `kek …`, `backup`,
`restore …`, `user reset-password`, `migrate`, `migrate-db`) do not use the API: they are
authorised by host access and audited as `local-cli` ([04](04-security.md#roles)).

Every method carries an `(rpmgr.v1.authz)` option naming the permission it needs, the request field
that identifies the target resource and whether it needs step-up; an unannotated method fails closed
([04](04-security.md#one-enforcement-point-with-defence-in-depth)). Secret fields carry
`(rpmgr.v1.sensitive)`. Both options are defined in `proto/rpmgr/v1/options.proto`. [R] A method on
an org's collection (`List…`, `Create…`) names the org in an `org_id` field, its resource field, as
AIP's `parent` does.

## Resource design

[R] Resource-oriented, in the style of Google's API Improvement Proposals:

| Method | Request | Notes |
|---|---|---|
| `Get<Resource>` | `id` | |
| `List<Resources>` | typed filter fields, `page_size` (default 50, max 500), `page_token` | Opaque, stable page tokens; ordered by ID (time-ordered) unless `order_by` is given. [R] A larger `page_size` is cut to 500; a token is bound to its query and authenticated, so one for another query, or altered, is `INVALID_ARGUMENT` |
| `Create<Resource>` | resource, `request_id` | `request_id` makes retries idempotent (deduplication window in [03](03-connections.md#timeouts-keepalive-and-backoff)). [R] Per caller and method: a retry gets the first response without a second change; the same ID with another request is `INVALID_ARGUMENT`, and `ABORTED` while the first request has not answered. A request that failed may run again |
| `Update<Resource>` | resource, `update_mask`, `etag` | Field mask lists exactly the fields to change; untouched fields are never reset. [R] Paths use proto field names, through singular messages with dots; an empty mask, an unknown field or one the method does not let clients change (output-only fields among them) is `INVALID_ARGUMENT` |
| `Delete<Resource>` | `id`, optional `etag`, `cascade` | Refuses when dependants exist unless `cascade` is set |

Field masks matter: a form that replaces the whole stored configuration silently deletes keys the
form does not model. With typed resources and explicit masks, an update can only change what it
names.

### Services

| Service | Main methods | Phase |
|---|---|---|
| `AuthService` | `Login`, `Logout`, `GetSession`, `StepUp` (a session, or a personal API token for itself, D63), `BeginWebAuthn`/`FinishWebAuthn`, `StartOIDC`/`FinishOIDC`, `ListSessions`, `RevokeSession`, `RequestPasswordReset` (only with SMTP configured; `UNAVAILABLE` without), `CompletePasswordReset` | 1 (WebAuthn, OIDC: 2) |
| `UserService` | `GetMe`, `UpdateMe`, `ChangePassword`, `EnrollTOTP`, `ConfirmTOTP`, `RemoveTOTP`, `RegenerateRecoveryCodes`, `ListUsers` (instance admin), `CreatePasswordResetLink` (one-time link; Owner/Admin for members, Instance Admin for any user) | 1 |
| `OrgService` | `GetOrg`, `UpdateOrg`, `ListMembers`, `UpdateMember`, `RemoveMember`, `CreateInvitation` (returns a one-time link; also e-mailed if SMTP is configured), `AcceptInvitation` | 1 (multi-org UI: 2) |
| `TokenService` | `CreateAPIToken`, `ListAPITokens`, `RevokeAPIToken`, `CreateServiceAccount`, … | Personal API tokens: 1; service accounts: 2 |
| `EnrollmentService` | `CreateEnrollmentToken` (connectors, also re-enrollment; `connectors.write`), `CreateGatewayEnrollmentToken` (a gateway an Admin created, R15; `infrastructure.write`), both with step-up and shown once; `ListEnrollmentTokens`, `RevokeEnrollmentToken`, `GetInstallCommand` | 1 |
| `ConnectorService` | `ListConnectors`, `GetConnector` (with its control session), `UpdateConnector` (name, labels, `transport`), `DecommissionConnector`, `GetConnectorStatus` (control session, data sessions as its gateways report them, routes it reports not ready) | 1 |
| `GatewayService` | `CreateGateway`, `GetGateway`, `ListGateways`, `UpdateGateway` (name, tunnel endpoints, `enabled`), `DecommissionGateway` (revokes the gateway's identity); CRUD on gateway groups and port pools; `SetPortQuota`, `ListPortQuotas`, `DeletePortQuota`; shared-group grants | 1 (shared-group grants: 2) |
| `RouteService` | CRUD on routes (`CreateRoute`, `GetRoute`, `ListRoutes`, `UpdateRoute`, `DeleteRoute`) and their targets (`CreateRouteTarget`, `GetRouteTarget` with its route's ID, `UpdateRouteTarget`, `DeleteRouteTarget`; a route shows its targets), `PreviewRoute` (compile without saving: the write's checks and each gateway's own, the route as it would be stored, the gateways and connectors it would reach). A hostname outside the org's verified domains is refused with `DOMAIN_NOT_VERIFIED`; ACME for a wildcard hostname with `WILDCARD_NEEDS_CERTIFICATE` (R42); a route in certificate mode names an uploaded certificate that covers each of its hostnames, or is refused with `CERTIFICATE_NOT_COVERING`. A tcp or udp route takes an explicit or a random port of its group's pools; `PORT_NOT_IN_POOL`, `POOL_EXHAUSTED` and `QUOTA_REACHED` refuse one. A route applies access policies of its org in the order of `policy_ids`, each once; one with a `basic_auth` rule only on an http route (`BASIC_AUTH_NOT_HTTP`) | 1 |
| `DomainService` | `CreateDomain` (returns the TXT record or HTTP token that proves the claim), `GetDomain`, `VerifyDomain`, `ListDomains`, `DeleteDomain` (refused while route hostnames lie under it), `MarkDomainTrusted` (Instance Admin, step-up), `DelegateDomain` and `ApproveDomainClaim` (Instance Admin, step-up) | 1 (`DelegateDomain`, `ApproveDomainClaim`: 2) |
| `CertificateService` | `UploadCertificate` (a chain and its key, checked as [04](04-security.md#controller-certificates) requires; the key is kept under the KEK and never returned), `GetCertificate`, `ListCertificates` (source, names, validity, status and the last ACME error; an uploaded certificate with the routes that serve it), `DeleteCertificate` (an uploaded certificate no route serves), `RenewCertificate` (an ACME certificate of a route in acme mode, renewed now even if not due, or obtained if it has none; the answer comes at once, and the outcome shows in the certificate); CRUD on CA bundles for HTTPS upstreams (`CreateCABundle`, `GetCABundle`, `ListCABundles`, `UpdateCABundle`, `DeleteCABundle`; shown with their certificates' subjects and expiry and the targets that use them, not deleted while one does) | 1 |
| `PkiService` | `GetPkiStatus` (the trust domain, the root's pin, and the CA's keys that have not expired, with their state and when the schedule replaces them), `RotateIntermediate` (replaces the intermediate before its half-life; the old one keeps verifying its leaves until it expires); Instance Admin, the rotation with step-up | 1 |
| `DnsProviderService` | `ConnectDnsProvider`, `ListDnsProviders`, `UpdateDnsProvider` (rename, rotate token), `DeleteDnsProvider`, `ListProviderZones` | 2 |
| `DnsZoneService` | `ImportZone`, `ListZones`, `UpdateZone` (gates), `RemoveZone` (keep or remove records), `PlanZoneSync`, `ApproveZonePlan` (plan hash), `SyncZone`, `ListZoneRecords` (owned and foreign, read live; Owner/Admin), `AdoptRecords`, `ReleaseRecord` (optionally restore the original) | 2 |
| `DnsNameService` | `CreateDnsName`, `GetDnsName`, `ListDnsNames`, `UpdateDnsName`, `DeleteDnsName` | 2 |
| `PolicyService` | CRUD on access policies (`CreateAccessPolicy`, `GetAccessPolicy`, `ListAccessPolicies`, `UpdateAccessPolicy`, `DeleteAccessPolicy`) with their rules in order (`ip_allow`, `ip_deny`, `basic_auth`; CIDRs kept in their masked form); a policy shows the routes that apply it and cannot be deleted while one does. An update replaces the rules as a whole. Basic-auth passwords are write-only: the controller hashes them ([04](04-security.md#secrets-at-rest-and-in-logs)) under the account password rules, and in an update a user without a password keeps the one of its name. A `basic_auth` rule on a policy that a route other than an http route applies is refused with `BASIC_AUTH_NOT_HTTP`; health checks | 2 (basic auth, IP rules: 1) |
| `PrivateServiceService` | private services and visitor grants | 2 |
| `StatusService` | `GetApplyStatus`, `WatchApplyStatus` (stream), `WatchEvents` (stream) | 1 |
| `LogService` | `StreamLogs` (server stream from an agent via an imperative operation) | 2 |
| `MetricsService` | `GetRouteTraffic`, `GetOverview` (rollups) | 1 |
| `AuditService` | `ListAuditEntries`, `ExportAudit`, `VerifyAuditChain` | 1 (export: 2) |
| `SettingsService` | `GetInstanceSettings`, `UpdateInstanceSettings` (including `default_transport`), `SetSmtpPassword` (write-only; a read says only whether it is set), all for the Instance Admin; `GetOrgSettings` (members), `UpdateOrgSettings` (Owners; a change of the MFA requirement needs a step-up, and a default gateway group must be one of the org's). Updates name their fields in a mask; a named field the request does not set returns to its default | 1 |
| `ReleaseService` | `ListReleases`, `UploadRelease` (air-gapped installs), `CreateRollout`, `GetRollout`, `PauseRollout`; the release check and update channel are instance settings (`SettingsService`) | 2 |
| `ManifestService` | `ExportManifests` (an org's resources as YAML manifests: all, of the kinds named, or the resources named), `Plan`, `Apply` (declarative manifests) | 1 (`Plan`, `Apply`: 2) |
| `WebhookService` | webhook endpoints and deliveries | 2 |
| `VirtualNetworkService`, `FunctionService`, `ShellService` | — | 3 |

### Example: a route

```protobuf
// rpmgr/v1/route.proto (sketch)
message Route {
  string id = 1;                       // rte_…, output only
  string name = 2;                     // unique per org
  string gateway_group_id = 3;
  bool enabled = 4;                    // the only desired on/off switch
  map<string, string> labels = 5;
  oneof spec {
    HttpRouteSpec http = 10;
    TcpRouteSpec tcp = 11;
    UdpRouteSpec udp = 12;
    TlsPassthroughRouteSpec tls_passthrough = 13;
  }
  repeated Target targets = 20;
  repeated string policy_ids = 21;
  RouteLimits limits = 22;
  TransportPolicy transport = 23;      // AUTO, QUIC, H2; UNSPECIFIED = the connector's (03)
  string etag = 30;                    // output only; send back on update
  RouteStatus status = 31;             // output only; derived from observed state (see 06-data-model)
  repeated HostnameDnsStatus dns_status = 32;  // output only; per hostname, not part of status
}

message HttpRouteSpec {
  repeated string hostnames = 1 [(buf.validate.field).repeated = {min_items: 1, max_items: 100}];
  string path_prefix = 2;              // longest prefix wins among routes sharing a hostname
  TlsMode tls_mode = 3;                // ACME or an uploaded certificate
  Port80Mode port80 = 4;               // REDIRECT (default), SERVE or OFF; ACME HTTP-01 always works
  map<string, string> request_headers_set = 5;
  map<string, string> response_headers_set = 6;
  bool dns_proxied = 7;                // Phase 2: opt into Cloudflare's proxy (15-dns)
}

message Target {
  string id = 1;
  string connector_id = 2;
  oneof address { HostPort host_port = 3; string unix_path = 4; }
  UpstreamProtocol upstream_protocol = 5;   // TCP, HTTP, HTTPS (verified), H2C; one per http route
  ProxyProtocol proxy_protocol = 6;         // NONE, V1, V2
  uint32 weight = 7;
  uint32 priority = 8;                      // lower = preferred; higher priorities are failover
  string health_check_id = 9;
  bool enabled = 10;
}
```

```protobuf
// rpmgr/v1/dns.proto (sketch)
message DnsProvider {
  string id = 1;                       // dnp_…, output only
  string name = 2;                     // unique per org
  oneof kind { CloudflareProvider cloudflare = 10; }
  ProviderStatus status = 30;          // output only: OK, INVALID
  google.protobuf.Timestamp token_expires_at = 31;  // output only
  string etag = 32;                    // output only
}

message CloudflareProvider {
  string api_token = 1 [(rpmgr.v1.sensitive) = true];  // write-only, never returned
  string account_id = 2;               // set only for account-owned tokens
}
```

## Writes and apply status

Saving a configuration change and the change being active on agents are two different events; the
API reports both ([03](03-connections.md#configuration-reconciliation)).

- Every mutating response contains `revision` and `apply_status`:

```json
{ "route": { "id": "rte_…", "etag": "7" },
  "revision": { "db_epoch": "0192f6a4-7c3e-7b1a-9f2d-3c4b5a6d7e8f", "seq": 4211 },
  "apply_status": { "state": "PENDING", "agents_total": 3, "agents_applied": 0 } }
```

- `apply_status.state` is `PENDING`, `APPLIED`, `REJECTED` (with per-agent structured reasons) or
  `APPLY_TIMEOUT` (an agent did not answer within the apply acknowledgement period,
  [03](03-connections.md#timeouts-keepalive-and-backoff)). Offline agents are listed separately and
  do not hold the state at `PENDING` forever.
- A caller may set `wait = APPLIED` with a timeout (max 30 s) on any mutation, as the request
  header `Rpmgr-Wait-Applied: <duration>` (for example `30s`); the response then returns once the
  revision is applied, rejected or timed out, or the wait passes, with the state then. A duration
  that does not parse is no wait. The CLI does this by default.
- `StatusService.WatchApplyStatus(revision)` streams progress; the UI uses it to show
  "pending → applied" live after every save. `GetApplyStatus(revision)` returns it once.
- The status is derived over the org's agents with a live control session: an agent applied the
  revision when it runs that revision or a later one, which an agent whose snapshot the revision
  did not change does at once; it rejected or timed out when the newest snapshot it was sent, of
  that revision or later, was rejected or not answered; it is pending otherwise, also when it runs
  a revision of an older database epoch. A watch ends at the final state, or after 60 s.
- DNS configuration (managed zones, DNS names, `dns_target`, `dns_proxied`) is written in ordinary
  configuration transactions with a revision. Publication at the DNS provider is **not** part of
  `apply_status` and `wait = APPLIED` does not wait for it; it is reported as `dns_status` per
  hostname and streamed by `WatchEvents` ([15](15-dns.md#publication-rules)).

## Concurrency

- Every mutable resource has a `version` counter, exposed as `etag` (its decimal digits).
- `Update…` and `Delete…` from the UI always send the `etag` they read. If the stored version
  differs, the request fails with `FAILED_PRECONDITION` (`reason = ETAG_MISMATCH`) and the current
  resource, so the UI can show a merge view instead of overwriting someone else's change.
- The CLI sends the etag from its last read; `--force` omits it.

## Errors

- Connect/gRPC status codes, with structured details:

| Situation | Code | Detail |
|---|---|---|
| Validation failed | `INVALID_ARGUMENT` | List of field violations (`field`, `rule`, `message`) from protovalidate |
| Not found, or exists in another org | `NOT_FOUND` | — (no existence oracle across orgs) |
| Permission missing | `PERMISSION_DENIED` | `reason = PERMISSION_MISSING`, metadata `permission` |
| Step-up required | `UNAUTHENTICATED` | `reason = STEP_UP_REQUIRED` |
| Second factor needed: at login, or by the org's policy | `UNAUTHENTICATED` (login), `PERMISSION_DENIED` (policy) | `reason = MFA_REQUIRED` |
| Etag mismatch, dependants exist, domain not verified, port taken | `FAILED_PRECONDITION` | `reason` + metadata |
| DNS (Phase 2): zone not managed or not `active`, proxied or wildcard name not allowed by the zone, plan changed since it was shown, provider refuses the token for this zone | `FAILED_PRECONDITION` | `reason` = `ZONE_NOT_MANAGED`, `ZONE_NOT_ACTIVE`, `PROXY_NOT_ALLOWED`, `WILDCARD_NOT_ALLOWED`, `PLAN_CHANGED`, `PROVIDER_PERMISSION_DENIED` |
| Rate limited | `RESOURCE_EXHAUSTED` | retry-after (`google.rpc.RetryInfo`) |
| Agent unreachable for an imperative operation; DNS provider unreachable for a live call (`ListProviderZones`, `ListZoneRecords`, `PlanZoneSync`) | `UNAVAILABLE` | — |
| Operation exceeded its deadline | `DEADLINE_EXCEEDED` | — |

- [R] A `reason` comes as `google.rpc.ErrorInfo` with domain `rpmgr.v1`; field violations come as
  `buf.validate.Violations`.
- Error messages never contain secrets or other orgs' data. [R] An error a method did not write
  for the client is `INTERNAL` without its text, which goes to the log.
- **Validation is server-authoritative** (protovalidate annotations in the protos). The UI runs its
  own checks for responsiveness only ([09](09-web-ui.md)).

## Events and streaming

- `StatusService.WatchEvents` is a server stream of resource changes and status changes for the
  caller's org. It needs `org.read`, which lets every role read every resource of the org, so P1
  filters it no further. The UI uses it instead of polling.
  - **Resource changes:** one event per configuration revision of the org, in revision order, with
    the IDs of the resources it changed, the actor and the time. The client reads those resources
    again. A revision that a controller job makes for an org, such as an ACME renewal or the purge
    of an ephemeral connector, belongs to that org. Instance-wide revisions are in no org's
    stream.
  - **Resume:** every event carries a resume token. A client that reconnects with its last token
    gets every change since, so it misses nothing. Without a token, the stream starts with the next
    change. A token of another database epoch (after a restore) gets one `reset` event first, and
    the client reads everything again. A token the stream did not give is refused with
    `INVALID_ARGUMENT`.
  - **Status changes:** an event without a revision names the routes, gateways and connectors
    whose status changed: a route's derived status
    ([06](06-data-model.md#desired-vs-observed-state)) or an agent's control session going up or
    down. The stream compares the status with the one it saw when it opened, so a client reads the
    status it shows when it opens the stream. Status changes are not replayed after a reconnect,
    and their events carry the last resume token.
- `LogService.StreamLogs(connector_id, filter)` opens an imperative log operation on the agent
  ([03](03-connections.md#control-session)) and streams lines. Log lines pass through the agent's
  redaction before they leave the host.
- Server streams work over HTTP/1.1 and HTTP/2 with the Connect protocol, so no WebSocket is needed
  except for the Phase 3 terminal.

## Declarative manifests

[R] `rpmgr apply -f` accepts YAML manifests whose schema is the protobuf JSON mapping of the public
resources, plus `kind` and `metadata.name`:

```yaml
kind: Route
metadata: { name: nas-web, labels: { site: home } }
spec:
  gatewayGroup: eu
  http:
    hostnames: [nas.example.com]
    tlsMode: TLS_MODE_ACME
  targets:
    - connector: home-connector
      hostPort: { host: 192.168.10.20, port: 5000 }
      upstreamProtocol: UPSTREAM_PROTOCOL_HTTP
  policies: [office-ip-only]
```

- [R] **Phase 1 writes manifests; it does not apply them** ([D58](14-open-decisions.md#project-and-process)).
  The kinds are `Route` (with its targets), `AccessPolicy`, `GatewayGroup`, `Gateway`,
  `PortPool`, `Domain`, `Connector` and `CABundle`.
  - `metadata.name` is the resource's name, a domain's FQDN, or the ID of a resource without a
    name (a port pool).
  - The spec has no field the server sets: no ID, etag, status, times or lists of dependants.
  - It names gateway groups, access policies, connectors and CA bundles by their names
    (`gatewayGroup`, `policies`, `connector`, `caBundle`). A certificate, which has no name, keeps
    its ID.
  - Fields marked `sensitive` are never written, so a basic-auth user appears without a
    password. Certificates and their keys are not a kind.
  - `ManifestService.ExportManifests` writes them for the CLI and the UI's YAML tab: every kind,
    the kinds named, or the resources named. Decommissioned gateways and connectors are left out.

- `ManifestService.Plan` returns the diff against the current state; `Apply` performs it in **one
  transaction** (one revision). Manifests reference other resources by name; the server resolves
  names to IDs.
- The same format is used by the UI's per-resource YAML view and export, and by the importer's
  output ([11](11-migration.md)).
- DNS (Phase 2): `kind: DnsName` and the route field `dnsProxied` are manifest resources. Managed
  zones are referenced by name but never created by a manifest, because importing a zone calls the
  provider and cannot happen inside the `Apply` transaction. DNS providers never appear in
  manifests: they carry a secret.

## Webhooks (Phase 2)

- Event types: route status changes, agent connect/disconnect, apply rejected, certificate expiring
  or failed, enrollment, security events; DNS conflict, DNS zone held, DNS sync failing,
  DNS-provider token invalid or expiring.
- Delivery: `POST` with JSON, `Rpmgr-Signature: t=<unix>,v1=<HMAC-SHA256(secret, t.body)>`, a
  delivery timeout ([03](03-connections.md#timeouts-keepalive-and-backoff)), TLS verification on,
  retries with backoff, delivery log in the UI. Receivers should reject signatures older than the
  maximum signature age defined in [04](04-security.md#audit-log). (Timestamps are used here
  because webhook receivers are third-party HTTP endpoints without mutual TLS; rpmgr-internal
  authentication never uses them.)

## Agent protocol catalogue

Defined in [03-connections.md](03-connections.md); summarised here for reference.

| Channel | Message | Direction | Purpose |
|---|---|---|---|
| Enrollment | `Enroll` | agent → controller | Token + CSR → certificate, trust bundle |
| Control `Session` | `Hello` / `Welcome` | both | Identity, last applied revision, capabilities, versions, clocks |
| | `Snapshot` | controller → agent | Desired state at a revision, signed |
| | `Applied` / `Rejected` | agent → controller | Result of applying a revision |
| | `Status` | agent → controller | Health, route readiness, counters |
| | `Open` | controller → agent | Start an imperative operation (logs, diagnostics, shell) |
| | `Drain` / `Goodbye` | controller → agent | Reconnect elsewhere / session ends (superseded, revoked, upgrade required) |
| | `DenyListUpdate` | controller → agent | Revocations; applied unconditionally, independent of snapshots |
| | `AcmeChallenge` / `OpResult` | controller → gateway / back | An ACME HTTP-01 or TLS-ALPN-01 challenge the gateway answers (add, remove), and its acknowledgement |
| Control unary | `Renew`, `FetchResource` | agent → controller | Certificate renewal; large resources by hash |
| `Reauth` (SNI `reauth.controller.<td>`) | `Reauth` | agent → controller | New certificate for an agent whose certificate expired within the grace period; mutual TLS with the expired certificate |
| Control `Attach` | `AttachFrame` | both | Data of an imperative operation |
| Data session control stream | `SessionHello` / `SessionWelcome`, `Ping`/`Pong`, `RouteHealth`, `OpenRequest` / `OpenRejected`, `Drain`, `P2PCandidates`, `Goodbye` | both | Data-session control; `OpenRequest` asks the gateway to open a stream (TCP transport) |
| Data user/relay stream | `StreamOpen` / `StreamResult` | opener → other side / back | Per-connection preamble; the opener is the gateway, or the connector for `RELAY_OUT` and `CONTROL_PASSTHROUGH` on QUIC ([03](03-connections.md#framing)) |

## Versioning and compatibility

- Packages are versioned: `rpmgr.v1`, `rpmgr.agent.v1`. Within a version, changes are **additive only**
  (new fields, new methods, new enum values); `buf breaking` enforces this in CI. Before v1.0.0 a
  breaking change passes only in a PR labelled `breaking` with `!` in its title
  ([D56](14-open-decisions.md#engineering)).
- Removing or changing anything requires `v2`. Adding `rpmgr.v2` is additive, so it ships in a
  MINOR release, served alongside `v1`, with deprecation warnings for `v1` in responses and in the
  UI. Removing `v1` is a MAJOR release, at least two minor releases after `v2` appeared
  ([RELEASING](../RELEASING.md#versioning)).
- Clients must ignore unknown fields and treat unknown enum values as "unspecified".
- The agent protocol's compatibility rules (ALPN major version, capability strings,
  `min_agent_version`) are in [03](03-connections.md#versioning-and-capabilities) and
  [10](10-operations.md#upgrades-and-version-skew).
