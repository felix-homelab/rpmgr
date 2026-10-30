# 07 — API

> Status: Phase 1 is implemented. Tags: [F] fact · [R] recommendation · [T] target · [V] verify
> at implementation ([README](README.md#how-to-read-these-documents)).

## Overview

| API | Package | Clients | Protocol |
|---|---|---|---|
| **Public API** | `rpmgr.v1` | Web UI, `rpmgr` CLI, scripts, Terraform provider (later) | ConnectRPC: Connect protocol (JSON or binary) over HTTP/1.1 or HTTP/2; gRPC and gRPC-Web on the same endpoints |
| **Agent protocol** | `rpmgr.agent.v1` | Gateways, connectors | gRPC over HTTP/2 with mutual TLS, grpc-go at both ends ([03](03-connections.md#control-session)) |

Both are defined in protobuf and managed with `buf` (lint, breaking-change detection, code
generation for Go and TypeScript); buf generates connect-go code for the public API and grpc-go
code for the agent protocol ([ADR-0016](adr/0016-connectrpc-public-api-grpc-go-agents.md)). The web
UI uses exactly the public API; there are no private UI endpoints.

The controller's web server, which serves the UI and the public API, offers ALPN `h2` before
`http/1.1` and `http/1.0` wherever TLS ends at the controller: on its own port 443, behind
all-in-one's gateway and behind a gateway's `controller.passthrough`, both of which forward the
handshake untouched ([03](03-connections.md#transport), [D92](14-open-decisions.md#engineering)).
Connect, gRPC and gRPC-Web clients call the API over HTTP/2, and Connect and gRPC-Web clients over
HTTP/1.1 as well; a client that offers no ALPN gets HTTP/1.1. When the controller gets its own
certificate by ACME, the listener offers `acme-tls/1` as well, last, for the CA's TLS-ALPN-01
check ([04](04-security.md#controller-certificates)). The security headers, the CSP and the
cross-origin and content-type checks are the same over every version
([04](04-security.md#human-authentication-and-sessions)).

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
| `AuthService` | `Login`, `Logout`, `GetSession` (also the version the controller runs, D80), `StepUp` (a session, or a personal API token for itself, D63), `BeginWebAuthn`/`FinishWebAuthn`, `StartOIDC`/`FinishOIDC`, `ListSessions`, `RevokeSession`, `RequestPasswordReset` (only with SMTP configured; `UNAVAILABLE` without), `CompletePasswordReset` | 1 (WebAuthn, OIDC: 2) |
| `UserService` | `GetMe` (with the instance's restore review), `UpdateMe` (display name and web UI theme), `ChangePassword`, `EnrollTOTP`, `ConfirmTOTP`, `RemoveTOTP`, `RegenerateRecoveryCodes`, `ListUsers` (instance admin), `CreatePasswordResetLink` (one-time link), `RemoveUserTOTP` (another user's lost second factor), `SetInstanceAdmin` (instance admin; account recovery as in [04](04-security.md#account-recovery)) | 1 |
| `OrgService` | `GetOrg`, `UpdateOrg`, `ListMembers`, `UpdateMember`, `RemoveMember`, `CreateInvitation` (returns a one-time link; also e-mailed if SMTP is configured), `AcceptInvitation`; in restore review ([10](10-operations.md#backup-and-restore)), for an Owner with step-up: `ListSuspendedAPITokens`, `ResumeAPIToken`, `ConfirmRestoreReview` (the org's review only) | 1 (multi-org UI: 2) |
| `TokenService` | `CreateAPIToken`, `ListAPITokens`, `RevokeAPIToken`, `CreateServiceAccount`, … | Personal API tokens: 1; service accounts: 2 |
| `EnrollmentService` | `CreateEnrollmentToken` (connectors, also re-enrollment; `connectors.write`), `CreateGatewayEnrollmentToken` (a gateway an Admin created, R15; `infrastructure.write`), both with step-up and shown once; `ListEnrollmentTokens`, `RevokeEnrollmentToken`, `GetInstallCommand` | 1 |
| `ConnectorService` | `ListConnectors`, `GetConnector` (with its control session), `UpdateConnector` (name, labels, `transport`), `EndConnectorDrain` (the same for a connector, `connectors.write`; its `session.draining` carries the old process, [D160](14-open-decisions.md#engineering)), `DecommissionConnector` (with the routes it deletes, [D78](14-open-decisions.md#engineering); `FAILED_PRECONDITION` for the all-in-one's own connector, whose `built_in` is set, [ADR-0019](adr/0019-all-in-one-runs-a-connector.md)), `GetConnectorStatus` (control session, data sessions as its gateways report them, routes it reports not ready) | 1 |
| `GatewayService` | `CreateGateway`, `GetGateway`, `ListGateways`, `UpdateGateway` (name, tunnel endpoints, `enabled`, and in Phase 2 `wss_hostname`, under a verified domain of the group's owner org), `EndGatewayDrain` (ends the drain of the gateway's old process after a hand-off at once, `infrastructure.write`, step-up, audited; `FAILED_PRECONDITION` when no old process drains, when the gateway has no control session with the answering controller or when its release cannot; for the all-in-one's own gateway the Instance Admin only; the gateway's status carries the old process as `draining`: connections, UDP flows, data sessions, since and ends, [D160](14-open-decisions.md#engineering)), `DecommissionGateway` (revokes the gateway's identity; `FAILED_PRECONDITION` for the all-in-one's own gateway, whose `built_in` is set, and so is an enrollment token bound to either); CRUD on gateway groups and port pools; `SetPortQuota`, `ListPortQuotas`, `DeletePortQuota`; shared-group grants; in Phase 2 `SetGatewayPage`, `ListGatewayPages`, `DeleteGatewayPage` (a group's own not-found, unavailable and maintenance pages: UTF-8 HTML of at most the size of [03](03-connections.md#timeouts-keepalive-and-backoff), one per kind, set again to replace it; the list returns the HTML and leaves out the kinds that are built in; deleting a kind that is built in is `NOT_FOUND`; writes take `infrastructure.write` of the group's owner org and are audited, [D132](14-open-decisions.md#engineering); deleting the group deletes its pages), and `PreviewGatewayPage` (same permission: a link, signed and valid for the time of [03](03-connections.md#timeouts-keepalive-and-backoff), at which the controller shows the page of a kind, own or built in, as gateways render it with sample values; the link shows nothing once the page changed, [D136](14-open-decisions.md#engineering)) | 1 (shared-group grants: 2) |
| `RouteService` | CRUD on routes (`CreateRoute`, `GetRoute`, `ListRoutes`, `UpdateRoute`, `DeleteRoute`) and their targets (`CreateRouteTarget`, `GetRouteTarget` with its route's ID, `UpdateRouteTarget`, `DeleteRouteTarget`; a route shows its targets), `ProbeTargetCertificate` (an enabled connector of the org reads the certificate a target presents, for its key pin, [ADR-0018](adr/0018-pin-the-key-a-target-presents.md); `routes.write`), `PreviewRoute` (compile without saving: the write's checks and each gateway's own, the route as it would be stored, the gateways and connectors it would reach, judged by the capabilities each announced in its latest control session, or by this release's for one that never connected, so that a gateway or connector whose release lacks a capability the route needs is not listed, [03](03-connections.md#versioning-and-capabilities)). A hostname outside the org's verified domains is refused with `DOMAIN_NOT_VERIFIED`; ACME for a wildcard hostname with `WILDCARD_NEEDS_CERTIFICATE` (R42); a route in certificate mode names an uploaded certificate that covers each of its hostnames, or is refused with `CERTIFICATE_NOT_COVERING`. A tcp or udp route takes an explicit or a random port of its group's pools, and a tcp_udp route one port number from both protocols' pools, free in both and counted against both quotas; `PORT_NOT_IN_POOL`, `POOL_EXHAUSTED` and `QUOTA_REACHED` refuse one. A route applies access policies of its org, each once; one with a `basic_auth` rule only on an http route (`BASIC_AUTH_NOT_HTTP`), likewise one with a `require_header` rule (`REQUIRE_HEADER_NOT_HTTP`). The order of `policy_ids`, like that of a policy's rules, is still stored but no longer changes who is admitted: a deny rule of any of them wins (D85). An http route's `maintenance` and `maintenance_message` (plain text, at most 500 characters, line feeds the only control characters, no bidirectional embedding, override or isolate) put it in maintenance (D88); changing only them leaves its hostnames as they are, so it works while a domain claim has lapsed. Phase 2 ([03](03-connections.md#http-routes)): an http route's header matches (at most 8; a second route with the same hostname, prefix and set is refused with `ALREADY_EXISTS`, as a taken hostname is) and its two upstream timeouts; a route's `RouteLimits`; its health check (the route's `health_check`, set when it is created or by an update of `health_check`, removed by one without it; a `udp` route has only a `tcp` check of a port it names and a `tls_passthrough` route only a `tcp` check, a check port excludes a Unix socket target and an `http` check an `h2c` target (`FAILED_PRECONDITION`), and the interval and timeout keep the bounds of [03](03-connections.md#timeouts-keepalive-and-backoff)), with the observed health of each target in the route's status: an unhealthy target is in `not_serving` with `TARGETS_UNHEALTHY` and the last failure, or `BLOCKED_BY_LOCAL_POLICY`; a target whose first check has not decided yet is there with `TARGET_UNKNOWN` and counts as ready (D156); `health_not_checked` lists the targets whose connector runs no checks (D133); a Viewer reads both; a tcp route in `http_connect` mode with its authorities and authentication mode, placed on a CONNECT listener of the org (`CONNECT_MODE_MISMATCH` for a named port whose listener has another mode or hostname; choosing `plain_basic` returns a warning that the password crosses the network in the clear, and a route of a basic mode without a basic-auth rule one that every client gets 407, in the `warnings` of `CreateRouteResponse`, `UpdateRouteResponse` and `PreviewRouteResponse`; the listener mode cannot change, `LISTENER_MODE_CHANGE`; [D130](14-open-decisions.md#engineering)) | 1 (header matches, timeouts, limits, health checks, CONNECT: 2) |
| `DomainService` | `CreateDomain` (returns the TXT record or HTTP token that proves the claim), `GetDomain`, `VerifyDomain`, `ListDomains`, `DeleteDomain` (refused while route hostnames or the hostname of a CONNECT listener lie under it), `MarkDomainTrusted` (Instance Admin, step-up), `DelegateDomain` and `ApproveDomainClaim` (Instance Admin, step-up) | 1 (`DelegateDomain`, `ApproveDomainClaim`: 2) |
| `CertificateService` | `UploadCertificate` (a chain and its key, checked as [04](04-security.md#controller-certificates) requires; the key is kept under the KEK and never returned), `GetCertificate`, `ListCertificates` (source, names, validity, status and the last ACME error; an uploaded certificate with the routes that serve it), `DeleteCertificate` (an uploaded certificate no route serves), `RenewCertificate` (an ACME certificate of a route in acme mode, renewed now even if not due, or obtained if it has none; the answer comes at once, and the outcome shows in the certificate); CRUD on CA bundles for HTTPS upstreams (`CreateCABundle`, `GetCABundle`, `ListCABundles`, `UpdateCABundle`, `DeleteCABundle`; shown with their certificates' subjects and expiry and the targets that use them, not deleted while one does) | 1 |
| `PkiService` | `GetPkiStatus` (the trust domain, the root's pin, and the CA's keys that have not expired, with their state and when the schedule replaces them), `RotateIntermediate` (replaces the intermediate before its half-life; the old one keeps verifying its leaves until it expires); Instance Admin, the rotation with step-up | 1 |
| `DnsProviderService` | `ConnectDnsProvider`, `ListDnsProviders`, `UpdateDnsProvider` (rename, rotate token), `DeleteDnsProvider`, `ListProviderZones` | 2 |
| `DnsZoneService` | `ImportZone`, `ListZones`, `UpdateZone` (gates), `RemoveZone` (keep or remove records), `PlanZoneSync`, `ApproveZonePlan` (plan hash), `SyncZone`, `ListZoneRecords` (owned and foreign, read live; Owner/Admin), `AdoptRecords`, `ReleaseRecord` (optionally restore the original) | 2 |
| `DnsNameService` | `CreateDnsName`, `GetDnsName`, `ListDnsNames`, `UpdateDnsName`, `DeleteDnsName` | 2 |
| `PolicyService` | CRUD on access policies (`CreateAccessPolicy`, `GetAccessPolicy`, `ListAccessPolicies`, `UpdateAccessPolicy`, `DeleteAccessPolicy`) with their rules (`ip_allow`, `ip_deny`, `basic_auth`; their order is stored but a deny wins over every allow, D85; a CIDR with host bits set is accepted and kept in its masked form, so `10.0.0.1/16` is `10.0.0.0/16`); a policy shows the routes that apply it and cannot be deleted while one does. An update replaces the rules as a whole. Basic-auth passwords are write-only: the controller hashes them ([04](04-security.md#secrets-at-rest-and-in-logs)) under the account password rules, and in an update a user without a password keeps the one of its name. A `basic_auth` rule on a policy that a route other than an http route, or a CONNECT route in a basic mode, applies is refused with `BASIC_AUTH_NOT_HTTP`. Phase 2 rule kinds ([03](03-connections.md#access-policies), [04](04-security.md#route-edge-rules)): `rate_limit` (a rate and a burst per client, on every route type, at most one per policy); `require_header` (a header name, once per policy, and 1 to 4 write-only values of 32 to 1024 visible ASCII characters, kept as their SHA-256; a read shows the header only, and in an update a rule without values keeps the values of its header; on a policy a route other than an http route applies, `REQUIRE_HEADER_NOT_HTTP`); `oidc` (a route identity provider, the accepted e-mail addresses, domains and groups, the session length; with basic auth on one route, `OIDC_WITH_BASIC_AUTH`). Route identity providers are managed here too, their client secret write-only | 2 (basic auth, IP rules: 1) |
| `PrivateServiceService` | private services and visitor grants | 2 |
| `StatusService` | `GetApplyStatus`, `WatchApplyStatus` (stream), `WatchEvents` (stream) | 1 |
| `LogService` | `StreamLogs` (a connector's or gateway's live log, server stream from an imperative operation; `agents.logs`) | 2 |
| `MetricsService` | `GetRouteTraffic` (a route's hourly or daily buckets, at most 31 days of hours or 400 days of days), `GetOverview` (an org's last 24 hours per hour, and its 10 busiest routes); from the rollups, buckets without traffic left out | 1 |
| `AuditService` | `ListAuditEntries`, `VerifyAuditChain` (an org's chain, `audit.read`), `ListInstanceAuditEntries`, `VerifyInstanceAuditChain` (the instance chain, Instance Admin), `ExportAudit` (a server stream of a chain as JSON Lines with its proofs, ending at the newest checkpoint, after a step-up; [04](04-security.md#audit-log)) | 1 (export: 2) |
| `SettingsService` | `GetInstanceSettings`, `UpdateInstanceSettings` (including `default_transport` and `rollout_mode`, `easy` when unset, which picks the kind of rollout the web UI starts, [D129](14-open-decisions.md#engineering)), `SetSmtpPassword` (write-only; a read says only whether it is set), Phase 2: `webhook_private_ranges` ([04](04-security.md#webhooks-and-the-egress-guard-phase-2)), the audit sinks with their status and backlog, and `SetAuditSinkSecret` (write-only), all for the Instance Admin; `GetOrgSettings` (members), `UpdateOrgSettings` (Owners; a change of the MFA requirement needs a step-up, and a default gateway group must be one of the org's; Phase 2: `alert_email` and `alert_types`, [Webhooks](#webhooks-phase-2)). Updates name their fields in a mask; a named field the request does not set returns to its default | 1 |
| `ReleaseService` | `ListReleases` (the newest version first, each with its channel, source, whether the mirror holds it and whether it is newer than the controller, and the state of the release check: whether one runs, when the last ended and how, ok, failed with its error, off, or none on a build that checks for no releases), `CheckReleases` (the release check at once: joins a check that runs; refused while the release check is off or the build checks for no releases, and within a short gap after the last check started or while the release source limits the rate, with the time to wait, [03](03-connections.md#timeouts-keepalive-and-backoff)), `UploadRelease` (a release's signed manifest, signing-key statement and their signatures, verified like the release check; for air-gapped installs and signed downgrades; the artifacts come from the release source or `rpmgr release import`), `CreateRollout` (a release, a mode, `advanced` or `easy` ([D129](14-open-decisions.md#engineering)), and for a staged rollout its canary agents, for an easy one its ordered queue of agents, connectors or gateways of any org; an easy rollout refuses an agent that is built in, decommissioned or without the capability `ota`, and an empty queue; refused when the release is newer than the controller or the controller is a development build, when it is below the controller's `min_agent_version`, when it is a pre-release and the instance's update channel is stable, or while another rollout runs or is paused; a recorded release the mirror does not hold yet is accepted, the mirror checks for it at once and the rollout job offers it once the mirror holds it ([D125](14-open-decisions.md#engineering)); in a staged rollout every connector and enrolled gateway that is neither decommissioned nor built in becomes a target, in an easy one each agent of the queue, with the version it last connected with), `UpgradeAgents` (connectors or gateways added to the end of the queue of the easy rollout that runs or is paused, when its target is the controller's own version, or an easy rollout of the controller's own version started with them when none runs; an agent already queued keeps its place; refused while a staged rollout or an easy rollout of another release runs or is paused, and for an agent an easy rollout refuses), `UpdateController` (the Instance Admin's request, after a step-up, that the controller or all-in-one update itself over the air, [D158](14-open-decisions.md#engineering): a release newer than the controller, held by the mirror and taken by the instance's update channel, which the controller stages, from a running release of v0.3.0 or later only (an earlier one is updated by hand once, and the refusal says so) for the root updater of its host; refused while a rollout runs, while another update of the controller is under way, on a development build, on a host without the root updater or on a PostgreSQL controller; audited like every change), `GetControllerUpdate` (the state of that update from the staged release and the root updater's status file: staged, updating with its step, updated, rolled back with the reason, rollback failed or refused; why none can be started; the version that runs, and whether it is too old to update itself (`by_hand`); a status of `updating` that the updater has not written to for 30 min is from an updater that died and shows as no update), `GetRollout`, `ListRollouts`, `ListRolloutTargets` (each agent's state and reason, and its place in an easy rollout's queue), `AdvanceRollout` (a running staged rollout to a higher percentage, 1 to 99, or to all agents, under the rollout's etag), `PauseRollout` (a running one), `ResumeRollout` (a paused one), `CancelRollout` (a running or paused one, for good); each change may name the etag the caller read. Creating a rollout and each change are configuration changes with a revision, so the agents' snapshots compile again, and changes of one rollout happen one after the other. All for the Instance Admin; uploading, creating, upgrading agents, advancing, resuming and cancelling take a step-up, and each of these and a check is audited ([04](04-security.md#over-the-air-updates), [D121](14-open-decisions.md#engineering)). The release check and the instance's update channel are instance settings (`SettingsService`). A connector and a gateway show their version, their update state, and whether they are below `min_agent_version` with the reason of their last `Goodbye` | 2 |
| `ManifestService` | `ExportManifests` (an org's resources as YAML manifests: all, of the kinds named, or the resources named), `Plan`, `Apply` (declarative manifests) | 1 (`Plan`, `Apply`: 2) |
| `WebhookService` | `CreateWebhook`, `GetWebhook`, `ListWebhooks`, `UpdateWebhook` (URL, event types, enabled; enabling again clears a disable), `DeleteWebhook`, `RotateWebhookSecret` (the new secret returned once), `ListWebhookDeliveries`, `TestWebhook` (a `webhook.test` event, audited); an org's endpoints for `webhooks.write` ([Webhooks](#webhooks-phase-2)); every method, reads included, needs `webhooks.write`, since a URL may carry a token of the receiver's | 2 |
| `InstanceWebhookService` | The same methods for the instance's endpoints (`CreateInstanceWebhook`, `GetInstanceWebhook`, `ListInstanceWebhooks`, `UpdateInstanceWebhook`, `DeleteInstanceWebhook`, `RotateInstanceWebhookSecret`, `ListInstanceWebhookDeliveries`, `TestInstanceWebhook`), which receive instance events; every method needs the Instance Admin role. An org's endpoint is `NOT_FOUND` here and an instance endpoint is `NOT_FOUND` in `WebhookService`, so an org Owner neither sees nor changes one ([Webhooks](#webhooks-phase-2)) | 2 |
| `VirtualNetworkService`, `FunctionService`, `ShellService` | — | 3 |

### Example: a route

The sketch follows `proto/rpmgr/v1/route.proto`, with its validation left out; fields marked
Phase 2 are planned and take the numbers shown.

```protobuf
// rpmgr/v1/route.proto (sketch)
message Route {
  string id = 1;                       // rte_…, output only
  string name = 2;                     // unique per org
  string gateway_group_id = 3;
  bool enabled = 4;                    // the only desired on/off switch
  map<string, string> labels = 5;
  string description = 6;
  oneof spec {
    HTTPRouteSpec http = 10;
    TCPRouteSpec tcp = 11;
    UDPRouteSpec udp = 12;
    TLSPassthroughRouteSpec tls_passthrough = 13;
    TCPUDPRouteSpec tcp_udp = 14;
  }
  repeated RouteTarget targets = 20;
  repeated string policy_ids = 21;
  RouteLimits limits = 22;             // Phase 2: for the route as a whole, divided among gateways
  DataTransport transport = 23;        // AUTO, QUIC, H2, WSS (Phase 2); UNSPECIFIED = the connector's (03)
  google.protobuf.Timestamp create_time = 24;  // output only
  google.protobuf.Timestamp update_time = 25;  // output only
  string update_user_id = 26;          // output only
  HealthCheck health_check = 27;       // Phase 2: one per route, run against each target
  string etag = 30;                    // output only; send back on update
  RouteStatus status = 31;             // output only; derived from observed state (see 06-data-model)
  repeated HostnameDnsStatus dns_status = 32;  // Phase 2, output only; per hostname
}

message HTTPRouteSpec {
  repeated string hostnames = 1;       // 1 to 100
  string path_prefix = 2;              // longest prefix wins among routes sharing a hostname
  TLSMode tls_mode = 3;                // ACME or an uploaded certificate
  string certificate_id = 4;           // in certificate mode
  Port80Mode port80 = 5;               // REDIRECT (default), SERVE or OFF; ACME HTTP-01 always works
  uint32 hsts_max_age_seconds = 6;     // 0 = no HSTS
  string host_header = 7;              // empty = the client's
  map<string, string> request_headers_set = 8;
  map<string, string> response_headers_set = 9;
  optional bool websocket = 10;        // upgrades pass unless false
  uint64 max_body_bytes = 11;          // 0 = no limit
  bool maintenance = 12;               // answer every request with the maintenance page, 503 (D88)
  string maintenance_message = 13;     // plain text on that page, at most 500 characters
  repeated HeaderMatch header_matches = 14;            // Phase 2: at most 8
  uint32 upstream_response_header_timeout_seconds = 15;  // Phase 2: 0 = the gateway's
  uint32 upstream_idle_timeout_seconds = 16;           // Phase 2: 0 = the gateway's
  bool dns_proxied = 17;               // Phase 2: opt into Cloudflare's proxy (15-dns)
}

message HeaderMatch {                  // Phase 2
  string name = 1;                     // compared without regard to case
  oneof match { string exact = 2; bool present = 3; }
}

message TCPRouteSpec {
  uint32 port = 1;                     // 0 = a random free port of the pool
  optional uint32 idle_timeout_seconds = 2;
  ListenerMode listener_mode = 3;      // Phase 2: PLAIN (default) or HTTP_CONNECT
  ConnectSpec connect = 4;             // Phase 2: with HTTP_CONNECT
}

message ConnectSpec {                  // Phase 2 (D130)
  repeated string authorities = 1;     // host names, unique on the listener
  ConnectAuthMode auth_mode = 2;       // NONE (default), TLS_BASIC, PLAIN_BASIC (password in clear)
  string hostname = 3;                 // TLS_BASIC: the listener's name, under a verified domain
  string certificate_id = 4;           // TLS_BASIC: an uploaded certificate that covers hostname; empty: ACME
}

message RouteLimits {                  // Phase 2; 0 = no limit
  uint32 max_connections = 1;
  uint32 requests_per_second = 2;
  uint64 bandwidth_bytes_per_second = 3;
}

message HealthCheck {                  // Phase 2
  HealthCheckType type = 1;            // TCP or HTTP
  uint32 port = 2;                     // 0 = the target's; required on udp routes
  string http_path = 3;
  uint32 expected_status_min = 4;      // 200 unless set
  uint32 expected_status_max = 5;      // 399 unless set
  uint32 interval_seconds = 6;
  uint32 timeout_seconds = 7;
  uint32 unhealthy_threshold = 8;
  uint32 healthy_threshold = 9;
}

message RouteTarget {
  string id = 1;
  string connector_id = 2;
  oneof address { HostPort host_port = 3; string unix_path = 4; }
  UpstreamProtocol upstream_protocol = 5;   // TCP, HTTP, HTTPS, H2C; one per http route; HTTPS
                                            // verified, or unverified by choice (ADR-0017)
  UpstreamTLSSettings tls = 6;
  ProxyProtocol proxy_protocol = 7;         // NONE, V1, V2
  uint32 weight = 8;
  uint32 priority = 9;                      // lower = preferred; higher priorities are failover
  bool enabled = 10;
  string etag = 11;
}
```

The values and bounds of these fields live in
[03](03-connections.md#timeouts-keepalive-and-backoff).

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
  that does not parse is no wait. The CLI does this with `--wait <duration>`; without it, it does
  not wait.
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
| A change while its org or the instance is in restore review ([10](10-operations.md#backup-and-restore)) | `FAILED_PRECONDITION` | `reason = RESTORE_REVIEW` |
| DNS (Phase 2): zone not managed or not `active`, proxied or wildcard name not allowed by the zone, plan changed since it was shown, provider refuses the token for this zone | `FAILED_PRECONDITION` | `reason` = `ZONE_NOT_MANAGED`, `ZONE_NOT_ACTIVE`, `PROXY_NOT_ALLOWED`, `WILDCARD_NOT_ALLOWED`, `PLAN_CHANGED`, `PROVIDER_PERMISSION_DENIED` |
| Releases (Phase 2): an upload whose chain does not verify | `INVALID_ARGUMENT` | `reason = RELEASE_DOES_NOT_VERIFY` |
| Releases (Phase 2): a release check asked for while the release check is off or the build checks for no releases | `FAILED_PRECONDITION` | `reason = RELEASE_CHECK_OFF` |
| Rollouts (Phase 2): another rollout runs or is paused, the release is newer than the controller, below its `min_agent_version` or a pre-release on a stable instance, a stage change the rollout's state or stage does not allow, a stage change of an easy rollout, an agent an easy rollout cannot update (built in, decommissioned, or without `ota`) | `FAILED_PRECONDITION` | `reason` = `ROLLOUT_ACTIVE`, `RELEASE_NEWER_THAN_CONTROLLER`, `RELEASE_BELOW_MIN_AGENT_VERSION`, `RELEASE_NOT_ON_CHANNEL`, `ROLLOUT_STATE`, `ROLLOUT_MODE`, `AGENT_NOT_UPGRADABLE` |
| The controller's own update (Phase 2): the release is not newer than the controller, not held by the mirror yet, or the host cannot take it (no root updater, PostgreSQL, a development build), an update of the controller is under way, or a rollout runs | `FAILED_PRECONDITION` | `reason` = `CONTROLLER_UPDATE_REFUSED`; `RELEASE_NOT_ON_CHANNEL` and `ROLLOUT_ACTIVE` as for a rollout |
| Rate limited | `RESOURCE_EXHAUSTED` | retry-after (`google.rpc.RetryInfo`) |
| Agent unreachable for an imperative operation; DNS provider unreachable for a live call (`ListProviderZones`, `ListZoneRecords`, `PlanZoneSync`) | `UNAVAILABLE` | — |
| Operation exceeded its deadline | `DEADLINE_EXCEEDED` | — |

- [R] A `reason` comes as `google.rpc.ErrorInfo` with domain `rpmgr.v1`; field violations come as
  `buf.validate.Violations`.
- Error messages never contain secrets or other orgs' data. [R] An error a method did not write
  for the client is `INTERNAL` without its text, which goes to the log.
- [R] Every request the audit log records, every one but those free of side effects, gets a
  request ID: its `request_id` if it has one, else one the API makes. The response, or the error,
  carries it in the header `Rpmgr-Request-Id`, and the request's audit entries carry it
  ([04](04-security.md#audit-log)).
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
- `LogService.StreamLogs(agent_id, level, filter, raise_to_debug)` opens an imperative log
  operation on a connector or gateway ([03](03-connections.md#control-session)) and streams lines,
  with a marker where lines were dropped or cut. Log lines pass through the agent's redaction
  before they leave the host ([04](04-security.md#secrets-at-rest-and-in-logs)). It needs
  `agents.logs`; a gateway of a shared group needs the Instance Admin. Another org's agent is
  `NOT_FOUND`, an offline agent or one without `logs.stream` `UNAVAILABLE`, and a caller or agent
  at its limit ([03](03-connections.md#timeouts-keepalive-and-backoff)) `RESOURCE_EXHAUSTED`.
  Cancelling the stream ends the operation on the agent. At the operation's deadline the stream
  ends without an error, and the client may open a new one; an operation that breaks off, as when
  the agent is revoked or goes offline, ends it with `UNAVAILABLE` and the reason; a caller who
  loses the permission or whose credentials end while it runs loses it with `PERMISSION_DENIED` or
  `UNAUTHENTICATED` ([04](04-security.md#roles)). `raise_to_debug`
  raises the agent's level for the operation's life ([D140](14-open-decisions.md#engineering)).
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

- Every manifest carries `apiVersion: rpmgr.v1`, the API package its schema comes from
  ([D115](14-open-decisions.md#engineering)); a later package changes the value. `apply` refuses
  an `apiVersion` it does not know and reads a file without one, as Phase 1 exports them, as
  `rpmgr.v1`. The export writes it from Phase 2's manifest slices on.
- [R] **Phase 1 writes manifests; it does not apply them** ([D58](14-open-decisions.md#project-and-process)).
  The kinds are `Route` (with its targets), `AccessPolicy`, `GatewayGroup`, `Gateway`,
  `PortPool`, `Domain`, `Connector` and `CABundle`.
  - `metadata.name` is the resource's name, a domain's FQDN, or the ID of a resource without a
    name (a port pool).
  - The spec has no field the server sets, which the protos mark output only: no ID, etag,
    status, times, lists of dependants, `updateUserId` or `builtIn`. A route's targets are the
    exception: its manifest carries them, without their IDs and etags.
  - It names gateway groups, access policies, connectors and CA bundles by their names
    (`gatewayGroup`, `policies`, `connector`, `caBundle`). A certificate, which has no name, keeps
    its ID.
  - Fields marked `sensitive` are never written, so a basic-auth user appears without a
    password. Certificates and their keys are not a kind.
  - `ManifestService.ExportManifests` writes them for the CLI and the UI's YAML tab: every kind,
    the kinds named, or exactly the resources named by ID. Decommissioned gateways and connectors
    are left out. A resource named that is not the org's, not of a kind named, or decommissioned
    is `NOT_FOUND`.

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

- **Events.** [R] Every change an org's audit log records as a success is an event of the same
  type as its audit action, such as `route.update` or `token.revoke`, written in the change's
  transaction ([06](06-data-model.md#observability-phase-2)). An API method's entry is typed
  `<resource>.<verb>` from the method's name, so `RouteService.UpdateRoute` is `route.update` and
  `CreateRouteTarget` is `route_target.create`; a method that is a verb alone takes its service's
  name, as `auth.logout`. An update's event names the fields of its update mask. Signing in and
  out, a step-up, asking for a reset link and the use of a token or a system scope change nothing
  and are no events. Status changes add `route.status`
  (a route's state changed), `agent.connect`, `agent.disconnect`, `apply.reject`, `alert.fire` and
  `alert.resolve` ([10](10-operations.md#suggested-alerts)), `webhook.disable`, and with DNS
  automation `dns.conflict`, `dns.zone_held`, `dns.sync_failing` and `dns.token_expiring`.
  Instance events go to instance endpoints only: the instance chain's audit actions, releases and
  rollouts, events of gateways in shared groups, and the instance alerts. An endpoint names the
  types it wants, by name or by prefix such as `route.*`; none means all
  ([D145](14-open-decisions.md#engineering), E1, E12).
- **Envelope** ([D144](14-open-decisions.md#engineering)): `POST` of
  `{"id", "type", "time", "org_id", "actor": {"type", "id"}, "subject": {"type", "id", "name"},
  "summary", "changed": [field names]}`; no resource body. Fetch the resource through the API for
  more. An alert event's subject is what the alert is about (an agent, a route, a certificate, or
  `instance` for an instance alert), its actor the system, and its summary begins with the alert's
  kind and a colon, such as `agent_offline: Agent offline fires, gw1`
  ([10](10-operations.md#suggested-alerts)).
- **Headers:** `Rpmgr-Event-Id` (the event's ID, the same on every retry: delivery is at least
  once), `Rpmgr-Event-Type`, and `Rpmgr-Signature: t=<unix>,v1=<HMAC-SHA256(secret, t.body)>`, with
  a second `v1=` value while a rotated secret still signs. Receivers reject signatures older than
  the age in [04](04-security.md#webhooks-and-the-egress-guard-phase-2).
- **Delivery:** HTTPS only, TLS verified, no redirect followed, retries, give-up and the disabling
  of a failing endpoint as in [03](03-connections.md#timeouts-keepalive-and-backoff); a 2xx answer
  is a success, anything else or no answer a failure. Receivers on private networks need the
  instance's allow-list ([04](04-security.md#webhooks-and-the-egress-guard-phase-2)). A replica
  that lost the delivery job's lease while a request was in flight may still finish it, and the new
  holder sends the event again: a duplicate within at-least-once, with the same `Rpmgr-Event-Id`
  ([03](03-connections.md#timeouts-keepalive-and-backoff)).
- **Endpoints.** An endpoint's URL is `https://` with a host and no credentials or fragment; the
  event types it names are checked at save, and a refused value is `INVALID_ARGUMENT`. An org's
  endpoint also may not name `localhost` or a loopback, link-local or unspecified address as a
  literal, which tells the person early; the guard at dial time stays the defence
  ([04](04-security.md#webhooks-and-the-egress-guard-phase-2)). An org, and the instance, has the
  number of endpoints in [03](03-connections.md#timeouts-keepalive-and-backoff), and a further one
  is `RESOURCE_EXHAUSTED`, as is a test past a caller's allowance there. A URL that is not changed
  by an update is not checked again. **Instance endpoints** are managed in
  `InstanceWebhookService` by the Instance Admin, receive the instance events only, and may name a
  receiver on loopback or a private network; the instance setting `webhook_private_ranges`, a list
  of at most 32 prefixes such as `10.0.0.0/8`, admits the private ranges of orgs' receivers, and
  its changes are audited like those of every instance setting. A secret
  is made by the controller, returned by `CreateWebhook` and `RotateWebhookSecret` and never again:
  no read, audit entry, event or log line carries it. A rotation keeps the old secret as a second
  signing key for the period in [03](03-connections.md#timeouts-keepalive-and-backoff); a second
  rotation within it drops the oldest one. `RotateWebhookSecret` is audited as
  `webhook_secret.rotate` by the naming rule above, and its event has that type. `TestWebhook` signs
  and sends a `webhook.test` event to the one endpoint at once, through the egress guard, and
  answers the receiver's status code or why it failed; the request is audited, and the test is no
  outbox event, so no other endpoint gets it. Enabling a disabled endpoint, whatever the reason,
  clears the disable and its failing period; events count from then on. Deleting an endpoint deletes
  its deliveries.
- **Deliveries** are listed per endpoint: event, attempt, time, status code or error, and the
  next retry.
- **Alert e-mails** ([D139](14-open-decisions.md#engineering)): with SMTP configured, an alert's
  firing and resolving are also mailed to the org's Owners and Admins, and an instance alert to
  the Instance Admins; an org turns this off with the org setting `alert_email`, and chooses which
  alert types it gets with `alert_types` ([D142](14-open-decisions.md#engineering)).

## Agent protocol catalogue

Defined in [03-connections.md](03-connections.md); summarised here for reference.

| Channel | Message | Direction | Purpose |
|---|---|---|---|
| Enrollment | `Enroll` | agent → controller | Token + CSR → certificate, trust bundle |
| Control `Session` | `Hello` / `Welcome` | both | Identity, last applied revision, capabilities, versions, clocks |
| | `Snapshot` | controller → agent | Desired state at a revision, signed; with the capability `ota`, the release the agent is offered (version, `seq`, its files under `/dl/` with sizes and SHA-256), Phase 2 |
| | `Applied` / `Rejected` | agent → controller | Result of applying a revision |
| | `Status` | agent → controller | Health, route readiness, counters; with `ota`, the update state (available, declined, downloading, staged or failed, and the updater's outcome) |
| | `Open` | controller → agent | Start an imperative operation (Phase 2: live logs; Phase 3: shell): `open_operation`, a new field number; 3 and `open` stay reserved |
| | `Drain` / `Goodbye` | controller → agent | Reconnect elsewhere / session ends (superseded, revoked, upgrade required) |
| | `DenyListUpdate` | controller → agent | Revocations; applied unconditionally, independent of snapshots |
| | `AcmeChallenge` / `OpResult` | controller → gateway / back | An ACME HTTP-01 or TLS-ALPN-01 challenge the gateway answers (add, remove), and its acknowledgement |
| Control unary | `Renew`, `FetchResource` | agent → controller | Certificate renewal; large resources by hash |
| `Reauth` (SNI `reauth.controller.<td>`) | `Reauth` | agent → controller | New certificate for an agent whose certificate expired within the grace period; mutual TLS with the expired certificate |
| Control `Attach` | `AttachFrame` | both | An imperative operation: the agent's first frame presents the ticket of its `Open`; log lines; `AttachEnd` from either side ([03](03-connections.md#control-session)) |
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
- **From v1.0.0 the same additive rule covers the names other programs read**
  ([D115](14-open-decisions.md#engineering)): metric names and their labels
  ([10](10-operations.md#metrics)), the keys of structured log records, audit actions and the
  fields of audit entries and their export, and webhook event types and their fields. Within a
  major release names are added, never renamed or removed, and readers ignore what they do not
  know. Log messages and the web UI's texts are not covered.
- **Outside the API**, for command-line commands and flags, boot-file keys, settings and the names
  above, a deprecation is announced in the changelog and by a warning at least one minor release
  before the item goes. It goes only in a major release, unless rpmgr migrates it automatically
  ([RELEASING](../RELEASING.md#versioning)).
- The command line's JSON and YAML output and its exit codes are stable within a major release;
  its table output is for people and may change in any release ([16](16-cli.md#conventions)).
- The agent protocol's compatibility rules (ALPN major version, capability strings,
  `min_agent_version`) are in [03](03-connections.md#versioning-and-capabilities) and
  [10](10-operations.md#upgrades-and-version-skew).
