# API

The web UI and the `rpmgr` command line do everything through one public API, and so can your
scripts. This page is for anyone who automates rpmgr: it shows how to authenticate, how to call a
method with `curl`, how writes, paging, retries and streams work, and what the errors mean. The
protobuf files are the reference for every method and field; this page links each of them.

## Overview

- **Address.** The API is served by the controller at its public URL, the URL of the web UI. A
  method is `POST <public URL>/rpmgr.v1.<Service>/<Method>`, for example
  `https://panel.example.com/rpmgr.v1.RouteService/ListRoutes`.
- **Protocol.** The API speaks ConnectRPC's Connect protocol: a unary call is a plain HTTP request
  whose body is the request message and whose response body is the answer. Send JSON with
  `Content-Type: application/json`, or binary protobuf with `Content-Type: application/proto`.
  Methods that stream answers use the Connect streaming format
  ([Watch for changes](#watch-for-changes)). gRPC and gRPC-Web clients work as well, on the same
  paths.
- **HTTP version.** The controller answers over HTTP/2 or HTTP/1.1, as the client chooses in the
  TLS handshake; a client that names neither gets HTTP/1.1. Connect and gRPC-Web clients work over
  both. Plain gRPC clients need HTTP/2 and get it: point one at the public URL's host and port, and
  send the token as the `authorization` metadata, `Bearer rpmgr_pat_…`. The same holds on
  all-in-one and for a private controller published through a gateway
  ([07](../../07-api.md#overview)).
- **JSON.** Requests and answers use the protobuf JSON mapping: field names in lowerCamelCase
  (`gatewayGroupId`), enum values by name (`"UPSTREAM_PROTOCOL_HTTP"`), 64-bit numbers as strings
  (`"seq": "42"`), durations as seconds with an `s` (`"3600s"`) and times in RFC 3339 (UTC). Leave
  out a field to leave it unset. Clients must ignore fields they do not know.
- **Same API for everyone.** The web UI has no private endpoints; anything you can do in it, a
  script can do with the API and a token whose scopes allow it ([07](../../07-api.md#overview)).
- **Not in the API.** Administration commands that run on the controller host, such as
  `rpmgr backup`, `rpmgr ca rotate-intermediate` or `rpmgr user reset-password`, use the database
  directly and need no token ([Command-line reference](cli.md)). Agents use their own protocol
  with mutual TLS, never this API.

## Authenticate

### Personal API tokens

Scripts and the command line authenticate with a personal API token, `rpmgr_pat_…`, in the
`Authorization` header:

```sh
curl https://panel.example.com/rpmgr.v1.RouteService/ListRoutes \
  -H "Authorization: Bearer $RPMGR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"orgId":"org_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R"}'
```

- You make a token in the web UI, under your account's API tokens, and copy it once
  ([API tokens and the command line](../accounts/api-tokens-and-cli.md)). Only a signed-in session
  makes one, after a step-up, so a token can never make another.
- A token belongs to one organisation. It can do what its **scopes** allow, and never more than
  your current role there: a lower role limits the token at its next request. The scopes are the
  permissions of [Members and roles](../accounts/members-and-roles.md): `org.read`,
  `routes.write`, `connectors.write`, `infrastructure.write`, `members.write`, `audit.read`,
  `org.write`, and `instance.admin` for an Instance Admin.
- Every token expires; its lifetime and the defaults are in
  [04](../../04-security.md#human-authentication-and-sessions).
- The token goes only in `Authorization: Bearer`. A token in a query string or a cookie is never
  read. A header that is not a Bearer token, or a token that is wrong, expired or revoked, is
  `UNAUTHENTICATED` with the message `api: the credentials are not valid`.
- Keep the token out of your shell history: read it from a file readable by you only, as in
  `RPMGR_TOKEN=$(cat ~/.config/rpmgr/token)`. On a host that others use, they can see a command
  line; there, give `curl` the header from a file instead, `-H @<file>`, the file holding the line
  `Authorization: Bearer rpmgr_pat_…`.

### Browser sessions

The web UI uses a session cookie, `__Host-rpmgr_session`, which the controller sets at sign-in. A
script can use one too, but tokens are simpler. Calls with a session follow the browser rules of
[04](../../04-security.md#human-authentication-and-sessions):

- A call that changes something is a `POST` with `Content-Type: application/json` or
  `application/proto` (or their `connect+` streaming forms). A content type that a web form can
  send, such as `text/plain`, is refused with HTTP 415 before the method runs.
- An `Origin` header, if the request has one, must be the public URL's origin or one of the
  instance's further public URLs ([Settings](../operations/settings.md)); any other is refused
  with HTTP 403.
- Methods that change nothing may also be called with `GET`, as the Connect protocol allows:
  `GET /rpmgr.v1.SettingsService/GetInstanceSettings?connect=v1&encoding=json&message=%7B%7D`.

These rules apply to tokens as well, so send `Content-Type: application/json` with every JSON call.

### Step-up for sensitive methods

Some methods need a recent **step-up**: you confirm your identity again. Minting enrollment and
gateway tokens, rotating the CA's intermediate, making an API token, granting Admin or Owner, and
changing the organisation's MFA requirement are among them; the full list is in
[04](../../04-security.md#human-authentication-and-sessions). Without one, the method answers
`UNAUTHENTICATED` with the reason `STEP_UP_REQUIRED`:

```json
{"code":"unauthenticated","message":"api: step-up required","details":[{"type":"google.rpc.ErrorInfo","value":"ChBTVEVQX1VQX1JFUVVJUkVEEghycG1nci52MQ","debug":{"reason":"STEP_UP_REQUIRED","domain":"rpmgr.v1"}}]}
```

A personal API token steps up on its own ([D63](../../14-open-decisions.md#engineering)): call
`AuthService.StepUp` with the token and a code of your authenticator app or a recovery code, or,
if you have no second factor, your password. Then repeat the call:

```sh
curl https://panel.example.com/rpmgr.v1.AuthService/StepUp \
  -H "Authorization: Bearer $RPMGR_TOKEN" -H "Content-Type: application/json" \
  -d '{"secondFactor":"123456"}'
```

```json
{"expireTime":"2026-10-15T09:44:02.846467976Z"}
```

The step-up covers that token only, until `expireTime`; your sessions and other tokens keep their
own. Of the methods of your own account, a token may call only `StepUp`, and with the scope
`org.read` also `TokenService.ListAPITokens` and `RevokeAPIToken` for your tokens. It cannot change
your password, second factor or sessions. A stolen token alone therefore still cannot make such a
change. The command line asks for the factor on the terminal
when it meets `STEP_UP_REQUIRED`, and repeats the change.

## Organisations

Everything except your account, the instance settings and the instance audit log belongs to an
**organisation** (org). Each method names what it works on:

- A method on a collection, such as `ListRoutes` or `CreateRoute`, takes the org's ID in `orgId`.
- A method on one resource, such as `GetRoute` or `UpdateConnector`, takes the resource's ID, and
  the controller finds its org.
- A resource that does not exist and a resource of an org you are no member of give the same
  answer, `NOT_FOUND` (`api: not found`), so nobody learns what other orgs hold.

Your org's ID, `org_…`, is in the login command the web UI shows with a new token, and
`rpmgr login` prints it: `Logged in to https://panel.example.com, org Default (org_…)`. IDs start
with their kind: `rt_` a route, `tg_` a route target, `con_` a connector, `gw_` a gateway, `gwg_` a
gateway group, `enr_` an enrollment token.

## Call a method with curl

The examples use these variables; the answers shown are shortened where they have `…`:

```sh
API=https://panel.example.com
ORG=org_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R
RPMGR_TOKEN=$(cat ~/.config/rpmgr/token)
rpc() { curl -sS "$API/rpmgr.v1.$1" -H "Authorization: Bearer $RPMGR_TOKEN" \
  -H "Content-Type: application/json" -d "$2"; }
```

### List routes

```sh
rpc RouteService/ListRoutes "{\"orgId\":\"$ORG\"}"
```

```json
{"routes":[{"id":"rt_01M4ZEM8WFF24VT354JQBHZSZ2","name":"ssh","gatewayGroupId":"gwg_01M4ZEJ9BNEJWTRGAE2YEZEZ7D","enabled":true,"tcp":{"port":20046,…},"targets":[…],"etag":"1","status":{"state":"ROUTE_STATE_READY","targetsTotal":1,"targetsReady":1,"gatewaysTotal":1,"gatewaysServing":1}}]}
```

An org without routes answers `{}`: fields with their zero value are left out. A route comes with
its targets and its `status`, which [Preview and apply](../routes/preview-and-apply.md#route-states)
explains.

### Page through a list

A `List…` method returns at most `pageSize` items, 50 if you send none; a larger `pageSize` than
500 is cut to 500 ([07](../../07-api.md#resource-design)). The items are ordered by ID, which is
the order of creation. If there are more, the answer has a `nextPageToken`; send it back as
`pageToken` with the same request for the next page:

```sh
rpc GatewayService/ListGatewayGroups "{\"orgId\":\"$ORG\",\"pageSize\":1}"
```

```json
{"gatewayGroups":[{"id":"gwg_01M4ZEJ2NFEAQ9YWGB8AJQF7MT","name":"other","etag":"1"}],"nextPageToken":"Hmd3Z18wMU00…"}
```

A page token is opaque and bound to its query: a token sent with other filters, or altered, is
`INVALID_ARGUMENT` (`api: the page_token is not valid for this request`). The last page has no
`nextPageToken`.

Some lists differ:

- **The audit log.** `AuditService.ListAuditEntries` and `ListInstanceAuditEntries` return the
  newest entries first, and refuse a `pageSize` above 500 with `INVALID_ARGUMENT` instead of
  cutting it.
- **Short lists.** `AuthService.ListSessions`, `OrgService.ListMembers` and
  `ListSuspendedAPITokens`, and `TokenService.ListAPITokens` take no `pageSize` and no
  `pageToken`: they return everything in one answer. Sessions and tokens come newest first,
  members with the Owners first.
- **Webhook deliveries.** `WebhookService.ListWebhookDeliveries` returns the newest first.

### Create a route and a target

A write sends the new resource in the request. This creates a TCP route on a free port of the
gateway group's pools, then a target on a connector:

```sh
rpc RouteService/CreateRoute "{\"orgId\":\"$ORG\",
  \"route\":{\"name\":\"ssh\",\"gatewayGroupId\":\"gwg_01M4ZEJ9BNEJWTRGAE2YEZEZ7D\",\"tcp\":{\"port\":0}},
  \"requestId\":\"3d0c6c1e-6b1f-4a8e-9a57-6f8e0b1c2d3e\"}"
```

```json
{"route":{"id":"rt_01M4ZEM8WFF24VT354JQBHZSZ2","name":"ssh","gatewayGroupId":"gwg_01M4ZEJ9BNEJWTRGAE2YEZEZ7D","enabled":true,"tcp":{"port":20046,…},"etag":"1",…},"revision":{"dbEpoch":"01a13ee8-581f-74c2-a713-5a06c75d4532","seq":"5"},"applyStatus":{"state":"APPLY_STATE_PENDING","agentsTotal":2}}
```

```sh
rpc RouteService/CreateRouteTarget '{"routeId":"rt_01M4ZEM8WFF24VT354JQBHZSZ2",
  "target":{"connectorId":"con_01M4ZEK2EXFBJRKFW4JB7DQVZ6","hostPort":{"host":"192.168.1.20","port":22}}}'
```

An HTTP route takes its hostnames instead of a port, `"http":{"hostnames":["nas.example.com"]}`,
and its targets an upstream protocol such as `"upstreamProtocol":"UPSTREAM_PROTOCOL_HTTP"`. The
fields of each route type and target are in [route.proto](../../../proto/rpmgr/v1/route.proto),
and what they do in [HTTP routes](../routes/http.md), [TCP and UDP routes](../routes/tcp-and-udp.md)
and [Targets](../routes/targets.md).

Every write that changes the configuration answers with a `revision`, and a write in an
organisation also with the revision's `applyStatus`.

### Wait until the agents apply a change

Saving a change and the gateways and connectors running it are two events. Add the header
`Rpmgr-Wait-Applied` with a duration to any write, and the answer comes once every online agent
applied the revision, one rejected it or did not answer in time, or the wait is over, at most 30 s
([07](../../07-api.md#writes-and-apply-status)):

```sh
curl -sS "$API/rpmgr.v1.RouteService/CreateRouteTarget" \
  -H "Authorization: Bearer $RPMGR_TOKEN" -H "Content-Type: application/json" \
  -H "Rpmgr-Wait-Applied: 10s" \
  -d '{"routeId":"rt_01M4ZEM8WFF24VT354JQBHZSZ2","target":{"connectorId":"con_01M4ZEK2EXFBJRKFW4JB7DQVZ6","hostPort":{"host":"192.168.1.20","port":22}}}'
```

```json
{"target":{"id":"tg_01M4ZEM9MSEJCTVT4KNSS1X5D3",…},"revision":{"dbEpoch":"01a13ee8-581f-74c2-a713-5a06c75d4532","seq":"6"},"applyStatus":{"state":"APPLY_STATE_APPLIED","agentsTotal":2,"agentsApplied":2}}
```

`applyStatus.state` is `APPLY_STATE_PENDING`, `APPLY_STATE_APPLIED`, `APPLY_STATE_REJECTED` (the
reasons are in `agents[].errors`) or `APPLY_STATE_APPLY_TIMEOUT`. Agents without a control session
are listed in `offline` and do not hold the state at pending. A duration that does not parse means
no wait. To follow a revision later, call `StatusService.GetApplyStatus` with the org and the
revision, or stream `WatchApplyStatus` ([Watch for changes](#watch-for-changes)). The command line
waits only when you give it `--wait`.

### Preview a route

`RouteService.PreviewRoute` takes a route as `CreateRoute` does, or with `route.id` and
`updateMask` a change of one, and saves nothing. It answers with the route as it would be stored,
the gateways that would serve it, the connectors its streams would reach, and what a gateway would
refuse:

```sh
rpc RouteService/PreviewRoute "{\"orgId\":\"$ORG\",
  \"route\":{\"name\":\"db\",\"gatewayGroupId\":\"gwg_01M4ZEJ9BNEJWTRGAE2YEZEZ7D\",\"tcp\":{\"port\":20010}}}"
```

```json
{"route":{"name":"db","gatewayGroupId":"gwg_01M4ZEJ9BNEJWTRGAE2YEZEZ7D","enabled":true,"tcp":{"port":20010,…},…},"gatewayIds":["gw_01M4ZEJPH7EHCT1XTFPV3MFHPH"]}
```

A route the write would refuse gets the same error the write would give, for example a port
outside the pools:

```json
{"code":"failed_precondition","message":"routes: the port is in no pool of the gateway group","details":[{"type":"google.rpc.ErrorInfo","value":"ChBQT1JUX05PVF9JTl9QT09MEghycG1nci52MQ","debug":{"reason":"PORT_NOT_IN_POOL","domain":"rpmgr.v1"}}]}
```

### Export manifests

`ManifestService.ExportManifests` writes the org's resources as YAML manifests, the format the web
UI's YAML view shows: every kind, the kinds you name (`Route`, `AccessPolicy`, `GatewayGroup`,
`Gateway`, `PortPool`, `Domain`, `Connector`, `CABundle`), or the resources you name by ID
([07](../../07-api.md#declarative-manifests)):

```sh
rpc ManifestService/ExportManifests "{\"orgId\":\"$ORG\",\"kinds\":[\"Route\"]}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["yaml"], end="")'
```

```yaml
kind: Route
metadata:
  name: ssh
spec:
  enabled: true
  gatewayGroup: home
  targets:
    - connector: nas
      enabled: true
      hostPort:
        host: 192.168.1.20
        port: 22
      proxyProtocol: PROXY_PROTOCOL_NONE
      upstreamProtocol: UPSTREAM_PROTOCOL_TCP
      weight: 1
  tcp:
    idleTimeoutSeconds: 600
    port: 20046
```

Manifests name other resources by their names, never carry secrets, and leave out decommissioned
agents. Applying manifests is not there yet; it is planned for Phase 2
([13](../../13-roadmap.md#phase-2--production)).

### Manage a webhook endpoint

An endpoint receives the organisation's events as signed HTTPS requests. Owners and Admins manage
endpoints; nobody else can read them, because a receiver's URL may carry a token. The URL must start
with `https://` and hold no credentials. `eventTypes` names the types it wants, such as
`route.update` or a prefix such as `route.*`; none means all.

```sh
rpc WebhookService/CreateWebhook "{\"orgId\":\"$ORG\",
  \"webhook\":{\"url\":\"https://hooks.example.com/rpmgr\",\"eventTypes\":[\"route.*\"]}}"
```

The answer carries the endpoint and its `secret`, `rpmgr_whs_…`. It is shown once, here and in the
answer of `RotateWebhookSecret`, and no call reads it back: store it where the receiver can check
the `Rpmgr-Signature` header. After a rotation both secrets sign for a while, so the receiver can
switch without a gap. `UpdateWebhook` takes an update mask over `url`, `eventTypes` and `enabled`;
enabling an endpoint again clears a disable, also one that rpmgr made after days of failed
deliveries. `TestWebhook` sends a `webhook.test` event now and answers what the receiver said, and
`ListWebhookDeliveries` lists the attempts of an endpoint, the newest first. The format of the
events, the headers and the limits are in [07](../../07-api.md#webhooks-phase-2),
[04](../../04-security.md#webhooks-and-the-egress-guard-phase-2) and
[03](../../03-connections.md#timeouts-keepalive-and-backoff).

## Change a resource: etags and update masks

An `Update…` method changes only the fields its **update mask** names, under the resource's
**etag**:

```sh
rpc RouteService/UpdateRoute '{"route":{"id":"rt_01M4ZEM8WFF24VT354JQBHZSZ2","description":"SSH to the NAS",
  "tcp":{"idleTimeoutSeconds":600}},"updateMask":"description,tcp.idleTimeoutSeconds","etag":"1"}'
```

- **The mask.** In JSON the mask is one string of field paths separated by commas, in
  lowerCamelCase, through nested messages with dots: `"http.hostnames,http.maintenanceMessage"`.
  A path in snake_case is refused when the request is parsed. A field the mask names takes the
  value the request gives, or goes back to unset or its default where the request leaves it out;
  every other field stays as it is. An empty mask, an unknown path or one you may not change, such
  as `etag` or `id`, is `INVALID_ARGUMENT`. The fields each method lets you change are listed in
  the comment of its request message.
- **The etag** is a number that grows with every change of the resource, in every answer that
  returns the resource. Send the one you read: if someone changed the resource since, the update
  is `FAILED_PRECONDITION` with the reason `ETAG_MISMATCH` and the resource as it is now among the
  error's details, so you can show what changed and try again. An empty etag skips the check, as
  the command line's `--force` does. `Delete…` and `Decommission…` methods take an etag too.
- **Switches** are fields like any other: `enabled` of a route, connector or gateway, and
  `http.maintenance` of an HTTP route, each with its mask path.

## Retry safely: request IDs

The methods that create something, those that mint tokens included, take a `requestId` (its
request message has the field), any string of at most 128 characters, such as a UUID. Within the
deduplication window ([03](../../03-connections.md#timeouts-keepalive-and-backoff)) the controller
runs each request ID once per user and method:

- a retry with the same ID and the same request gets the first answer again, and changes nothing
  more;
- the same ID with another request is `INVALID_ARGUMENT`
  (`api: the request_id was used for another request`);
- a retry while the first request has not answered yet is `ABORTED`; retry it a moment later;
- a request that failed did not use its ID: a retry runs again.

So a script that lost an answer to a network error can send the same request again without
creating the resource twice. Updates need no request ID: the etag protects them.

Every request that the audit log records answers with the header `Rpmgr-Request-Id`, which is the
request's `requestId` if it had one, else an ID the controller made (`req_…`). The request's audit
entries carry the same ID ([Audit log](../operations/audit-log.md)).

## Watch for changes

`StatusService.WatchEvents` streams the org's changes as they happen; the web UI uses it instead of
polling ([07](../../07-api.md#events-and-streaming)):

- one event per configuration revision, with the IDs of the resources it changed, who changed them
  and when; read those resources again;
- events without a revision that name routes, gateways and connectors whose status changed, such
  as a route's state or an agent's control session going up or down;
- a `resumeToken` in every event. Reconnect with the last one and you get every change since, so
  you miss none. After a restore of the controller, a token of the old database gets one event
  with `"reset": true`: read everything again.

`StatusService.WatchApplyStatus` streams a revision's apply status until it is final, or for at
most 60 s.

A stream uses the Connect streaming format: `Content-Type: application/connect+json`, and every
message, the request too, is preceded by five bytes, a flag byte and the message's length as a
32-bit big-endian number. A last message with the flag `0x02` ends the stream, with an error if
there was one. With `curl`:

```sh
body="{\"orgId\":\"$ORG\"}"
{ printf '\0'; printf '%08x' "${#body}" | xxd -r -p; printf '%s' "$body"; } |
  curl -sSN "$API/rpmgr.v1.StatusService/WatchEvents" \
    -H "Authorization: Bearer $RPMGR_TOKEN" -H "Content-Type: application/connect+json" \
    --data-binary @-
```

Each change then arrives as a five-byte prefix followed by JSON:

```json
{"revision":{"dbEpoch":"01a13ee8-581f-74c2-a713-5a06c75d4532","seq":"9"},"changedResources":["rt_01M4ZEM8WFF24VT354JQBHZSZ2"],"actor":"usr_01M4ZEHHDQE96SJT7GF77VK5YC","time":"2026-10-15T09:35:30.588936999Z","resumeToken":"MDFhMTNlZTgt…"}
```

For more than a quick look, use a ConnectRPC client library, which handles the framing: generate
a client from the proto files with `buf generate`, or use the code the repository generates for
itself, Go in `gen/` and TypeScript in `web/src/gen/`.

## Errors

An error answers with an HTTP status and a JSON body with the Connect error code, a message and
details:

```json
{"code":"failed_precondition","message":"domains: no verified domain of the org covers the hostname","details":[{"type":"google.rpc.ErrorInfo","value":"ChNET01BSU5fTk9UX1ZFUklGSUVEEghycG1nci52MQ","debug":{"reason":"DOMAIN_NOT_VERIFIED","domain":"rpmgr.v1"}}]}
```

Read the `code` in the body rather than the HTTP status. Each detail has a `type`, the protobuf
message in base64 in `value`, and the same message as JSON in `debug`:

- `google.rpc.ErrorInfo` with the domain `rpmgr.v1` carries a **reason**, the stable name of what
  went wrong, and sometimes metadata, such as the missing `permission`.
- `buf.validate.Violations` lists the fields that broke the request's rules, each with its path,
  the rule and a message, for `INVALID_ARGUMENT`.
- `google.rpc.RetryInfo` says how long to wait, for `RESOURCE_EXHAUSTED`.
- A resource of the method, such as `rpmgr.v1.Route`, is the resource as it is now, for
  `ETAG_MISMATCH`.

Messages never hold secrets or other orgs' data. An error that the method did not write for you is
`INTERNAL` without details; the controller's log has them.

| Code | When | Reason |
|---|---|---|
| `invalid_argument` | A field breaks its rules (with `buf.validate.Violations`), a bad mask, a bad page token, a reused request ID | — |
| `invalid_argument` | `StepUp` without a second factor, for a user who has one | `MFA_REQUIRED` |
| `already_exists` | A name, hostname, public port or domain claim that is taken already | — |
| `unauthenticated` | No credentials, or credentials that are not valid, or any API token from an address that sent too many failed ones ([Rate limits](#rate-limits)) | — |
| `unauthenticated` | The method needs a recent step-up | `STEP_UP_REQUIRED` |
| `unauthenticated` | `Login` without the second factor of a user who has one | `MFA_REQUIRED` |
| `permission_denied` | Your role or the token's scopes lack the permission; the metadata names it | `PERMISSION_MISSING` |
| `permission_denied` | The org requires a second factor and you signed in without one, or the token was made from such a session | `MFA_REQUIRED` |
| `not_found` | The resource does not exist, or belongs to an org you are not in | — |
| `failed_precondition` | The resource changed since you read it | `ETAG_MISMATCH` |
| `failed_precondition` | Something still depends on what you delete, such as a gateway group that has gateways | `DEPENDANTS_EXIST` |
| `failed_precondition` | A hostname under no verified domain of the org | `DOMAIN_NOT_VERIFIED` |
| `failed_precondition` | ACME for a wildcard hostname, which needs an uploaded certificate | `WILDCARD_NEEDS_CERTIFICATE` |
| `failed_precondition` | An uploaded certificate that does not cover each of the route's hostnames | `CERTIFICATE_NOT_COVERING` |
| `failed_precondition` | A port outside the gateway group's pools | `PORT_NOT_IN_POOL` |
| `failed_precondition` | An access policy with basic auth on a route that is not HTTP | `BASIC_AUTH_NOT_HTTP` |
| `failed_precondition` | An access policy with a required header on a route that is not HTTP | `REQUIRE_HEADER_NOT_HTTP` |
| `failed_precondition` | A change while the org or the instance is in restore review, read-only ([Backup and restore](../operations/backup-and-restore.md)) | `RESTORE_REVIEW` |
| `failed_precondition` | Decommissioning the all-in-one's built-in gateway or connector, and other states that forbid the change; the message says which | — |
| `resource_exhausted` | No free port is left in the pools | `POOL_EXHAUSTED` |
| `resource_exhausted` | The org's port quota for the gateway group is used up | `QUOTA_REACHED` |
| `resource_exhausted` | Too many attempts: wait as `google.rpc.RetryInfo` says ([Rate limits](#rate-limits)) | — |
| `aborted` | A retry while the first request with the same request ID is still running | — |
| `unavailable` | The controller cannot do it at all now, such as a password reset without a mail relay | — |
| `deadline_exceeded` | A connector did not answer in time, such as when it reads a target's certificate | — |
| `internal` | Anything else; see the controller's log | — |

## Rate limits

The controller limits only what an attacker could guess at
([04](../../04-security.md#human-authentication-and-sessions)):

- sign-ins and completed password resets per client address, and failed sign-ins per account,
  which wait longer after each failure in a row;
- requested password resets per client address and per e-mail address;
- failed step-ups and wrong current passwords per user, counted together;
- API tokens that fail, per client address.

A limited call is `RESOURCE_EXHAUSTED` with `google.rpc.RetryInfo`, whose `retryDelay` says how
long to wait. Failed API tokens are the exception. After several from one address, every token
from that address, valid ones too, is refused with `UNAUTHENTICATED`
(`api: the credentials are not valid`) and no `RetryInfo` until the wait is over. So a script
that keeps sending a wrong token also locks out the right one from its host: fix the token, wait,
and try again. Enrollments are limited per client address as well, but in the agents' own
protocol, not in this API ([Enrolling connectors](../connectors/enroll.md)).

Calls with a valid token are not limited otherwise; still, keep scripts from polling. Watch for
changes with a stream instead.

## Compatibility

The API is versioned as `rpmgr.v1`. Within it, changes only add fields, methods and enum values;
removing or changing anything needs `rpmgr.v2`, served next to `v1` for a while
([07](../../07-api.md#versioning-and-compatibility)). Ignore fields you do not know, and treat an
enum value you do not know as unspecified.

## The proto files

The files in [proto/rpmgr/v1](../../../proto/rpmgr/v1/) are the reference: every method, every
field, its rules and a comment on what it does. Each method also states the permission it needs,
in its `(rpmgr.v1.authz)` option, whether it needs a step-up, and whether it changes nothing
(`idempotency_level = NO_SIDE_EFFECTS`). Secret fields carry `(rpmgr.v1.sensitive)` and are
redacted in logs and the audit log ([options.proto](../../../proto/rpmgr/v1/options.proto)). A
secret you send, such as a password, is never returned. A secret the controller makes, such as a
new API token, an enrollment token, recovery codes or a reset or invitation link, is returned
once, in the answer that makes it.

| Service | File | What it covers |
|---|---|---|
| `AuthService` | [auth.proto](../../../proto/rpmgr/v1/auth.proto) | Sign-in, step-up, sessions, password reset |
| `UserService` | [user.proto](../../../proto/rpmgr/v1/user.proto) | Your account, its authenticator and recovery codes; users and the Instance Admin role for the Instance Admin; recovering another user's account ([Members and roles](../accounts/members-and-roles.md#recover-a-members-account)) |
| `OrgService` | [org.proto](../../../proto/rpmgr/v1/org.proto) | The organisation, its members and invitations; the restore review |
| `TokenService` | [token.proto](../../../proto/rpmgr/v1/token.proto) | Your personal API tokens |
| `EnrollmentService` | [enrollment.proto](../../../proto/rpmgr/v1/enrollment.proto) | Enrollment tokens for connectors and gateways, the install command |
| `ConnectorService` | [connector.proto](../../../proto/rpmgr/v1/connector.proto) | Connectors, their status, switching them off, decommissioning |
| `GatewayService` | [gateway.proto](../../../proto/rpmgr/v1/gateway.proto) | Gateway groups, gateways, port pools and port quotas |
| `RouteService` | [route.proto](../../../proto/rpmgr/v1/route.proto) | Routes, their targets, preview, and reading a target's certificate |
| `DomainService` | [domain.proto](../../../proto/rpmgr/v1/domain.proto) | Domain claims and their proofs |
| `CertificateService` | [certificate.proto](../../../proto/rpmgr/v1/certificate.proto) | Uploaded and ACME certificates, CA bundles |
| `PolicyService` | [policy.proto](../../../proto/rpmgr/v1/policy.proto) | Access policies |
| `StatusService` | [status.proto](../../../proto/rpmgr/v1/status.proto) | Apply status of revisions, the event stream |
| `MetricsService` | [metrics.proto](../../../proto/rpmgr/v1/metrics.proto) | Traffic of a route, and the org's overview |
| `AuditService` | [audit.proto](../../../proto/rpmgr/v1/audit.proto) | The audit log, and verifying its chains |
| `SettingsService` | [settings.proto](../../../proto/rpmgr/v1/settings.proto) | Instance and organisation settings, the mail relay's password |
| `PkiService` | [pki.proto](../../../proto/rpmgr/v1/pki.proto) | The internal CA's keys and the intermediate's rotation |
| `WebhookService` | [webhook.proto](../../../proto/rpmgr/v1/webhook.proto) | An organisation's webhook endpoints, their secrets and deliveries |
| `ManifestService` | [manifest.proto](../../../proto/rpmgr/v1/manifest.proto) | YAML manifests of the org's resources |

The shared messages are in [common.proto](../../../proto/rpmgr/v1/common.proto). The design of the
API, with its rules for new methods, is in [07](../../07-api.md).
