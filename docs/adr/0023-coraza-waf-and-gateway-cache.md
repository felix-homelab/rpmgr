# ADR-0023: Gateways inspect requests with Coraza and the OWASP Core Rule Set and cache responses with a store of their own

Status: Proposed (design phase; spike S11 decides it) · Date: 2026-11-07

## Context

- **The scope.** Gateways may cache the responses of http routes and may run a WAF. Both are
  Phase 3 items, built after v1.0.0, and rpmgr is still not a CDN
  ([D171](../14-open-decisions.md#engineering), [00](../00-vision-and-scope.md#non-goals)). The
  behaviour is in [17](../17-cache-and-waf.md).
- **One static binary.** Every role is one Go binary built with `CGO_ENABLED=0`
  ([ADR-0002](0002-one-binary-three-roles.md)). A WAF that needs a C library or a second process
  breaks that, and a second process adds a hop on the path of every request.
- **Plaintext only on the gateway.** A WAF and a cache both need the request and the response in
  clear, which only the gateway has on a route it terminates
  ([04](../04-security.md#threat-model)).
- **An engine that is maintained.** Writing a rule engine and its rules is a project of its own.
  Coraza is Apache-2.0 [F coraza: LICENSE, v3.8.1, retrieved 2026-11-07] and runs the OWASP Core Rule
  Set, which is Apache-2.0 too [F crs: LICENSE, v4.30.0, retrieved 2026-11-07]. Coraza's module
  lists no cgo dependency [F coraza: go.mod, v3.8.1, retrieved 2026-11-07]; that the whole
  gateway still builds with `CGO_ENABLED=0` is not yet shown [V S11].
- **The rule set must be the signed software.** A rule set downloaded at run time would be code
  the release signature does not cover ([04](../04-security.md#release-signing)).
- **Cost.** The CRS costs CPU and memory per request, rising with the paranoia level, and its false
  positives rise with it. Both are unmeasured here [V S11]. The testbed is the small gateway of
  [D30](../14-open-decisions.md#project-and-process): 2 vCPU.
- **A shared cache has rules of its own.** RFC 9111 describes a shared cache
  [F rfc9111: §3.5, §4.4, retrieved 2026-11-07]. The owner's rules are stricter in places (never a
  response to a request with credentials, a key made of the route, access policy before the cache),
  and Go libraries that implement the RFC are built for other places: a cache for Caddy, a client-side
  cache that is archived, and a parser of `Cache-Control` [F gh: darkweak/souin, MIT, v1.7.9;
  gregjones/httpcache, MIT, archived; pquerna/cachecontrol, Apache-2.0, v0.2.0; retrieved
  2026-11-07].

## Decision

**WAF**
- The gateway runs **Coraza** in process with the **OWASP Core Rule Set**, at the versions the
  repository pins, embedded in the binary and covered by the release signature; no rule is
  downloaded at run time ([17](../17-cache-and-waf.md#engine-and-rule-set)).
- Tuning is the mode (`off`, `detection`, `blocking`), the paranoia level 1 to 4, the anomaly
  threshold and exclusions by rule ID or tag, optionally per path or parameter; custom rules are
  SecLang written by Instance Admins only, from an allow-list
  ([04](../04-security.md#gateway-cache-and-waf-phase-3)).
- Settings have the scopes instance, org, gateway group and route, the most specific winning and an
  instance floor clamping the result ([17](../17-cache-and-waf.md#scopes)).
- Request inspection only, up to a size limit; response inspection is off.

**Order and cache**
- The request path is TLS, access policy, WAF, cache, tunnel; a hit is judged like a miss and an
  attack never creates an object ([17](../17-cache-and-waf.md#the-request-path)).
- The cache is **our own** store (`internal/gwcache`) on `net/http`, a strict shared cache by
  default, with a memory tier and a disk tier ([17](../17-cache-and-waf.md#gateway-cache)). A
  library replaces it only if S11 shows one that meets rule C-1 below.

**Process**
- The ADR stays *Proposed* until S11 has run and applied its rules; the decisions
  [D172](../14-open-decisions.md#engineering) and [D173](../14-open-decisions.md#engineering) hold
  independently of the engine, so a different engine changes this ADR, not the behaviour.

## Consequences

**Positive**

- A WAF and a cache in the one binary, with no second process, no hop and no C library.
- The most used open rule set, maintained by others, with the pinned version covered by the release
  signature.
- A cache whose security rules are the product's own and are tested by named tests
  ([12](../12-testing-and-quality.md#security-testing)).

**Negative**

- The CRS and Coraza are in the gateway's process: a bug in either is a bug in the gateway, and a
  vulnerability in either is fixed only with a new release, as with any dependency.
- The CRS is rules for a family of attacks and produces false positives; tuning is the
  operator's work, which detection mode, exclusions and the hits tab make bearable but not nil.
- A cache of our own is more code to keep correct than a library would be.
- The binary grows by the engine and the rule set.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| ModSecurity through cgo, or as a sidecar | Breaks `CGO_ENABLED=0` and the single static binary, or adds a process and a hop |
| A WAF of our own | The rule set is the maintained work; an engine without it protects nothing |
| A rule set downloaded at run time | Code the release signature does not cover, and a new failure at start-up |
| A reverse proxy in front of gateways | A second product to run and a hop; the access policy would no longer come first |
| A cache library, as the default | The library candidates are built for other uses and none is known to meet the owner's rules; S11 may change this |
| A cache shared between gateways | Not a goal: it would be a CDN ([D171](../14-open-decisions.md#engineering)) |
| Cache before WAF | A hit would be served without a verdict, and a rule change would need a purge ([17](../17-cache-and-waf.md#the-request-path)) |

## Verification

Spike S11 ([13](../13-roadmap.md#phase-0--spikes)) runs at the start of the first Phase 3 slice of
either feature and applies these rules; each has its fallback, and a result that applies no
fallback moves this ADR to *Accepted*. The testbed is the small gateway of D30 (2 vCPU, 2 GiB), the
rule set at the pinned CRS version, and the numbers of [03](../03-connections.md#cache-and-waf-limits-phase-3)
are those under test.

| Rule | Must show | Fallback |
|---|---|---|
| **W-1 latency** | At 50 % of the WAF-off saturation load, the added p99 latency at paranoia levels 1 and 2 is at most 5 ms for a request without a body and at most 15 ms for one with a 10 KiB JSON body. Levels 3 and 4 are measured and reported | The inspected body size is lowered; a level that still fails is offered with its measured cost in the web UI; if level 1 fails, Coraza is rejected and the product owner decides on the WAF half of D171 |
| **W-2 throughput** | At level 2 the gateway serves at least 70 % of its WAF-off throughput for requests without a body, and CPU per request is reported for each level | As W-1 |
| **W-3 memory and apply** | One engine at level 2 holds at most 48 MiB and builds in at most 3 s; the profiles a gateway group may need (16) together hold at most 512 MiB; a snapshot that changes the WAF applies in at most 5 s with no in-flight request failed | The profile bound of 03 is lowered to what fits 512 MiB; engines that share the parsed rules where the engine allows it |
| **W-4 false positives** | Against at least 8 real self-hosted applications (for example Nextcloud, Gitea, Home Assistant, Jellyfin, Vaultwarden, Grafana, Paperless-ngx and WordPress), each driven through login, navigation, create, edit, delete, upload and its API in at least 1 000 requests in detection mode: at level 1 at most 1 request in 1 000 would be blocked per application and none on login, static files or health checks; level 2 is reported; **every** false positive at levels 1 and 2 can be removed by an exclusion of the kinds designed (rule ID or tag, path, parameter) | The default recommendation starts at level 1; a kind of exclusion the designed ones cannot express is added to [03](../03-connections.md#cache-and-waf-limits-phase-3) and [06](../06-data-model.md#cache-and-waf-phase-3) before the WAF is built |
| **W-5 detection** | The CRS's own regression tests run as Coraza's CI runs them (go-ftw) at levels 1 and 2 pass, except those Coraza itself lists as skipped [V S11] | A failing rule family is listed in the documentation as not working; if a family fails that the product claims, the paranoia levels offered drop to those that pass |
| **W-6 build and engine** | The gateway builds with `CGO_ENABLED=0` on every supported platform of [10](../10-operations.md#supported-platforms); the binary grows by at most 25 MiB; `govulncheck` finds nothing; exclusions by generated per-transaction rules work with path and parameter conditions; the custom-rule allow-list can be enforced on the parsed text | Engine profiles instead of generated exclusions if they do not; the allow-list parsed by rpmgr if the engine does not expose enough |
| **C-1 library or own** | A cache library is adopted only if it meets the shared-cache part of the HTTP cache test suite at 95 % of its required tests [V S11], supports without a fork every rule of [17](../17-cache-and-waf.md#gateway-cache) (never storing or looking up a response of a credentialed request, the route in the key, `Vary`, rules, purge by prefix with a generation, byte-bounded LRU in two tiers, a cursor listing, collapsing, streaming storage), is licensed Apache-2.0, MIT or BSD, has a release in the last 12 months and no cgo, and its adapter is at most half the size of our own store | Our own store, which is the default |
| **C-2 hit cost** | At 5 000 hits a second of 10 KiB objects a memory hit adds at most 0.5 ms at p50 and 2 ms at p99, a disk hit at most 3 ms at p99, and storing costs a miss at most 10 % of its throughput | Smaller default limits in 03; a smaller memory tier object size |
| **C-3 store** | The index of 262 144 objects holds at most 100 MiB; the index of a full 1 GiB disk tier rebuilds in at most 30 s; no data race under `-race` with stores, evictions and purges together; 1 000 kills of the process during writes leave no half object that a hit could serve | The minimum charge per object is raised; the disk tier's limit is lowered |
