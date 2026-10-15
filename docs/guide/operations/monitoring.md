# Monitoring

Every rpmgr process reports its health, its metrics and its logs, and can send traces. This page is
for whoever runs rpmgr's hosts and wants to watch them: it covers the admin listener with its
health checks and Prometheus metrics, traces, logs, and what the web UI shows. Which metric means
what is listed in [10](../../10-operations.md#metrics); this page shows how to use them.

## The admin listener

Each role serves `/healthz`, `/readyz` and `/metrics` on its **admin listener**, a separate HTTP
port that only the host, or a private network, can reach. Its address is `listen.admin` in the
boot file ([Boot files](../reference/boot-files.md)). The defaults differ per role, so roles on one
host never collide ([10](../../10-operations.md#ports)):

| Role | Default admin address |
|---|---|
| Controller, all-in-one | `127.0.0.1:7381` |
| Gateway | `127.0.0.1:7382` |
| Connector | `127.0.0.1:7383` |

If the default port is taken, an agent's install command takes the next free one and writes it into
the boot file, so look there for the one in use. `rpmgr setup` refuses a port that is taken; choose
another with `--listen-admin` ([rpmgr setup](../install/setup.md)). The admin listener is never
public: a boot file that
binds it to all interfaces, a public address or a host name other than `localhost` is refused at
start. To let a scraper on another host read it, bind it to a private address, such as
`10.0.0.5:7383`, and allow only the scraper in the host's firewall.

## Health checks

```sh
curl -s http://127.0.0.1:7383/healthz
curl -s http://127.0.0.1:7383/readyz
```

- `/healthz` answers `ok` while the process runs.
- `/readyz` answers `ok` when the role can do its work, and otherwise HTTP 503 with the reason,
  such as `not ready: no control session`
  ([10](../../10-operations.md#health)):

| Role | Ready when |
|---|---|
| Controller | The database answers and every migration of the binary is applied (`not ready: database: …`, `not ready: 2 migrations not applied`) |
| Gateway | It holds a control session (`no control session`) and applied a configuration (`no snapshot applied`) |
| Connector | The same as a gateway. Its data sessions are reported apart and do not make it unready |
| All-in-one | Its controller, gateway and connector are all ready; the reasons of each that is not are listed |

A check that takes longer than the limit counts as not ready. Use `/readyz` for load-balancer
health checks and after upgrades: `rpmgr setup` waits for it before it reports success, and
`rpmgr status` shows its answer on agent hosts
([Status and diagnostics](../connectors/status-and-diagnostics.md#rpmgr-status)).

## Metrics

`/metrics` serves Prometheus metrics. Labels carry stable IDs, such as `route="rt_…"`, never
client addresses. An all-in-one serves the metrics of its controller, gateway and connector on its
one listener, and adds a `role` label (`gateway` or `connector`) to the agents' series.

A Prometheus job on each host, or on a host that can reach their private addresses:

```yaml
scrape_configs:
  - job_name: rpmgr
    static_configs:
      - targets: ["127.0.0.1:7381"]   # controller or all-in-one
      - targets: ["127.0.0.1:7382"]   # gateway
      - targets: ["127.0.0.1:7383"]   # connector
```

The full table of metrics is in [10](../../10-operations.md#metrics). Those most worth watching:

| Watch | Metric |
|---|---|
| Agents connected to the controller | `rpmgr_controller_control_sessions` |
| Changes the agents did not apply | `rpmgr_agent_apply_status{status="rejected"}`, `{status="apply_timeout"}` |
| Agent certificates that are not renewed | `rpmgr_agent_cert_expiry_timestamp_seconds` |
| Route certificates from ACME that run out | `rpmgr_acme_cert_expiry_timestamp_seconds` |
| Connections that reached no target | `rpmgr_route_connections_total` by `result` |
| Targets the local policy refuses | `rpmgr_connector_policy_denied_total` |
| Data sessions and their round trip | `rpmgr_gateway_sessions`, `rpmgr_connector_session_rtt_seconds` |
| Hosts whose UDP buffers are too small for QUIC | `rpmgr_quic_udp_buffer_warning` |
| Audit entries not yet covered by a signed checkpoint | `rpmgr_audit_checkpoint_age_seconds` |
| Revocations not yet copied off the host | `rpmgr_revocation_log_unshipped` |
| Sign-ins and enrollments a rate limit refused | `rpmgr_ratelimit_refused_total` |

Alerts that pay off, with their conditions, are in
[10](../../10-operations.md#suggested-alerts).

## In the web UI

- The **Overview** sums up routes, agents, certificates and domains, and lists under **Needs
  attention** the agents without a control session, the routes that do not serve fully or were
  rejected, certificates that failed or expire soon, unverified domains and your API tokens that
  expire soon. Disabled connectors and drained gateways are left out.
- A route's page shows its state per target and gateway, and its traffic
  ([Preview and apply](../routes/preview-and-apply.md#route-states)).
- A connector's page shows its sessions and the routes it reports not ready
  ([Status and diagnostics](../connectors/status-and-diagnostics.md#in-the-web-ui)).
- **Settings** warns when the revocation log has no copy off the controller's host, or when an
  entry has waited too long to reach it ([Settings](settings.md#warnings-on-the-settings-page)).

## Traces

rpmgr can send OpenTelemetry traces to a collector over OTLP/HTTP. A traced public request can be
followed from the gateway through the connector, and on into your service if it reads the W3C
`traceparent` header. Tracing is off by default. Turn it on in the `tracing` section of each role's
boot file ([10](../../10-operations.md#traces)):

```yaml
tracing:
  otlp_endpoint: https://collector.example.com:4318/v1/traces
  sample_ratio: 0.05
```

- `otlp_endpoint` is the collector's OTLP/HTTP traces URL; empty turns tracing off.
- `sample_ratio`, from 0 to 1, is the share of new traces that are sampled; the default is in
  [10](../../10-operations.md#traces). Spans that fail are sent whatever the sampling.
- A connector follows the sampling decision of the gateway that opened the stream. A gateway does
  not follow a public client's `traceparent`, so that clients cannot make it trace every request.
- The exporter goes through `HTTPS_PROXY` if one is set
  ([Environment variables](../reference/environment.md#proxies)).
- Restart the role after a change of its boot file. At a stop, it sends what is left.

## Logs

Every role writes one structured line per event to standard error, which systemd keeps in the
journal under the role's unit:

```sh
sudo journalctl -u rpmgr-connector.service -f              # follow a connector
sudo journalctl -u rpmgr-controller.service --since -1h    # the last hour of a controller
```

The units are `rpmgr-controller`, `rpmgr-gateway`, `rpmgr-connector` and `rpmgr-all-in-one`.
`systemctl status rpmgr-<role>.service` shows whether the unit runs and its last lines. The journal
stores every line of rpmgr at the same priority, so `journalctl -p warning` shows nothing; filter
on each line's own `level` instead, as below.

The `log` section of the boot file sets the level and the format:

```yaml
log:
  level: debug    # debug, info (the default), warn or error
  format: json    # json (the default) or text
```

Restart the role after a change: the boot file is read at start. In JSON, each line has `time`,
`level`, `msg` and the event's fields, so a tool such as `jq` can filter them:

```sh
# a controller's errors
sudo journalctl -u rpmgr-controller.service -o cat | jq -c 'select(.level == "ERROR")'
# a gateway's warnings and errors
sudo journalctl -u rpmgr-gateway.service -o cat | jq -c 'select(.level == "WARN" or .level == "ERROR")'
```

Logs never hold secrets: tokens, passwords, keys and fields named like them are replaced by a
placeholder before they are written ([04](../../04-security.md#secrets-at-rest-and-in-logs)).
Useful lines to know, by their `msg`:

| Message | Meaning |
|---|---|
| `controller running`, `gateway running`, `connector running` | The role started |
| `controller said goodbye` with `reason` `GOODBYE_REASON_REVOKED` | The agent's identity was revoked; it stops ([Connector lifecycle](../connectors/lifecycle.md)) |
| `controller said goodbye` with `reason` `GOODBYE_REASON_SUPERSEDED` | Another session of the same agent took over, for example during `rpmgr diag clock` |
| `control session ended` | The agent lost its control session and reconnects |
| `clock skew to the controller; TLS and certificate checks may fail` | The host's clock is off ([Troubleshooting](troubleshooting.md#clocks-and-certificates)) |
| `the local policy does not load: every target is blocked` | The connector's policy file is invalid ([The local policy](../connectors/local-policy.md)) |
| `the public URL has a self-signed certificate` | The controller has no certificate a browser trusts yet ([Domains and certificates](../domains-and-certificates.md)) |

Live logs of an agent in the web UI are planned for Phase 2
([05](../../05-features.md#observability)).
