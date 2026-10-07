# Spike S2: reverse HTTP/2 as the TCP transport

Throw-away prototype for spike S2 (issue #6, [docs/13](../../docs/13-roadmap.md#phase-0--spikes),
[ADR-0005](../../docs/adr/0005-reverse-http2-fallback.md)). This directory lives only on the branch
`tmp/s2-reverse-h2` and the archive tag `spike/s2`; it is never merged. The result is
`docs/spikes/S2.md`.

## What it builds

A connector dials a gateway over TCP + TLS 1.3 with mutual TLS (test CA, SPIFFE IDs, ALPN
`rpmgr-tunnel-h2/1`, `ServerName` `<gateway-id>.gateway.<td>`), then serves HTTP/2 on the connection
it dialled; the gateway is the HTTP/2 client and opens every stream: the session control stream
first, one request per user connection, and streams the connector asks for with `OpenRequest`.

| File | Content |
|---|---|
| `pki.go` | Test CA, leaf certificates, TLS 1.3 mutual-TLS configurations with SPIFFE checks |
| `wire.go` | `varint ‖ payload` framing (JSON payloads instead of protobuf), framed chunks |
| `impl.go` | The two HTTP/2 implementations under test, behind one interface |
| `session.go` | Gateway and connector sessions: control stream, streams, `OpenRequest`, half-close modes |
| `stall.go` | Prototype of the stall-detection rule of 03 |
| `netsim.go` | TCP proxy that adds a one-way delay or blackholes the connection |
| `*_test.go` | One test per pass criterion; `measure_test.go` for the measurements |
| `run.sh` | Runs everything and writes the raw output to `results/` |

**Implementations** (`impl.go`):

- `stdlib`: net/http's own HTTP/2 in Go 1.27 — `http.Server` with `Protocols` set to unencrypted
  HTTP/2 on the connection (the TLS connection is wrapped so net/http speaks HTTP/2 with prior
  knowledge instead of looking for ALPN `h2`), and `http.Transport.NewClientConn` whose
  `DialContext` returns the accepted connection. Windows and PINGs come from `http.HTTP2Config`.
- `xnet`: `golang.org/x/net/http2` v0.59.0 (`Server.ServeConn`, `Transport.NewClientConn`), the API
  ADR-0005 names. With Go 1.27 this package is a deprecated wrapper around net/http's
  implementation; built with `-tags http2legacy` it is x/net's own implementation.

**Half-close modes** (`session.go`):

- `raw`: the design as written in ADR-0005 — raw bytes in both bodies; the connector's FIN is the
  end of the HTTP response.
- `framed`: the gateway-to-connector direction stays raw (its FIN is the request's END_STREAM);
  the connector-to-gateway direction is a sequence of `varint(length) ‖ bytes` chunks, a
  zero-length chunk is the connector's FIN, and the response ends only when both directions have.

## Criteria and tests

| S2 criterion | Tests |
|---|---|
| 1 GiB in both directions concurrently | `TestDuplex` (1 GiB; 64 MiB with `-short` or `-race`) |
| Half-close each side | `TestHalfClose_GatewayFirst`, `TestHalfClose_ConnectorFirst_Framed`, `TestHalfClose_ConnectorFirst_RawLosesClientData` |
| Abort mid-stream | `TestAbort` (gateway and connector side) |
| Control stream first; `OpenRequest` | `TestControlStreamIsFirstRequest`, `TestStreamBeforeControlRefused`, `TestOpenRequest_*` (accepted, rejected, duplicate `open_id`, 300 ms and 10 s timeout) |
| +1 RTT and the first chunk | `TestMeasureOpenLatency` (`S2_MEASURE=1`) |
| Tuned windows on a client conn over an existing connection | `TestWindowsApplied`, `TestMeasureThroughputAt100ms` |
| No deadlock under flow-control pressure; stall detection | `TestFlowControl_*` |
| Never blocks at the stream limit | `TestStreamLimit_NeverBlocks`, `TestStreamLimit_TenThousand` |
| HTTP/2 PING liveness | `TestPingLiveness_Blackhole` (15 s + 10 s; scaled with `-short`) |
| Identity | `TestTLS_WrongGatewayIDRejected` |

## Repeating the runs

Requirements: Go 1.27.1 (the scripts expect it in `~/.local/go1.27.1`; any `go1.27.1` on `PATH`
works when `run.sh` is adjusted), Linux, about 8 GiB of free memory for the 10 000-stream test.
No Docker, no network access after `go mod download`.

```sh
./run.sh criteria   # all criteria, stdlib + x/net wrapper   → results/criteria.txt
./run.sh legacy     # the same with x/net's own HTTP/2       → results/criteria-legacy.txt
./run.sh race       # with -race, 64 MiB transfers           → results/criteria-race.txt
./run.sh measure    # open latency and throughput            → results/measure.txt
./run.sh one '<regex>' [-short]                              # → results/dev-run.txt
```

`results/streams-10k-*.txt` are single runs of `TestStreamLimit_TenThousand` per frame size,
each in its own process so that the heap readings do not overlap.

Numbers are from a shared development host (WSL2, 20 cores) while other spikes ran in parallel;
throughput and memory are indicative. The RTT is injected by `netsim.go` in user space, not by
netem.
