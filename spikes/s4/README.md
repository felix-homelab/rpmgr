# Spike S4: Does ConnectRPC carry the agent control session?

Throw-away code for spike S4 ([docs/13-roadmap.md](../../docs/13-roadmap.md#phase-0--spikes),
issue #8). The result and the decision are in `docs/spikes/S4.md`; this directory only has to make
every run repeatable. It is never merged (CONTRIBUTING.md, "Spikes").

## Layout

| Path | What |
|---|---|
| `proto/rpmgr/agent/v1/control.proto` | Reduced sketch of the agent `Control` service (03, "Service sketch") |
| `gen/` | Generated code: protobuf, connect-go, grpc-go (committed) |
| `internal/pki` | Test CA: P-256 root with `spiffe://<td>`, one name-constrained intermediate, 7-day leaves with SPIFFE URI and DNS SANs |
| `internal/control` | connect-go server on `net/http` (TLS 1.3, mutual TLS, HTTP/2) and connect-go client (gRPC protocol); the S4 tests |
| `internal/proxy` | TCP relay that can route by SNI without terminating TLS and can blackhole traffic |
| `internal/grpcstack` | The rule's fallback, grpc-go, on the same contract: native server, `ServeHTTP` on `net/http`, client; comparison tests |
| `cmd/idle` | 10 000 idle sessions: memory and CPU per session, controller in a child process |
| `results/` | Raw outputs of the runs below |

## Versions

Go 1.27.1 (`toolchain go1.27.1`), connectrpc.com/connect v1.21.0, google.golang.org/protobuf
v1.36.12, google.golang.org/grpc v1.84.0, golang.org/x/net v0.59.0 (only for the comparison with
`x/net/http2`, see below), golang.org/x/sync (errgroup in `cmd/idle`). Code generation: buf v1.73.0,
protoc-gen-go v1.36.12, protoc-gen-connect-go v1.21.0, protoc-gen-go-grpc v1.6.2.

## Repeat the runs

All commands from this directory, with Go 1.27.1 on `PATH`.

```sh
# Code generation (the output is committed in gen/)
GOBIN=$HOME/.cache/rpmgr-s4-bin go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
GOBIN=$HOME/.cache/rpmgr-s4-bin go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.21.0
GOBIN=$HOME/.cache/rpmgr-s4-bin go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
GOBIN=$HOME/.cache/rpmgr-s4-bin go install github.com/bufbuild/buf/cmd/buf@v1.73.0
PATH=$HOME/.cache/rpmgr-s4-bin:$PATH buf generate && buf lint

# All tests, with the race detector (results/test-race.txt)
go test -race -count=1 -timeout 600s -v ./...

# HTTP/2 PING liveness at the real values, 20 s / 10 s, about 35 s (results/liveness-real-values.txt)
S4_REAL_LIVENESS=1 go test -count=1 -v -run TestLivenessRealValues ./internal/control/

# 10 000 idle sessions (results/idle-*-10000.json, logs in results/idle-*-10000.txt)
go build -o /tmp/s4-idle ./cmd/idle
/tmp/s4-idle -stack connect -n 10000 -idle 60s -out results/idle-connect-10000.json
/tmp/s4-idle -stack grpc -n 10000 -idle 60s -out results/idle-grpc-10000.json
```

Machine of the recorded runs: 13th Gen Intel Core i7-1370P (20 threads), 32 GB, WSL2 kernel
6.18.33.2, Ubuntu 26.04, `ulimit -n` 1 048 576, all processes on loopback. Other spikes ran on the
same machine at the same time, so CPU figures are indicative only; memory figures come from the
runtime statistics of the measured processes.

## Tests and what they show

| Test | Criterion | Shows |
|---|---|---|
| `TestBidiFullDuplex` | (1) | 62.5 MiB each way at the same time, ordered, over HTTP/2, identity visible to the handler |
| `TestHalfCloseThenServerSends` | (1) | Client half-close: the server reads EOF and keeps sending |
| `TestFinding_CancelDoesNotReachBlockedStream` | (2) | **Finding:** a cancelled client context ends neither a pending `Receive` nor the server's call |
| `TestFinding_CancelDoesNotReachBlockedStreamXNet` | (2) | The same with `x/net/http2`'s `Transport`: not specific to Go 1.27's `net/http` |
| `TestCancelWithCloseResponseWorkaround` | (2) | Closing the response side on cancel ends both sides within about 1 ms |
| `TestCancelReachesServerOnNextCall` | (2) | **Finding:** the cancel reaches the server only with the next stream call, and the server reads a clean EOF |
| `TestServerErrorReachesClient`, `TestServerCloseIsEOF` | (2) | Server errors and clean ends reach the client |
| `TestDeadlineHeaderPropagates` | (3) | The deadline travels in `grpc-timeout` |
| `TestFinding_DeadlineDoesNotEndBlockedStream` | (3) | **Finding:** an expired deadline ends neither a pending `Receive` nor a server handler waiting in `Receive` |
| `TestUnaryDeadline` | (3) | Unary deadlines work on both sides |
| `TestMessageSizeLimits` | (4) | 4 MiB passes, 4 MiB + 1 is refused by send and read limits on both sides (gzip off) |
| `TestFinding_SendLimitCountsCompressedSize` | (4) | **Finding:** with gzip, the sender's limit counts the compressed size |
| `TestFinding_ReadLimitBlocksOnOpenStream` | (4) | **Finding:** a read-limit error on a stream the server keeps open blocks `Receive` |
| `TestLivenessBlackhole`, `TestLivenessRealValues`, `TestIdleSessionSurvivesPings` | (5) | `HTTP2Config.SendPingTimeout`/`PingTimeout` detect a dead path on both ends, directly and through a TLS passthrough |
| `cmd/idle` | (6) | Memory and idle CPU of 10 000 sessions |
| `TestTLSPassthrough`, `TestRejectsWrongIdentity` | (7), TLS | SNI-only routing, end-to-end mutual TLS, no plaintext at the proxy; wrong CA, wrong role, TLS 1.2 and missing certificates refused |
| `internal/grpcstack` tests | rule | grpc-go client: cancel and deadline end both sides within about 1 ms against grpc-go's server, `ServeHTTP` and the connect-go server; read limits return at once; keepalive detects a dead path; full duplex |

The `TestFinding_*` tests assert the faulty behaviour, so they fail when a library fixes it.
