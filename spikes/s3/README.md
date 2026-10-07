# Spike S3: TCP/443 and UDP/443 multiplexing on the gateway

Throw-away prototype for spike S3 ([docs/13-roadmap.md](../../docs/13-roadmap.md#phase-0--spikes),
issue #7). The result is written down in `docs/spikes/S3.md`; this branch is never merged and is
kept as the tag `spike/s3`.

**Question.** Can the gateway multiplex TCP/443 and UDP/443 as designed in
[docs/03](../../docs/03-connections.md#port-443-multiplexing)? **Pass:** all clients routed
correctly; peek within limits; both ALPNs served from one UDP socket. **Rule:** if one quic-go
listener cannot serve both ALPNs well, tunnels move to a separate UDP port (`listen.tunnel_udp`).

## Layout

| Path | What |
|---|---|
| `mux/peek.go` | ClientHello peek: full TLS records, at most 16 KiB within 5 s, parsed with `cryptobyte`; the alternative peek through `crypto/tls` aborted in `GetConfigForClient`; replay connection |
| `mux/router.go` | TCP/443 router: the decision table of docs/03 |
| `mux/gateway.go` | Test gateway: in-process controller (agent, Reauth and UI names on one TLS stack, chosen by SNI), HTTP engine with per-SNI certificates, tunnel endpoint (mutual TLS), TLS-passthrough backend; test PKI in `mux/pki.go` |
| `mux/udp.go` | UDP/443: one `quic.Transport`, one listener for `h3` and `rpmgr-tunnel/1`, dispatch on the negotiated ALPN, per-ALPN TLS settings via `GetConfigForClient`, per-ALPN window budgets |
| `mux/relay.go` | Relay that delivers client bytes in ≤ 1448-byte segments (as on a 1500-byte MTU path) |
| `mux/*_test.go` | Tests for every pass criterion and the error paths; `FuzzParseClientHello` |
| `cmd/s3gw`, `cmd/s3probe`, `cmd/s3summary` | Gateway binary, Go client, and the summary of a real-client run |
| `scripts/` | Real-client run (Go, curl, Chromium, Firefox in pinned containers) |
| `results/` | Raw outputs of the runs below |

## Versions

| Component | Version |
|---|---|
| Go | go1.27.1 linux/amd64 (`toolchain` directive) |
| `github.com/quic-go/quic-go` | v0.63.0 (requires `go 1.26.0`) |
| `golang.org/x/crypto` (`cryptobyte`) | v0.57.0 |
| Playwright image | `mcr.microsoft.com/playwright:v1.63.0-noble` (digest in `scripts/images.sh`): Chrome for Testing 153.0.8010.12, its `chrome-headless-shell`, Firefox 155.0; `playwright-core` 1.63.0 from npm for Firefox |
| curl image | `curlimages/curl:8.22.0`: curl 8.22.0, OpenSSL 3.5.8, no HTTP/3 |
| Host | WSL2, Linux 6.18, x86-64, Docker 29.8 |

## How to repeat

```sh
export PATH=$HOME/.local/go1.27.1/bin:$PATH        # or any go1.27.1
go -C spikes/s3 test -count=1 -race -v ./...      # results/go-test-race.txt
go -C spikes/s3 test -run NoUnitTests -fuzz FuzzParseClientHello -fuzztime 60s ./mux/
bash spikes/s3/scripts/run-real-clients.sh        # needs Docker; results/real-clients/
```

`run-real-clients.sh` starts a fresh `s3gw` on `127.0.0.1:18443` (TCP and UDP) with the
segmenting relay on `127.0.0.1:18444` for each client, writes the test certificates and the
connector's test key to a temporary directory, and leaves in `results/real-clients/<client>/`:
`tcp-events.jsonl` (one routing decision per connection, with ClientHello size, records, reads,
key-share groups and peek time), `handler-notes.txt` (what the controller, HTTP, passthrough, h3 and
tunnel handlers served), `udp-budgets.json` and the client's own output. `summary.md` combines them.

Browsers ignore certificate errors in this run (Chromium `--ignore-certificate-errors`, and for
QUIC the SPKI allow-list; Firefox through Playwright's `ignoreHTTPSErrors`), because what is
measured is the routing, not the browsers' trust stores. rpmgr's own clients never skip
verification: the Go probe and the tests trust the generated test CAs.
