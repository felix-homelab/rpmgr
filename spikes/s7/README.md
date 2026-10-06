# Spike S7: does the PKI behave as designed?

Throw-away prototype for spike S7 ([issue #11](https://github.com/felix-homelab/rpmgr/issues/11),
`docs/13-roadmap.md`, "Phase 0 — spikes"). Never merged; archived as the tag `spike/s7`. The result
is `docs/spikes/S7.md`.

## What it contains

| File | What |
|---|---|
| `identity.go` | SPIFFE IDs and the DNS SANs derived from them; strict SPIFFE parsing |
| `ca.go` | Root (P-256, 10 y, URI SAN `spiffe://<td>`), issuing intermediate (pathlen 0, critical name constraints on URI and DNS = `<td>`), 7-day leaves backdated 5 min, renewal with a new key, the `issued_certificates` registry (revocation, supersession), the deny-list |
| `tlsconfig.go` | The client and server `tls.Config` constructors (TLS 1.3 only, pinned root, `ServerName` of the expected peer) and `VerifyConnection` |
| `reauth.go` | One controller listener: SNI `controller.<td>` normal mutual TLS; SNI `reauth.controller.<td>` selected with `GetConfigForClient`, accepting certificates expired at most the grace period ago |
| `binding.go` | CSR bound to the TLS connection: RFC 9266 `tls-exporter` value in a CSR extension |
| `bundle.go` | Selecting the pinned root from an unauthenticated trust bundle |
| `*_test.go` | One test per criterion (below), with error cases |
| `mutate.sh` | Removes one control at a time from a copy of the module; each must make a test fail |

| Criterion (13, S7) | Test |
|---|---|
| 1 Issue and renew 7-day leaves with new keys | `TestLeafIssueAndRenew`, `TestProfilesAndControllerNames` |
| 2 URI and DNS name constraints enforced by Go's verifier | `TestNameConstraintsEnforced`, `TestNameConstraintsInHandshake` |
| 3 Per-identity DNS SANs, `ServerName` per peer, SPIFFE ID and deny-list | `TestServerNamePerPeer`, `TestSelectPinnedRoot` |
| 4 `VerifyConnection` on resumed sessions, revocation effective | `TestResumptionRunsVerifyConnection` |
| 5 `Reauth` verifier: grace period, revoked and superseded serials | `TestReauth` |
| 6 CSR bound to the TLS session via exported keying material | `TestCSRBinding` |

## Repeat the run

Requirements: Go 1.27.1 (the `toolchain` line selects it), Linux; no network, no Docker.

```sh
cd spikes/s7
go vet ./...
go test -race -count=1 -v ./... | tee results/go-test-v.txt
./mutate.sh | tee results/mutations.txt
```

All tests use a fake clock and loopback TCP; they take about 3 s.

## Results

- `results/go-test-v.txt`: verbose test output (51 tests and subtests pass).
- `results/mutations.txt`: all 8 mutations are detected.
- `results/environment.txt`: Go version and platform.
