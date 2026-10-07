# Spike S6: certmagic on the controller, challenges answered by gateways

Throw-away code for spike S6 (issue #10). Question, method, pass criteria and the pre-agreed rule:
[docs/13-roadmap.md, "Phase 0 — spikes"](../../docs/13-roadmap.md#phase-0--spikes). The result
is written down in [docs/spikes/S6.md](../../docs/spikes/S6.md). This directory lives only on
the branch `tmp/s6-acme-certmagic` and, afterwards, the tag `spike/s6`.

## What is here

| Path | What it is |
|---|---|
| `internal/dbstore` | `certmagic.Storage` on SQLite (`acme_storage` table) with locks as database leases (`leases` table: holder, expiry, fencing token), `TryLocker` and `LockLeaseRenewer` |
| `internal/controlplane` | `SyncStorage`: a storage decorator that pushes HTTP-01/TLS-ALPN-01 challenges to every gateway of the name and waits for all acknowledgements before certmagic lets the CA validate; simulated control sessions (in-process and over HTTP) |
| `internal/gateway` | The gateway: answers HTTP-01 and TLS-ALPN-01 only from pushed challenges, serves pushed certificates; does not import certmagic |
| `internal/controller` | Two certmagic configurations on one storage and one cache, chosen per name: DNS-01 for managed zones, HTTP-01/TLS-ALPN-01 otherwise |
| `internal/cfclient`, `internal/dnsadapter` | Minimal Cloudflare client and the libdns `RecordAppender`/`RecordDeleter` adapter over it (marker comment, foreign records untouched) |
| `internal/fakecf`, `internal/dnsserver` | Fake Cloudflare API (zones with paging, TXT records, bearer auth) and an authoritative DNS server that answers its records |
| `internal/pebblehost` | Pebble v2.10.1 in-process, counting new orders per name and challenge requests |
| `s6_test.go`, `replicas_test.go` | End-to-end tests against Pebble; the two-replica tests run the controllers as two OS processes |
| `cmd/s6run` | `testbed`, `gateway` and `controller` commands for the external run and its rehearsal |
| `rehearse.sh` | Runs the external run's commands locally (Pebble and the fake API instead of Let's Encrypt staging and Cloudflare) and checks the outcome |
| `results/` | Raw outputs of the runs below |

## Versions

Go 1.27.1 (`toolchain` in `go.mod`; `go 1.26.0` is required by the dependencies), certmagic
v0.25.6, acmez v3.1.7, libdns v1.1.1, Pebble v2.10.1, modernc.org/sqlite v1.60.1,
miekg/dns v1.1.73.

## Repeating the local runs

From this directory (`spikes/s6`), with Go 1.27.1 on `PATH`:

```sh
go vet ./...
go test -race -count=1 -v ./...            # results/test-race.txt  (26 tests)
go test -count=5 -v .                      # results/test-count5.txt (end-to-end, 5 rounds)
./rehearse.sh results/rehearsal.txt        # separate processes; repeated 30 times, all passed
```

`S6_CERTMAGIC_LOG=1` prints certmagic's log (in the replica processes too); `S6_PEBBLE_LOG=1`
prints Pebble's. Pebble runs with `PEBBLE_VA_NOSLEEP=1`, `PEBBLE_WFE_NONCEREJECT=0` and
`PEBBLE_AUTHZREUSE=0` (every renewal validates again); `PEBBLE_VA_ALWAYS_VALID` is never set, so
every validation is real: Pebble's VA resolves the name through `internal/dnsserver` and connects
to the gateway's ports, or reads the TXT record the adapter created at the fake API.

One test uses `InsecureSkipVerify`: `gateway_test.go` plays the CA's TLS-ALPN-01 validator, which
by RFC 8737 checks the `acmeIdentifier` extension of a self-signed certificate instead of a chain.
No other code skips verification.

## External run (maintainer, D37)

Two parts of S6 need resources outside a development machine: Let's Encrypt **staging** and a
**real Cloudflare zone**. Run them on a throw-away Linux VM with a public IPv4 address. The
default ACME directory of `s6run` is staging; never point it at production.

### Prepare

1. **VM**: Linux, public IPv4, TCP 80 and 443 reachable from the internet (Let's Encrypt
   validates from several places). Go 1.27.1, `libcap2-bin` (for `setcap`).
2. **Zone**: a domain you own as an **active, full** Cloudflare zone, called `<zone>` below. Use
   a zone without mail or other production records (04, "Threat model").
3. **API token** (Cloudflare dashboard → My Profile → API Tokens → Create Custom Token):
   permissions *Zone → Zone → Read* and *Zone → DNS → Edit*; zone resources: only `<zone>`;
   client IP filtering: the VM's public IP; TTL: end date tomorrow. On the VM, store it in a
   private file without putting it on a command line or in the shell history:

   ```sh
   mkdir -p ~/s6 && install -m 600 /dev/null ~/s6/cf-token && nano ~/s6/cf-token   # paste, save
   install -m 600 /dev/null ~/s6/control-token && head -c 24 /dev/urandom | base64 >~/s6/control-token
   ```
4. **DNS records** in `<zone>`: `http.<zone>` → A record to the VM's IP, **DNS only** (grey
   cloud). Nothing for `dns.<zone>`: names below it use DNS-01, the run creates and removes their
   TXT records. (`--dns01-zone dns.<zone>` makes the controller treat that subtree as the managed
   zone; certmagic still finds the Cloudflare zone `<zone>` by its SOA.)
5. **Build** on the VM, from a checkout of `spike/s6`:

   ```sh
   go -C spikes/s6 build -o ~/s6/s6run ./cmd/s6run
   sudo setcap cap_net_bind_service=+ep ~/s6/s6run    # bind 80/443 without root
   ```

### Run

```sh
cd ~/s6
./s6run gateway --http :80 --tls :443 --control 127.0.0.1:9180 \
  --control-token-file control-token >gateway.out 2>gateway.err &
gw=$!
names="dns.<zone>,*.dns.<zone>,http.<zone>"
common="--db controller.db --email <your e-mail> --cf-token-file cf-token --dns01-zone dns.<zone>
  --gateway-control http://127.0.0.1:9180 --control-token-file control-token --names $names"
./s6run controller --id a --force-renew $common >a.out 2>a.err &   # two replicas at once
./s6run controller --id b $common >b.out 2>b.err &
wait %2 %3; kill $gw; wait
```

Then repeat the TLS-ALPN-01 path alone: delete `controller.db`, start the gateway again, and run
replica `a` with `--names http.<zone> --force-renew --disable-http01`.

### Record

Into `docs/spikes/S6.md`, section "External run":

- per name, from `a.out`/`b.out`: the `certificate` and `renewed_certificate` events (serial,
  issuer — a "(STAGING)" CA —, `not_after`, `dns01`), and that exactly one replica reported the
  first issuance (`obtained` with `renewal:false`); `lock_waits` of both replicas;
- from `gateway.out`: `http01_answered` and `tlsalpn01_answered` (the second run: TLS-ALPN-01
  only);
- from `a.err`: the time between "presenting" and "validated" for the DNS-01 names (real
  propagation, with certmagic's default 2-minute propagation check);
- in the Cloudflare dashboard: no `_acme-challenge` TXT record left in `<zone>`;
- anything that failed, with the log lines.

Afterwards delete the token at Cloudflare, delete `http.<zone>`, and destroy the VM.

### Apply the rule

If every check passed, the rule (D17) keeps **certmagic on the controller**; in the same PR set
S6 to *Done* and replace the remaining `[V S6]` tags listed in S6.md, "Not verified". If staging
or the real zone shows that gateway-answered challenges cannot work with certmagic, the rule
selects **acmez with rpmgr's own solvers and storage**, and the documents listed in S6.md change
accordingly.
