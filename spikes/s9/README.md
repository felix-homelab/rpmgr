# Spike S9: how do controller replicas share session ownership?

Throw-away prototype for spike S9 ([issue #595](https://github.com/felix-homelab/rpmgr/issues/595),
`docs/13-roadmap.md`, "Phase 0 — spikes", row S9). Never merged; archived as the tag `spike/s9`.
The result is `docs/spikes/S9.md`.

## What it contains

One binary, `s9`, with a subcommand per question. Replicas always run as separate processes
(`s9 replica`), started by the question's driver, which simulates the agents in its own process.

| File | What |
|---|---|
| `db.go` | The spike's schema (the revision, each agent's snapshot revision, the session registry `agent_sessions`, `controller_nodes`) and the two kinds of push: a revision (broadcast on `s9_rev`) and a change of one agent's snapshot (targeted, on the channel of the replica that holds the agent, which is read `FOR SHARE`) |
| `replica.go` | A replica: agent listener, a dedicated LISTEN connection that reconnects and then resyncs, the revision check (`-poll`), registration with the next `session_epoch` and a `supersede` signal to the replica that held the agent before, the admission limit of 03 |
| `c2c.go` | Controller-to-controller mutual TLS: a test CA, node certificates with a controller SPIFFE ID and both EKUs, an HTTP/2 listener that accepts only controller IDs, forwarding of `ProbeTarget` |
| `driver.go`, `proto.go` | Starting replicas, the simulated agents (rpmgr's reconnect backoff of 03: full jitter, base 0.5 s, factor 2, cap 30 s, `retry_after` honoured), latency collection |
| `facts.go` | Re-checks of the LISTEN/NOTIFY facts against the pinned PostgreSQL (D39) |
| `q1.go` … `q5.go` | One driver per question |
| `s3sink.go`, `q4.go` | The revocation-log sink on S3 with rpmgr's filesystem algorithm (`internal/revlog/sink.go`, used as it is for the filesystem runs) and `If-None-Match: *`; the shipper processes; the S3 facts |

The module imports `github.com/felix-homelab/rpmgr/internal/revlog` through a `replace` of the
repository root, so the filesystem sink under test is the product's.

## Versions (pinned 2026-10-19, D39)

- Go 1.27.2 (the `toolchain` line), linux/amd64, WSL2 kernel 6.18 on the maintainer's workstation.
- PostgreSQL 18.6: `mirror.gcr.io/library/postgres@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336`.
- pgx v5.11.0.
- MinIO `RELEASE.2025-10-15T17-29-55Z` (commit `9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`),
  built from source: the `minio/minio` repository is archived, its last release has no image on
  Docker Hub, Quay or `mirror.gcr.io` any more, and `dl.min.io` answers 410 for its binaries
  (checked 2026-10-19). Built with `mirror.gcr.io/library/golang:1.24` and run in
  `mirror.gcr.io/library/debian:13-slim`.
- aws-sdk-go-v2 `service/s3` v1.114.3 (a spike convenience; the product's client is its own, R22).

## Repeat the runs

```sh
# PostgreSQL 18.6
docker run -d --name s9-pg -p 127.0.0.1:55419:5432 -e POSTGRES_PASSWORD=s9 \
  mirror.gcr.io/library/postgres@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336 \
  -c max_connections=300

# MinIO from its last release's source, built and run in containers
git clone --depth 1 --branch RELEASE.2025-10-15T17-29-55Z https://github.com/minio/minio /tmp/minio-src
mkdir -p /tmp/minio-out
docker run --rm -v /tmp/minio-src:/src:ro -v /tmp/minio-out:/out -e CGO_ENABLED=0 -e GOTOOLCHAIN=local \
  -e GOFLAGS=-buildvcs=false -w /src mirror.gcr.io/library/golang:1.24 go build -trimpath -o /out/minio .
docker run -d --name s9-minio -p 127.0.0.1:19000:9000 -e MINIO_ROOT_USER=s9admin \
  -e MINIO_ROOT_PASSWORD=s9-spike-password -v /tmp/minio-out/minio:/usr/local/bin/minio:ro \
  mirror.gcr.io/library/debian:13-slim minio server /data

cd spikes/s9
go vet ./...
go build -o s9 .
./s9 facts                # LISTEN/NOTIFY facts                 → results/facts-postgres.txt
./s9 s3-facts             # conditional create on MinIO         → results/facts-s3.txt
./s9 q1 -mode main        # Q1 latency and LISTEN drop          → results/q1-main.txt
./s9 q1 -mode noresync    # Q1 negative control                 → results/q1-noresync.txt
./s9 q1 -mode poll        # Q1 with the revision check only     → results/q1-poll.txt
./s9 q2                   # Q2 storm, NOTIFY only               → results/q2-poll0.txt
./s9 q2 -poll 1s          # Q2 storm with the revision check    → results/q2-poll1s.txt (and -rerun.txt)
./s9 q3                   # Q3 c2c forwarding                   → results/q3.txt
./s9 q4-fs                # Q4 filesystem sink, tmpfs and disk  → results/q4-fs.txt
./s9 q4-s3                # Q4 S3 sink and negative control     → results/q4-s3.txt
./s9 q5                   # Q5 SIGKILL of a replica             → results/q5.txt
```

Each driver resets the spike's tables. Replica logs go to `results/logs/`. Runs take between
20 s and about 3 min each; nothing else should load the machine while Q1, Q2 and Q5 measure.

**Data connections across a controller SIGKILL (Q5)** run with the product, not the spike: data
sessions go from connectors to gateways and never pass a controller. The nightly chaos cell of the
end-to-end suite holds a connection through a gateway and a connector across each "soft" event, one
of which is the controller killed with SIGKILL or SIGTERM, and checks every byte of a load
generator. Seed 2975 makes five of its first eight events controller restarts, all of them with
SIGKILL (`go run ./chaosseed` replays the test's random draws to find such a seed):

```sh
cd test/e2e
E2E_FULL=1 E2E_CHAOS_SEED=2975 E2E_CHAOS_DURATION=4m go test -tags e2e -count=1 -timeout 40m -run 'TestChaos$' -v .
```

Its output is `results/q5-e2e-chaos.txt`.

## Results

See `results/` and `docs/spikes/S9.md`. `results/environment.txt` records the machine.
