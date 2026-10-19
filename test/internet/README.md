# The internet run: two cloud VMs

This sheet runs a release candidate over the real internet, the way a user deploys it: an
all-in-one at one place, a connector at another, and the internet between them. It checks the
functions, measures performance and runs a soak test with disturbances. It complements:

- the [real-world run](../realworld/README.md), whose hosts are containers on one machine, on
  networks without internet access;
- the [benchmark suite](../../bench/README.md), which runs on one host and imitates delay and loss
  with `tc netem`;
- the [VB-19 run sheet](../vb19/README.md), whose VM can be VM A here, when VB-19 runs first.

The run is not the reference testbed of [12](../../docs/12-testing-and-quality.md#benchmarks)
(D30, VB-20): it has two VMs, one pair of places and shared vCPUs, so its numbers are indications,
recorded with the place and time they were measured. It takes about five hours, of which three are
the soak test, which needs no one at the screen.

## The two VMs

| VM | Place | Runs |
|---|---|---|
| **A** | one data centre | the all-in-one (controller and gateway), the clients and the load generator |
| **B** | another data centre, 10 to 40 ms away | a connector, installed with the controller's install command, and the test services |

The clients sit next to the gateway, on A, and the internet lies between the gateway and the
connector: the link whose cost the targets of [03](../../docs/03-connections.md#targets-t) bound.
The direct baseline runs the same load from A to B's services without rpmgr.

- **The VMs:** a Linux of the supported list
  ([10](../../docs/10-operations.md#supported-platforms)), for example Debian 12, 2 vCPU and 2 to
  4 GB, with a public IPv4 address each and `curl`, `openssl` and `iptables` installed. Cloud
  providers bill such VMs by the hour; the run costs cents.
- **SSH:** a key of its own for the run, on both VMs, so that no everyday key lands on a throw-away
  host: `ssh-keygen -t ed25519 -f ~/.ssh/rpmgr-internet -N ''`.
- **Names:** `<name>` and `*.<name>`, A records to A, in a domain you control. A shared
  dynamic-DNS domain may hit Let's Encrypt's limit per registered domain.
- **Firewall:** A open on TCP 22, 80 and 443, UDP 443 and the port pool below, TCP and UDP. B
  needs TCP 22, and A's address on the test ports for the direct baseline: leave B without a
  provider firewall, as the run guards those ports with `iptables` on B. The run also closes ports
  on the VMs with `iptables` for its disturbances.
- **Certificates:** Let's Encrypt **production**, as a user's installation has them. A VM A that
  comes from VB-19 is still on staging: set the ACME directory back (step 1).
- **The workstation:** Go, to build the load tool, `jq`, and the release's `rpmgr` on the `PATH`
  as the command line.

Below, `v` is the version, `A` and `B` the addresses, and `ssh-a`, `ssh-b` run a command on them:

```sh
v=0.1.0-rc.9
name=perf.example.org
A=203.0.113.10 B=198.51.100.20
ssh-a() { ssh -i ~/.ssh/rpmgr-internet root@$A "$@"; }
ssh-b() { ssh -i ~/.ssh/rpmgr-internet root@$B "$@"; }
```

## 0. Prepare

On the workstation, in the repository at the release's tag, build the load tool for the VMs'
architecture (`arm64` for Arm VMs) and copy it:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bench ./bench/cmd/bench
scp -i ~/.ssh/rpmgr-internet bench root@$A:/usr/local/bin/ && scp -i ~/.ssh/rpmgr-internet bench root@$B:/usr/local/bin/
```

Record the path: `ssh-a ping -c 20 $B` (the round-trip time), `ssh-a uname -r`, `ssh-b uname -r`,
and the provider, the places and the VM types.

## 1. The all-in-one on A

Install it as the [quick start](../../docs/guide/quick-start.md) does: the global install script
of the release, which verifies it, then `rpmgr setup`:

```sh
ssh-a "curl -fsSLO https://github.com/felix-homelab/rpmgr/releases/download/v$v/install.sh && sh install.sh --no-setup"
ssh-a rpmgr setup --role all-in-one --public-url https://$name --acme-email you@example.org --yes
```

Then the first user from the link `setup` printed, an API token for one day with the scopes
`org.read`, `routes.write`, `connectors.write`, `infrastructure.write` and `instance.admin`, and
`rpmgr login` on the workstation ([API tokens](../../docs/guide/accounts/api-tokens-and-cli.md)).
A VM A that comes from VB-19 already has all three; point it back at Let's Encrypt production and
restart it, so that its certificates are trusted:

```sh
rpmgr update settings --instance --set acme_directory_url=https://acme-v02.api.letsencrypt.org/directory
ssh-a systemctl restart rpmgr-all-in-one
```

**Check:** `curl -fsS https://$name/readyz` from the workstation, without `-k`.

## 2. The connector and the services on B

The test services listen on loopback only, so that nothing but rpmgr reaches them, and a TLS
server for the `tls_passthrough` route beside them. Both are systemd units that start at boot, so
that they come back with B in the soak test:

```sh
ssh-b "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=tls.$name \
  -keyout /root/tls.key -out /root/tls.crt"
ssh-b 'cat >/etc/systemd/system/bench-service.service' <<'EOF'
[Service]
ExecStart=/usr/local/bin/bench service -name b -sink 127.0.0.1:7001 -source 127.0.0.1:7002 \
  -echo 127.0.0.1:7003 -who 127.0.0.1:7004 -udp 127.0.0.1:7003 -http 127.0.0.1:7080
[Install]
WantedBy=multi-user.target
EOF
ssh-b 'cat >/etc/systemd/system/tls-service.service' <<'EOF'
[Service]
ExecStart=/usr/bin/openssl s_server -accept 127.0.0.1:7443 -cert /root/tls.crt -key /root/tls.key -www
[Install]
WantedBy=multi-user.target
EOF
ssh-b systemctl enable --now bench-service tls-service
```

Then the connector, with the controller's install command
([Enroll a connector](../../docs/guide/connectors/enroll.md)). The token goes to B in a file, not
on a command line:

```sh
rpmgr create enrollment-token                                    # asks for a step-up
ssh-b "install -m 0600 /dev/null /root/token && cat >/root/token"  # paste the token, then Ctrl-D
rpmgr get --allow-target 127.0.0.1:7001-7443 install-command      # run it on B: see below
ssh-b rm /root/token
rpmgr list connector                                             # b online
```

Run the printed command on B as root, without its `sudo`, and with `--token-file /root/token`
after `install.sh`.

**Check:** `ssh-b rpmgr status` shows the control session and a data session over QUIC.

## 3. The routes

The domain, port pools, an access policy that admits only A and the workstation, so that the test
routes serve no one else, and one route of each type, the TCP and HTTP routes twice, pinned to each
transport. The clients on A connect from 127.0.0.1, which the policy admits too:

```sh
rpmgr create domain --fqdn $name --wildcard --method http
rpmgr verify domain <domain ID>                                   # until it says VERIFIED
rpmgr create port-pool --group default --protocol tcp --from 20000 --to 20099
rpmgr create port-pool --group default --protocol udp --from 20000 --to 20099
rpmgr create access-policy --name only-us --rule "allow:$A/32,127.0.0.1/32,<workstation>/32"
for t in quic h2; do
  rpmgr create route --tcp --name sink-$t --group default --port 0 --transport $t --policy only-us
  rpmgr create route --tcp --name source-$t --group default --port 0 --transport $t --policy only-us
  rpmgr create route --tcp --name echo-$t --group default --port 0 --transport $t --policy only-us
  rpmgr create route --http --name web-$t --group default --hostname web-$t.$name --tls-mode acme \
    --transport $t --policy only-us
done
rpmgr create route --udp --name udp --group default --port 0 --policy only-us
rpmgr create route --tcp-udp --name both --group default --port 0 --policy only-us
rpmgr create route --tcp --name hold --group default --port 0 --policy only-us
rpmgr create route --tls-passthrough --name tls --group default --hostname tls.$name --policy only-us
```

Each route gets its target on `b`: `sink-*` 127.0.0.1:7001, `source-*` 7002, `echo-*`, `udp`,
`both` and `hold` 7003, `web-*` 7080, `tls` 7443 (`rpmgr create route-target --route <route>
--connector b --address 127.0.0.1:<port> --wait 30s`). Then the public ports the routes got, as
`$P_<route>` with `_` for `-`:

```sh
port() { rpmgr list -o json route | jq -r ".[] | select(.name == \"$1\") | (.tcp // .udp // .tcpUdp).port"; }
for r in sink-quic sink-h2 source-quic source-h2 echo-quic echo-h2 udp both hold; do
  declare "P_${r//-/_}=$(port $r)"
done
```

**Check (functions):**
- `rpmgr list route` shows every route **ready**;
- from the workstation, `curl -fsS https://web-quic.$name/` answers with a publicly trusted
  certificate, and from any other address the routes refuse: the access policy;
- on A, `bench load -workload setup -duration 5s` and `-workload udp -duration 5s` against
  `127.0.0.1:$P_both`: the `tcp_udp` route on both protocols;
- on A, `curl -sk --resolve tls.$name:443:127.0.0.1 https://tls.$name/` shows `s_server`'s page:
  the TLS passed through to B;
- `rpmgr update route --maintenance web-h2` shows the maintenance page, `--maintenance=false`
  ends it;
- `ssh-b rpmgr policy deny-target 127.0.0.1:7003` takes `echo-*`, `udp`, `both` and `hold` out on
  the connector, `ssh-b rpmgr policy remove-deny-target 127.0.0.1:7003` brings them back.

## 4. Performance

On A, each measurement once direct, once over each transport, three times, into one file. The
direct runs need B's services on its public address, for A alone and for this step only:

```sh
ssh-b "iptables -I INPUT -p tcp --dport 7001:7080 ! -s $A -j DROP; iptables -I INPUT -p udp --dport 7003 ! -s $A -j DROP"
ssh-b "systemctl stop bench-service && systemd-run --unit=bench-direct /usr/local/bin/bench service -name b -udp :7003"
```

| Workload | Direct, on A | Through rpmgr, on A |
|---|---|---|
| Throughput up, 1 and 32 streams | `bench load -workload up -streams 1 -target $B:7001` | `-target 127.0.0.1:$P_sink_quic`, `$P_sink_h2` |
| Throughput down, 1 and 32 streams | `-workload down -target $B:7002` | `$P_source_quic`, `$P_source_h2` |
| Connection setup, p50 and p99 | `-workload setup -rate 200 -target $B:7003` | `$P_echo_quic`, `$P_echo_h2` |
| HTTP requests | — | `-workload http -url https://web-quic.$name/ -target 127.0.0.1:443 -ca /etc/ssl/certs/ca-certificates.crt`, and `web-h2` |
| UDP, 1 200 and 1 400 bytes | `-workload udp -size 1200 -target $B:7003` | `$P_udp` |

Each command takes `-duration 30s -testbed internet -system direct|quic|h2 -rtt <ms> -rep 1|2|3`,
with the round-trip time of step 0, and prints one JSON line: append it with `>>results.jsonl`.
Sample the processes' CPU and memory before and after each workload, on A and on B:

```sh
bench metrics -url http://127.0.0.1:7381/metrics \
  -names process_cpu_seconds_total,process_resident_memory_bytes,go_goroutines,process_open_fds   # A
bench metrics -url http://127.0.0.1:7383/metrics -names …                                         # B
```

Then the tables, with the targets of 03: `bench summarize -in results.jsonl`. Put the services
back on loopback, `ssh-b "systemctl stop bench-direct && systemctl start bench-service"`, and drop
B's two rules (`iptables -D` with the same arguments).

## 5. Stability: three hours with disturbances

The workstation drives twelve cycles of 15 minutes. Each cycle begins with a disturbance, waits 3
minutes for the recovery, then holds 64 connections on `hold` for 10 minutes while it changes an
unrelated route once a minute. Held connections must survive configuration changes; a lost data
session may end them, which is why each cycle holds new ones after the recovery. Meanwhile a
sampler on A measures HTTP requests and connection setups twice a minute, with the processes'
metrics, each line with its time. It is a systemd unit that starts at boot, so that it comes back
with A:

```sh
ssh-a 'cat >/root/sample.sh' <<EOF
#!/bin/bash
ca=/etc/ssl/certs/ca-certificates.crt
while :; do
  echo "\$(date -u +%T) \$(bench load -system soak -workload http -url https://web-quic.$name/ -target 127.0.0.1:443 -ca \$ca -workers 8 -duration 20s 2>&1)"
  echo "\$(date -u +%T) \$(bench load -system soak -workload setup -rate 50 -target 127.0.0.1:$P_echo_quic -duration 10s 2>&1)"
  echo "\$(date -u +%T) \$(bench metrics -url http://127.0.0.1:7381/metrics -names process_resident_memory_bytes,go_goroutines,process_open_fds 2>&1)"
  sleep 30
done >>/root/soak.log
EOF
ssh-a 'cat >/etc/systemd/system/soak-sample.service' <<'EOF'
[Service]
ExecStart=/bin/bash /root/sample.sh
[Install]
WantedBy=multi-user.target
EOF
ssh-a systemctl enable --now soak-sample
```

The disturbances, in turn, so that the list runs twice:

| # | Disturbance | Expected |
|---|---|---|
| 1 | UDP from B to A blocked for 2 minutes: `ssh-b iptables -I OUTPUT -d $A -p udp --dport 443 -j DROP`, then `-D` | the routes pinned to `quic` are not ready, `transport_unavailable`, until UDP passes again; the `auto` routes move to TLS and HTTP/2, and back to QUIC at a later probe ([03](../../docs/03-connections.md#transports-and-fallback)) |
| 2 | `ssh-b systemctl restart rpmgr-connector` | the connector reconnects |
| 3 | `ssh-a systemctl restart rpmgr-all-in-one` | the agents reconnect; the gateway serves again |
| 4 | `ssh-b reboot` | the connector and the test services come back with B |
| 5 | `ssh-a reboot` | everything comes back with A, the sampler too |
| 6 | TCP and UDP 443 from B to A blocked for 1 minute: `ssh-a iptables -I INPUT -s $B -p tcp --dport 443 -j REJECT` and the same for UDP, then `-D` | no session at all, then recovery |

One cycle, from the workstation, with `d` the disturbance's number:

```sh
echo "$(date -u +%T) start $d" >>soak-events.log   # then the disturbance of the table
echo "$(date -u +%T) end $d" >>soak-events.log     # once it is over: unblocked, or the VM up again
sleep 180
ssh-a bench load -system soak -workload hold -conns 64 -duration 10m -target 127.0.0.1:$P_hold >>hold.jsonl &
for m in $(seq 10); do
  rpmgr update route --description "$(date -u +%T)" sink-quic >/dev/null
  echo "$(date -u +%T) $(ssh-b bench metrics -url http://127.0.0.1:7383/metrics \
    -names process_resident_memory_bytes,go_goroutines,process_open_fds)" >>metrics-b.log
  sleep 60
done
wait
```

**Pass:**
- `hold.jsonl`: no connection lost in any cycle.
- `/root/soak.log` on A: failures only from a disturbance's start until 3 minutes after its end, in
  `soak-events.log`; the first sample without failures after the end is the recovery time, within
  the reconnect times of [03](../../docs/03-connections.md#timeouts-keepalive-and-backoff).
- Memory, goroutines and open files show no growth across the run: compare A's and B's samples at
  the end of each cycle, where every restart is minutes behind.
- The journals of both VMs hold no `ERROR`, and every `WARN` belongs to a disturbance:
  `journalctl -u 'rpmgr-*' -p warning --since <start>`.

## Record

Collect into `test/internet/results/<date>.md`:
- the environment of step 0 and `rpmgr version` on A and B;
- the checks of steps 1 to 3;
- `bench summarize`'s tables and the CPU and memory per workload;
- the soak: failures per hour outside disturbances, the reconnect time per disturbance, held
  connections lost, memory and goroutines at the start and end of each hour, and the journals'
  warnings and errors by message;
- anything that failed, with its log lines.

Open a pull request `docs: record the internet run of <version>` (labels `type:docs`, `phase:p1`,
`no-changelog`) with the file. A failed function or soak criterion is a defect of the release
candidate ([RELEASING](../../RELEASING.md#release-process)); a missed target of 03 is recorded, as
[12](../../docs/12-testing-and-quality.md#benchmarks) asks.

## Clean up

- **rpmgr:** revoke the API token and the enrollment token if unused.
- **The VMs:** destroy both; they hold nothing but test data and certificates for `<name>`.
- **DNS:** remove the records of `<name>`.
- **SSH:** delete `~/.ssh/rpmgr-internet` and its `.pub`.
