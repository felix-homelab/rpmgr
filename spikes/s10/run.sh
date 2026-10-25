#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs one scenario of spike S10 on a systemd host in a container (README.md).
# Usage: run.sh <ubuntu2204|debian13> <A|B|C|D|E|F>
#   A  relay mode (S-2/S-3 default): one hand-off under load, 4 QUIC connectors, bulk streams
#      before, during and after the drain
#   B  pause mode: two hand-offs in a row (the second during the first's drain), 1 connector
#   C  pause mode: hand-offs that must fail, under load: binary writable, unexpected descriptor,
#      wrong descriptor, new process never ready; then a good one
#   D  counterfactual: the new process reads the UDP sockets at once, no relay (-mode norelay)
#   E  baseline: quic-go on the plain UDP socket (its fast path), no hand-off, bulk streams only
#   F  pause mode (S-2/S-3 fallback): one hand-off under load, 3 connectors on auto and one
#      pinned to QUIC, bulk streams before and after
set -euo pipefail
distro=$1 scenario=$2
here=$(cd "$(dirname "$0")" && pwd)
out=$here/results/$distro-$scenario
rm -rf "$out" && mkdir -p "$out"
build=$(mktemp -d)
trap 'rm -rf "$build"; docker rm -f s10gw-$distro s10ld-$distro >/dev/null 2>&1 || true' EXIT

(cd "$here" && CGO_ENABLED=0 go build -trimpath -o "$build/s10" .)
cp "$here/docker/s10.service" "$here/docker/Dockerfile.$distro" "$build/"
case $scenario in
  E) flags="-fastpath" ;;
  D) flags="-mode norelay" ;;
  B | C | F) flags="-mode pause" ;;
  *) flags="" ;;
esac
sed -i "s|ExecStart=/usr/local/bin/s10 serve |ExecStart=/usr/local/bin/s10 serve $flags |" "$build/s10.service"
docker build -q -t "s10-$distro" -f "$build/Dockerfile.$distro" "$build" >/dev/null
docker network inspect s10net >/dev/null 2>&1 || docker network create s10net >/dev/null

docker run -d --name "s10gw-$distro" --network s10net --privileged --cgroupns=host \
  --tmpfs /run:rw,size=64m --tmpfs /tmp:rw,size=64m "s10-$distro" /sbin/init >/dev/null
gw() { docker exec "s10gw-$distro" sh -c "$1"; }
for _ in $(seq 100); do
  s=$(gw 'systemctl is-system-running 2>/dev/null || true')
  [[ $s == running || $s == degraded ]] && break
  sleep 0.2
done
gw 'systemctl --version | head -1; uname -r' | tee "$out/host.txt"
for _ in $(seq 100); do gw 'test -s /var/lib/s10/tls/ca.pem' && break; sleep 0.1; done
mkdir -p "$out/tls" && docker cp "s10gw-$distro:/var/lib/s10/tls/ca.pem" "$out/tls/ca.pem" >/dev/null
# The unit's state, sampled every 100 ms.
docker exec -d "s10gw-$distro" sh -c 'while true; do echo "$(date +%s.%N) $(systemctl show -p MainPID -p ActiveState -p SubState -p NRestarts --value s10 | tr "\n" " ")"; sleep 0.1; done > /var/tmp/states.txt'

load() { # dur, extra flags
  docker run -d --name "s10ld-$distro" --network s10net -v "$out:/out" \
    --sysctl net.ipv4.ip_local_port_range="1024 65535" --sysctl net.ipv4.tcp_tw_reuse=1 \
    --entrypoint /usr/local/bin/s10 "s10-$distro" load -tcp "s10gw-$distro:9000" -udp "s10gw-$distro:9001" \
    -quic "s10gw-$distro:9002" -tunnel "s10gw-$distro:9003" -tls /out/tls -dur "$1" -out /out/load.json "${@:2}" >/dev/null
}
reload() { # label
  echo "$(date +%s.%N) reload $1" >>"$out/reload.txt"
  gw 'systemctl reload s10 2>&1; echo "exit $?"' >>"$out/reload.txt" 2>&1 || true
  echo "$(date +%s.%N) reload $1 returned" >>"$out/reload.txt"
}
at() { sleep "$1"; }

case $scenario in
A)
  load 75s -connectors 4 -rate 500 -long 20 -flows 10 -bulk-at 4s,6s,8s,10s,12s,17s,18.5s,20s,21.5s,23s,24.5s,26s,27.5s,29s,30.5s,32s,40s,42s,44s,46s,48s,50s,52s,54s,56s,58s
  at 15; reload first
  ;;
B)
  load 60s -connectors 1 -transport auto -rate 500 -long 20 -flows 10
  at 15; reload first
  at 8; reload second
  ;;
C)
  load 90s -connectors 2 -transport auto -rate 500 -long 10 -flows 5
  at 10; gw 'chmod g+w /usr/local/bin/s10'; reload binary-group-writable
  gw 'chmod g-w /usr/local/bin/s10'
  at 5; gw 'echo extra > /run/s10/inject'; reload unexpected-descriptor
  at 25; gw 'echo wrong > /run/s10/inject'; reload wrong-descriptor
  at 5; gw 'echo notready > /run/s10/inject'; reload never-ready
  at 10; reload good
  ;;
D)
  load 50s -connectors 4 -rate 500 -long 20 -flows 10
  at 15; reload first
  ;;
F)
  load 75s -connectors 4 -transport auto,auto,auto,quic -rate 500 -long 20 -flows 10 -bulk-at 4s,6s,8s,10s,12s,40s,42s,44s,46s,48s,50s,52s,54s,56s,58s
  at 15; reload first
  ;;
E)
  load 40s -connectors 1 -rate 50 -long 1 -flows 1 -bulk-at 4s,6s,8s,10s,12s,14s,16s,18s,20s,22s,24s,26s,28s,30s,32s,34s
  ;;
esac
docker wait "s10ld-$distro" >/dev/null
docker logs "s10ld-$distro" >"$out/load.txt" 2>&1
gw 'journalctl -u s10 --no-pager -o short-precise' >"$out/journal.txt" 2>&1 || true
# A crash of the new main process, which systemd did not start: does Restart= still see it?
pid=$(gw 'systemctl show -p MainPID --value s10')
gw "kill -9 $pid"; sleep 4
echo "killed main pid $pid; now: $(gw 'systemctl show -p MainPID -p ActiveState -p SubState -p NRestarts --value s10 | tr "\n" " "')" | tee "$out/crash.txt"
docker cp "s10gw-$distro:/var/tmp/states.txt" "$out/states.txt" >/dev/null
rm -rf "$out/tls"
echo "results in $out"
