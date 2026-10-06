#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the S1 matrix: RTT × loss × system (direct, quic, h2) × workload (1 and 32 streams up and
# down, connection setup), REPS times, and appends one JSON line per measurement to OUT.
#
#   MODE=docker   three containers (client, gateway, connector + service) on two bridge networks;
#                 a local dry run that never decides the rule (D37). Needs Docker.
#
# netem shapes only the gateway↔connector link. "direct" is the baseline of
# docs/03-connections.md#targets-t: a plain TCP connection over that same link, opened from the
# gateway host to the service. Tunnel runs start on the client host and add the LAN hop
# client↔gateway.
#   MODE=testbed  the reference testbed (D30): three hosts reachable as `ssh s1-client`,
#                 `ssh s1-gateway`, `ssh s1-connector`, prepared with scripts/setup-host.sh.
#
# Usage: run-matrix.sh docker|testbed OUT.jsonl
# Environment: TESTBED (label), REPS, DUR, SETUP_DUR, RATE, RTTS, LOSSES; for testbed mode also
# GATEWAY_PUB, GATEWAY_PRIV, CONNECTOR_IP, CONNECTOR_MGMT, GATEWAY_IF, CONNECTOR_IF (README.md).
set -euo pipefail
trap 'echo "run-matrix.sh: failed at line $LINENO: $BASH_COMMAND" >&2' ERR

mode=${1:?usage: run-matrix.sh docker|testbed OUT.jsonl}
out=${2:?usage: run-matrix.sh docker|testbed OUT.jsonl}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPS=${REPS:-3}
DUR=${DUR:-10s}
SETUP_DUR=${SETUP_DUR:-5s}
RATE=${RATE:-1000}
RTTS=${RTTS:-"1 80"}
LOSSES=${LOSSES:-"0 1"}

case $mode in
  docker)
    TESTBED=${TESTBED:-docker-dryrun}
    GATEWAY_PUB=10.231.1.20
    GATEWAY_PRIV=10.231.2.20
    CONNECTOR_IP=10.231.2.30
    CONNECTOR_MGMT=10.231.1.30
    S1=/s1/s1
    CERTS=/s1/certs
    SUDO=""
    ;;
  testbed)
    TESTBED=${TESTBED:?set TESTBED, e.g. ref-x86, ref-arm64 or ref-pi5}
    : "${GATEWAY_PUB:?} ${GATEWAY_PRIV:?} ${CONNECTOR_IP:?} ${CONNECTOR_MGMT:?} ${GATEWAY_IF:?} ${CONNECTOR_IF:?}"
    S1=${S1:-/opt/s1/s1}
    CERTS=${CERTS:-/opt/s1/certs}
    SUDO=${SUDO-sudo}
    ;;
  *)
    echo "unknown mode $mode" >&2
    exit 2
    ;;
esac

# on ROLE CMD runs a command on a host; bg ROLE NAME CMD starts a background process.
on() {
  local role=$1
  shift
  if [[ $mode == docker ]]; then
    docker exec "rpmgr-s1-$role" sh -c "$*"
  else
    ssh "s1-$role" "$*"
  fi
}
bg() {
  local role=$1 name=$2
  shift 2
  if [[ $mode == docker ]]; then
    docker exec -d "rpmgr-s1-$role" sh -c "exec $* >/tmp/s1-$name.log 2>&1"
  else
    ssh "s1-$role" "nohup $* >/tmp/s1-$name.log 2>&1 </dev/null & echo \$! >/tmp/s1-$name.pid"
  fi
}
stop() {
  local role=$1 name=$2
  if [[ $mode == docker ]]; then
    # "[/]" keeps the pattern from matching this sh -c command line itself.
    docker exec "rpmgr-s1-$role" sh -c "pkill -f '[/]${S1#/} $name' || true"
  else
    ssh "s1-$role" "kill \$(cat /tmp/s1-$name.pid) 2>/dev/null || true"
  fi
  sleep 1
}

docker_up() {
  local work=$1
  docker build -q -t rpmgr-s1-tools - >/dev/null <<'EOF'
FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 procps iputils-ping >/dev/null \
 && rm -rf /var/lib/apt/lists/*
EOF
  docker network create --subnet 10.231.1.0/24 rpmgr-s1-pub >/dev/null
  docker network create --subnet 10.231.2.0/24 rpmgr-s1-priv >/dev/null
  local common=(-d --rm --cap-add NET_ADMIN -v "$work:/s1:ro" rpmgr-s1-tools sleep infinity)
  docker run --name rpmgr-s1-client --network rpmgr-s1-pub --ip 10.231.1.10 "${common[@]}" >/dev/null
  docker run --name rpmgr-s1-gateway --network rpmgr-s1-pub --ip "$GATEWAY_PUB" "${common[@]}" >/dev/null
  docker network connect --ip "$GATEWAY_PRIV" rpmgr-s1-priv rpmgr-s1-gateway
  docker run --name rpmgr-s1-connector --network rpmgr-s1-priv --ip "$CONNECTOR_IP" "${common[@]}" >/dev/null
  # The management address only carries the stats requests; data uses the shaped link.
  docker network connect --ip "$CONNECTOR_MGMT" rpmgr-s1-pub rpmgr-s1-connector
  GATEWAY_IF=$(on gateway "ip -o -4 addr show | awk '/$GATEWAY_PRIV/ {print \$2}'")
  CONNECTOR_IF=$(on connector "ip -o -4 addr show | awk '/$CONNECTOR_IP/ {print \$2}'")
}

docker_down() {
  docker rm -f rpmgr-s1-client rpmgr-s1-gateway rpmgr-s1-connector >/dev/null 2>&1 || true
  docker network rm rpmgr-s1-pub rpmgr-s1-priv >/dev/null 2>&1 || true
}

# netem RTT LOSS: half the RTT and the full loss rate on each direction of the
# gateway↔connector link. The queue limit is raised so that netem itself does not cap the
# bandwidth-delay product.
netem() {
  local half loss=$2
  half=$(awk -v r="$1" 'BEGIN { printf "%.3f", r / 2 }')
  on gateway "$SUDO tc qdisc replace dev $GATEWAY_IF root netem delay ${half}ms loss ${loss}% limit 1000000"
  on connector "$SUDO tc qdisc replace dev $CONNECTOR_IF root netem delay ${half}ms loss ${loss}% limit 1000000"
}

wait_route() {
  for _ in $(seq 1 50); do
    if on client "$S1 load -target $GATEWAY_PUB:9003 -workload setup -rate 10 -duration 200ms" \
      2>/dev/null | grep -q '"failures":0'; then
      return 0
    fi
    sleep 0.2
  done
  echo "route not ready" >&2
  return 1
}

measure() { # measure SYSTEM RTT LOSS REP
  local sys=$1 rtt=$2 loss=$3 rep=$4 from host stats=""
  local labels="-testbed $TESTBED -system $sys -rtt $rtt -loss $loss -rep $rep"
  if [[ $sys == direct ]]; then
    from=gateway
    host=$CONNECTOR_IP
    local up=7001 down=7002 echo=7003
  else
    from=client
    host=$GATEWAY_PUB
    local up=9001 down=9002 echo=9003
    stats="-stats gateway=$GATEWAY_PUB:7382,connector=$CONNECTOR_MGMT:7383"
  fi
  for streams in 1 32; do
    on "$from" "$S1 load $labels $stats -target $host:$up -workload up -streams $streams -duration $DUR" >>"$out"
    on "$from" "$S1 load $labels $stats -target $host:$down -workload down -streams $streams -duration $DUR" >>"$out"
  done
  on "$from" "$S1 load $labels -target $host:$echo -workload setup -rate $RATE -duration $SETUP_DUR" >>"$out"
}

work=""
main() {
  if [[ $mode == docker ]]; then
    work=$(mktemp -d)
    trap 'docker_down; rm "$work/s1" "$work"/certs/*.pem && rmdir "$work/certs" "$work"' EXIT
    docker_down
    CGO_ENABLED=0 go -C "$here" build -trimpath -o "$work/s1" ./cmd/s1
    "$work/s1" certs -dir "$work/certs"
    docker_up "$work"
  fi
  {
    echo "# $TESTBED $(date -u +%FT%TZ)"
    for role in client gateway connector; do
      echo "## $role: $(on "$role" 'uname -srm; nproc; cat /proc/sys/net/core/rmem_max /proc/sys/net/core/wmem_max 2>/dev/null | tr "\n" " "')"
    done
  } >>"${out%.jsonl}.meta.txt"

  bg connector service "$S1 service -sink :7001 -source :7002 -echo :7003"
  bg gateway gateway "$S1 gateway -certs $CERTS -tunnel :4443 -admin :7382 -route 9001=sink -route 9002=source -route 9003=echo"
  sleep 1
  for rtt in $RTTS; do
    for loss in $LOSSES; do
      netem "$rtt" "$loss"
      for rep in $(seq 1 "$REPS"); do
        measure direct "$rtt" "$loss" "$rep"
        for transport in quic h2; do
          bg connector connector "$S1 connector -certs $CERTS -gateway $GATEWAY_PRIV:4443 -transport $transport -admin :7383 -route sink=127.0.0.1:7001 -route source=127.0.0.1:7002 -route echo=127.0.0.1:7003"
          wait_route
          measure "$transport" "$rtt" "$loss" "$rep"
          stop connector connector
        done
        echo "done: RTT $rtt ms, loss $loss %, repetition $rep" >&2
      done
    done
  done
  for role in gateway connector; do
    on "$role" "grep -i -E 'buffer|warn|error' /tmp/s1-*.log | head -20 || true" >>"${out%.jsonl}.meta.txt"
  done
}

main
