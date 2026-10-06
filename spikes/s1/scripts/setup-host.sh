#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Prepares one host of the S1 reference testbed (docs/12-testing-and-quality.md#benchmarks).
# Run as root on each VM after copying the s1 binary and the certificate directory to /opt/s1.
#
# Usage: setup-host.sh client|gateway|connector
set -euo pipefail

role=${1:?usage: setup-host.sh client|gateway|connector}

apt-get update -qq
apt-get install -y -qq iproute2 procps ethtool >/dev/null

# Host tuning applied by the installer (docs/03-connections.md#host-tuning-applied-by-the-installer):
# UDP socket buffers of at least 7 MiB. No BBR: the benchmark uses each distribution's default
# congestion control, which is recorded.
sysctl -q -w net.core.rmem_max=7340032 net.core.wmem_max=7340032

case $role in
  client | gateway | connector) ;;
  *)
    echo "unknown role $role" >&2
    exit 2
    ;;
esac

echo "role=$role kernel=$(uname -r) arch=$(uname -m) cpus=$(nproc)" \
  "cc=$(sysctl -n net.ipv4.tcp_congestion_control)" \
  "rmem_max=$(sysctl -n net.core.rmem_max) wmem_max=$(sysctl -n net.core.wmem_max)"
for dev in $(ip -o link show | awk -F': ' '$2 != "lo" {print $2}'); do
  echo "$dev: $(ethtool -k "$dev" 2>/dev/null | grep -E 'generic-(segmentation|receive)-offload' | tr '\n' ' ')"
done
