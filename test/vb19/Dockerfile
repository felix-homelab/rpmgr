# SPDX-License-Identifier: Apache-2.0
#
# The host of rehearse.sh: Debian with the tools of the VB-19 run sheet (README.md), OpenSSL and
# curl, plus jq for the rehearsal's checks and iptables, which stands in for the cloud firewall.
# rehearse.sh mounts the binaries. Base image pinned by digest (CONTRIBUTING).
FROM mirror.gcr.io/library/debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl iptables jq openssl procps \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
