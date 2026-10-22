# SPDX-License-Identifier: Apache-2.0
#
# The host of rehearse.sh: Debian with the tools of the VB-19 run sheet (README.md), OpenSSL and
# curl, plus jq for the rehearsal's checks and iptables, which stands in for the cloud firewall.
# rehearse.sh mounts the binaries. Base image pinned by digest (CONTRIBUTING).
FROM mirror.gcr.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl iptables jq openssl procps \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
