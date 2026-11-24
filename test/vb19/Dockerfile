# SPDX-License-Identifier: Apache-2.0
#
# The host of rehearse.sh: Debian with the tools of the VB-19 run sheet (README.md), OpenSSL and
# curl, plus jq for the rehearsal's checks and iptables, which stands in for the cloud firewall.
# rehearse.sh mounts the binaries. Base image pinned by digest (CONTRIBUTING).
FROM mirror.gcr.io/library/debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl iptables jq openssl procps \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
