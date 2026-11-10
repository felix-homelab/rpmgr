# SPDX-License-Identifier: Apache-2.0
#
# The host of rehearse.sh: Debian with the tools of the VB-19 run sheet (README.md), OpenSSL and
# curl, plus jq for the rehearsal's checks and iptables, which stands in for the cloud firewall.
# rehearse.sh mounts the binaries. Base image pinned by digest (CONTRIBUTING).
FROM mirror.gcr.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl iptables jq openssl procps \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
