# SPDX-License-Identifier: Apache-2.0
#
# The image of the hand-off test's one container (test/handoff): Debian with procps for pgrep and
# pkill. The test copies the rpmgr builds and e2eclient into it and runs every process as root,
# which the hand-off's binary check expects to own the binary. Base image pinned by digest
# (CONTRIBUTING).
FROM mirror.gcr.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
