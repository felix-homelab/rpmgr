# SPDX-License-Identifier: Apache-2.0
#
# The image of every end-to-end node: the rpmgrtest build of rpmgr and e2eclient, which the test
# builds into bin/ first, and iproute2 for tc netem. Base image pinned by digest (CONTRIBUTING).
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 procps \
    && rm -rf /var/lib/apt/lists/*
COPY bin/rpmgr bin/e2eclient /usr/local/bin/
CMD ["sleep", "infinity"]
