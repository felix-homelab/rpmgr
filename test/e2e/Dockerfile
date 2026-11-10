# SPDX-License-Identifier: Apache-2.0
#
# The image of every end-to-end node: the rpmgrtest build of rpmgr and e2eclient, which the test
# builds into bin/ first, iproute2 for tc netem and iptables to blackhole UDP. Base image pinned
# by digest (CONTRIBUTING).
FROM mirror.gcr.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables procps \
    && rm -rf /var/lib/apt/lists/*
COPY bin/rpmgr bin/e2eclient /usr/local/bin/
CMD ["sleep", "infinity"]
