# SPDX-License-Identifier: Apache-2.0
#
# The image of every end-to-end node: the rpmgrtest build of rpmgr and e2eclient, which the test
# builds into bin/ first, iproute2 for tc netem and iptables to blackhole UDP. Base image pinned
# by digest (CONTRIBUTING).
FROM mirror.gcr.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables procps \
    && rm -rf /var/lib/apt/lists/*
COPY bin/rpmgr bin/e2eclient /usr/local/bin/
CMD ["sleep", "infinity"]
