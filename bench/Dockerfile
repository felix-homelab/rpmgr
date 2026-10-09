# SPDX-License-Identifier: Apache-2.0
#
# The benchmark's nodes: the rpmgrtest build of rpmgr and the bench command, built by `bench run`,
# with iproute2 for netem and procps for pkill.
FROM mirror.gcr.io/library/debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 procps \
    && rm -rf /var/lib/apt/lists/*
COPY bin/rpmgr bin/bench /usr/local/bin/
CMD ["sleep", "infinity"]
