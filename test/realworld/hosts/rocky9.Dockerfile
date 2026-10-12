# SPDX-License-Identifier: Apache-2.0
#
# A Rocky Linux 9 host with systemd as PID 1, for the real-world run (README.md). Base image
# pinned by digest (CONTRIBUTING).
FROM mirror.gcr.io/rockylinux/rockylinux@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f
ENV container=docker
RUN dnf install -y --setopt=install_weak_deps=False systemd procps-ng iproute openssl ca-certificates \
    && dnf clean all && systemctl mask getty@tty1.service console-getty.service
COPY shared-root.service /etc/systemd/system/
RUN systemctl enable shared-root.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
