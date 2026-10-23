# SPDX-License-Identifier: Apache-2.0
#
# The OCI image ghcr.io/felix-homelab/rpmgr (docs/10-operations.md, "Install"): the release
# binary of the target platform on distroless static, run as its nonroot user. The build context is
# a directory of release artifacts (build-release.sh), so the image holds exactly the published
# binary; nothing runs during the build, so every platform builds without emulation. WORKDIR makes
# /var/lib/rpmgr, the nonroot user's, which a volume mounted there inherits. Base image pinned by
# digest (CONTRIBUTING).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
ARG VERSION
ARG REVISION
ARG TARGETARCH
LABEL org.opencontainers.image.source="https://github.com/felix-homelab/rpmgr" \
      org.opencontainers.image.title="rpmgr" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --chmod=0555 rpmgr-${VERSION}-linux-${TARGETARCH} /usr/bin/rpmgr
WORKDIR /var/lib/rpmgr
ENTRYPOINT ["/usr/bin/rpmgr"]
