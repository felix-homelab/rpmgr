# SPDX-License-Identifier: Apache-2.0
#
# The OCI image ghcr.io/felix-homelab/rpmgr (docs/10-operations.md, "Install"): the release
# binary of the target platform on distroless static, run as its nonroot user. The build context is
# a directory of release artifacts (build-release.sh), so the image holds exactly the published
# binary; nothing runs during the build, so every platform builds without emulation. WORKDIR makes
# /var/lib/rpmgr, the nonroot user's, which a volume mounted there inherits. Base image pinned by
# digest (CONTRIBUTING).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087
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
