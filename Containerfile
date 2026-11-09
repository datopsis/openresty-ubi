ARG UBI_MINIMAL_IMAGE="registry.access.redhat.com/ubi9/ubi-minimal:9.8@sha256:f26ef64172ea61f5ac5ba4be8c5c738bf8760b22b3e5148ce7b40f7308ab32db"
ARG UBI_MICRO_IMAGE="registry.access.redhat.com/ubi9/ubi-micro:9.8@sha256:d3499a0896e2d6a1642f922615831bc5c2fd513bbb34f3446cabba530d9d54a2"
FROM scratch AS artifact_bundle
FROM ${UBI_MINIMAL_IMAGE} AS builder
ARG ARTIFACT_LOCK_SHA256
COPY --from=artifact_bundle / /bundle/
COPY --chmod=0755 scripts/install-rpm-bundle.sh /usr/local/bin/install-rpm-bundle
RUN test -n "${ARTIFACT_LOCK_SHA256}" \
    && test "$(tr -d '\n' </bundle/LOCK-SHA256)" = "${ARTIFACT_LOCK_SHA256}" \
    && /usr/local/bin/install-rpm-bundle /bundle /runtime \
    && rm -rf /runtime/etc/yum.repos.d /runtime/etc/pki/rpm-gpg \
       /runtime/run/* /runtime/tmp/* /runtime/var/cache/* /runtime/var/log/* \
    && find /runtime -type f -perm /6000 -exec chmod a-s {} + \
    && mkdir -p /runtime/tmp/openresty \
    && chmod 0755 /runtime/tmp/openresty
FROM ${UBI_MICRO_IMAGE}
LABEL org.opencontainers.image.title="OpenResty on Red Hat UBI 9" \
      org.opencontainers.image.source="https://github.com/datopsis/openresty-ubi" \
      org.opencontainers.image.description="Rootless OpenResty web platform; development increment" \
      org.opencontainers.image.licenses="Apache-2.0 AND BSD-2-Clause AND MIT" \
      org.opencontainers.image.version="1.31.8.1" \
      io.datopsis.nginx.version="1.31.8"
COPY --from=builder /runtime/ /
RUN rm -rf /etc/yum.repos.d /etc/pki/rpm-gpg
COPY --chown=0:0 --chmod=0644 container/nginx.conf /etc/nginx/nginx.conf
COPY --chown=0:0 --chmod=0644 container/conf.d/default.conf /etc/nginx/conf.d/default.conf
COPY --chown=0:0 --chmod=0644 container/html/index.html /usr/share/nginx/html/index.html
COPY --chown=0:0 --chmod=0755 container/entrypoint.sh /usr/local/bin/entrypoint
ENV LANG="C.UTF-8" TZ="UTC"
USER 999:0
WORKDIR /usr/share/nginx/html
EXPOSE 8080
# Config validation only; runtime tests exercise HTTP liveness separately.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-ec", "openresty -t -q -p /tmp/openresty/ -c \"${OPENRESTY_UBI_CONFIG:-/etc/nginx/nginx.conf}\" -e stderr"]
STOPSIGNAL SIGQUIT
ENTRYPOINT ["/usr/local/bin/entrypoint"]
