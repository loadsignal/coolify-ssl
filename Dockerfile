# coolify-ssl — mkcert CA + leaf certs for Coolify Traefik.
# Runs as root: Coolify proxy cert/dynamic mounts are typically root-owned.
# See SECURITY.md. Drop privileges is not practical without host chown.
#
# Rebuild mkcert from source with a current Go toolchain. Upstream v1.4.4
# release binaries ship Go 1.18 / old x/* modules and fail Trivy HIGH/CRITICAL.

ARG GOLANG_IMAGE=golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2
ARG ALPINE_IMAGE=alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

FROM ${GOLANG_IMAGE} AS mkcert-build
ARG MKCERT_VERSION=v1.4.4
# FiloSottile/mkcert v1.4.4 tag commit
ARG MKCERT_COMMIT=2a46726cebac0ff4e1f133d90b4e4c42f1edf44a
WORKDIR /src
RUN apk add --no-cache git ca-certificates \
 && git clone --filter=blob:none https://github.com/FiloSottile/mkcert.git . \
 && git checkout --detach "$MKCERT_COMMIT" \
 && test "$(git rev-parse HEAD)" = "$MKCERT_COMMIT" \
 && go get golang.org/x/net@v0.55.0 \
 && go get golang.org/x/crypto@v0.54.0 \
 && go get golang.org/x/text@v0.37.0 \
 && go mod tidy \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${MKCERT_VERSION}" -o /out/mkcert .

FROM ${ALPINE_IMAGE}

ARG VERSION=0.1.0

LABEL org.opencontainers.image.title="coolify-ssl" \
      org.opencontainers.image.description="Local mkcert TLS for Coolify + Traefik (LAN/VPN/homelab)" \
      org.opencontainers.image.source="https://github.com/loadsignal/coolify-ssl" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# mkcert -install: write CAROOT only; do not mutate every trust store (see lib/ca.sh).
ENV TRUST_STORES=java

COPY --from=mkcert-build /out/mkcert /usr/local/bin/mkcert

RUN apk add --no-cache ca-certificates openssh-client openssl \
 && mkcert -version \
 && mkdir -p /run/coolify-ssl /usr/local/lib/coolify-ssl \
 && chmod 700 /run/coolify-ssl

COPY lib/ /usr/local/lib/coolify-ssl/
COPY generate-certs.sh /usr/local/bin/generate-certs.sh
COPY traefik-dynamic.yaml.tpl /etc/ssl-gen/traefik-dynamic.yaml.tpl
RUN chmod +x /usr/local/bin/generate-certs.sh \
 && chmod 644 /usr/local/lib/coolify-ssl/*.sh \
 && chmod +x /usr/local/lib/coolify-ssl/remote-publish.sh

STOPSIGNAL SIGTERM

# Healthy = leaf + provider present and leaf not already expired.
# Renewal timing uses RENEW_BEFORE_EXPIRY_SECONDS in the entrypoint (near-expiry window);
# do not couple HEALTHCHECK to that window or short check intervals flap the container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD /bin/sh -c 'test -s "/certs/${CERT_NAME:-lan}.cert" && test -s "/certs/${CERT_NAME:-lan}.key" && test -s "/dynamic/${PROVIDER_FILE:-local-certs.yaml}" && openssl x509 -in "/certs/${CERT_NAME:-lan}.cert" -noout -checkend 0 >/dev/null 2>&1'

ENTRYPOINT ["/usr/local/bin/generate-certs.sh"]
