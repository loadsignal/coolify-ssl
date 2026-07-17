# coolify-ssl — mkcert CA + leaf certs for Coolify Traefik.
# Runs as root: Coolify proxy cert/dynamic mounts are typically root-owned.
# See SECURITY.md. Drop privileges is not practical without host chown.
# alpine:3.24.1 multi-arch index (linux/amd64 + linux/arm64).
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG VERSION=0.1.0
ARG MKCERT_VERSION=v1.4.4
# SHA256 of FiloSottile/mkcert GitHub release binaries (not Homebrew bottles).
ARG MKCERT_SHA256_AMD64=6d31c65b03972c6dc4a14ab429f2928300518b26503f58723e532d1b0a3bbb52
ARG MKCERT_SHA256_ARM64=b98f2cc69fd9147fe4d405d859c57504571adec0d3611c3eefd04107c7ac00d0

LABEL org.opencontainers.image.title="coolify-ssl" \
      org.opencontainers.image.description="Local mkcert TLS for Coolify + Traefik (LAN/VPN/homelab)" \
      org.opencontainers.image.source="https://github.com/loadsignal/coolify-ssl" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# mkcert -install: write CAROOT only; do not mutate every trust store (see lib/ca.sh).
ENV TRUST_STORES=java

RUN apk add --no-cache ca-certificates wget openssh-client openssl \
 && arch="$(uname -m)" \
 && case "$arch" in \
      x86_64) march=amd64; expect_sha="$MKCERT_SHA256_AMD64" ;; \
      aarch64) march=arm64; expect_sha="$MKCERT_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac \
 && wget -qO /usr/local/bin/mkcert \
      "https://github.com/FiloSottile/mkcert/releases/download/${MKCERT_VERSION}/mkcert-${MKCERT_VERSION}-linux-${march}" \
 && echo "$expect_sha  /usr/local/bin/mkcert" | sha256sum -c - \
 && chmod +x /usr/local/bin/mkcert \
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
