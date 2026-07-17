#!/bin/sh
# Prove Traefik terminates TLS via coolify-ssl's symlink leaf layout (.leaf / .gen.*),
# including after a SAN-driven re-issue (atomic flip + provider rewrite).
#
# Prerequisites: docker, docker compose, openssl, curl
# Image tag: coolify-ssl:ci (build before running)
set -eu

SMOKE_DIR="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)"
DATA="$SMOKE_DIR/data"
COMPOSE="docker compose -f $SMOKE_DIR/docker-compose.yml"

# Cert/key dirs are written as root inside the container; host rm fails on CI.
rm_data() {
  [ -d "$DATA" ] || return 0
  docker run --rm --entrypoint /bin/rm \
    -v "$SMOKE_DIR:/smoke" \
    coolify-ssl:ci -rf /smoke/data
}

cleanup() {
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
  rm_data
}
trap cleanup EXIT

rm_data
mkdir -p "$DATA/caroot" "$DATA/certs" "$DATA/dynamic"
cp "$SMOKE_DIR/routes.yaml" "$DATA/dynamic/routes.yaml"

export SSL_DOMAINS="coolify.lan,*.tools.lan"

echo "==> starting coolify-ssl + Traefik + whoami"
$COMPOSE up -d

echo "==> waiting for leaf + provider"
ready=0
i=0
while [ "$i" -lt 60 ]; do
  if [ -s "$DATA/certs/lan.cert" ] && [ -s "$DATA/dynamic/local-certs.yaml" ] && [ -s "$DATA/caroot/rootCA.pem" ]; then
    ready=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "timed out waiting for certs"
  $COMPOSE logs || true
  exit 1
fi

echo "==> asserting symlink leaf layout"
[ -L "$DATA/certs/lan.cert" ] || {
  echo "FAIL: lan.cert is not a symlink"
  ls -la "$DATA/certs"
  exit 1
}
[ -L "$DATA/certs/lan.key" ] || {
  echo "FAIL: lan.key is not a symlink"
  exit 1
}
[ -L "$DATA/certs/.leaf" ] || {
  echo "FAIL: .leaf is not a symlink"
  exit 1
}
# Resolve through symlinks must yield a real PEM
openssl x509 -in "$DATA/certs/lan.cert" -noout -checkend 0
openssl x509 -in "$DATA/certs/lan.cert" -noout -text | grep -F 'coolify.lan' >/dev/null
openssl verify -CAfile "$DATA/caroot/rootCA.pem" "$DATA/certs/lan.cert" >/dev/null

# Verify Traefik presents our leaf and that OpenSSL trusts it via rootCA.pem.
# curl --cacert is unreliable on macOS Secure Transport; we verify with openssl,
# then use curl -k only for the HTTP body.
assert_tls_ok() {
  expect_san=$1
  presented="$DATA/.presented.pem"
  if ! echo | openssl s_client -connect 127.0.0.1:8443 -servername coolify.lan 2>/dev/null |
      openssl x509 -out "$presented" 2>/dev/null; then
    echo "FAIL: could not fetch presented leaf from Traefik"
    return 1
  fi
  if ! openssl x509 -in "$presented" -noout -text | grep -F "$expect_san" >/dev/null; then
    echo "FAIL: presented cert missing SAN $expect_san"
    return 1
  fi
  if ! openssl verify -CAfile "$DATA/caroot/rootCA.pem" "$presented" >/dev/null; then
    echo "FAIL: presented cert not trusted by rootCA.pem"
    return 1
  fi
  curl -fsSk --resolve coolify.lan:8443:127.0.0.1 "https://coolify.lan:8443/" | grep -qi 'Hostname:'
}

echo "==> waiting for Traefik to load TLS"
tls_ok=0
i=0
while [ "$i" -lt 45 ]; do
  if assert_tls_ok 'coolify.lan' >/dev/null 2>&1; then
    tls_ok=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$tls_ok" -ne 1 ]; then
  echo "FAIL: Traefik did not serve trusted HTTPS via symlink leaf"
  assert_tls_ok 'coolify.lan' || true
  $COMPOSE logs traefik coolify-ssl || true
  exit 1
fi
echo "OK: initial HTTPS via .leaf layout (openssl-verified)"

# Capture generation target before renew
old_gen="$(readlink "$DATA/certs/.leaf")"
old_fp="$(openssl x509 -in "$DATA/certs/lan.cert" -outform DER | openssl sha256 | awk '{print $NF}')"

echo "==> forcing SAN-driven re-issue (restart with extra domain)"
$COMPOSE stop coolify-ssl >/dev/null
export SSL_DOMAINS="coolify.lan,*.tools.lan,extra.lan"
$COMPOSE up -d coolify-ssl

echo "==> waiting for renewed leaf (new SAN + generation flip)"
renewed=0
i=0
while [ "$i" -lt 60 ]; do
  if [ -s "$DATA/certs/lan.cert" ] && \
      openssl x509 -in "$DATA/certs/lan.cert" -noout -text 2>/dev/null | grep -F 'extra.lan' >/dev/null; then
    new_gen="$(readlink "$DATA/certs/.leaf" 2>/dev/null || true)"
    if [ -n "$new_gen" ] && [ "$new_gen" != "$old_gen" ]; then
      renewed=1
      break
    fi
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$renewed" -ne 1 ]; then
  echo "FAIL: leaf did not renew with extra.lan / new .leaf target"
  echo "old_gen=$old_gen new_gen=$(readlink "$DATA/certs/.leaf" 2>/dev/null || true)"
  $COMPOSE logs coolify-ssl || true
  exit 1
fi

new_fp="$(openssl x509 -in "$DATA/certs/lan.cert" -outform DER | openssl sha256 | awk '{print $NF}')"
if [ "$old_fp" = "$new_fp" ]; then
  echo "FAIL: leaf fingerprint unchanged after renew"
  exit 1
fi
echo "OK: renewed leaf (gen $old_gen -> $(readlink "$DATA/certs/.leaf"))"

echo "==> HTTPS still works after atomic renew"
tls_ok=0
i=0
while [ "$i" -lt 45 ]; do
  if assert_tls_ok 'extra.lan' >/dev/null 2>&1; then
    tls_ok=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$tls_ok" -ne 1 ]; then
  echo "FAIL: Traefik HTTPS broken after leaf renew"
  assert_tls_ok 'extra.lan' || true
  $COMPOSE logs traefik coolify-ssl || true
  exit 1
fi

# SNI for extra.lan should also present the renewed leaf
echo | openssl s_client -connect 127.0.0.1:8443 -servername extra.lan 2>/dev/null |
  openssl x509 -out "$DATA/.sni-extra.pem" 2>/dev/null || {
  echo "FAIL: could not fetch cert for SNI extra.lan"
  exit 1
}
openssl x509 -in "$DATA/.sni-extra.pem" -noout -text | grep -F 'extra.lan' >/dev/null || {
  echo "FAIL: renewed leaf not presented for SNI extra.lan"
  exit 1
}
openssl verify -CAfile "$DATA/caroot/rootCA.pem" "$DATA/.sni-extra.pem" >/dev/null || {
  echo "FAIL: SNI extra.lan cert not trusted by rootCA.pem"
  exit 1
}

echo "OK: Traefik smoke passed (symlink leaf + renew)"
