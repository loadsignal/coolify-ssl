#!/bin/sh
# Integration: CA bootstrap + leaf cert + Traefik provider (requires mkcert).
set -eu

TESTS_DIR="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
. "$TESTS_DIR/helpers.sh"

if ! command -v mkcert >/dev/null 2>&1; then
  printf 'SKIP: mkcert not installed\n'
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  printf 'SKIP: openssl not installed\n'
  exit 0
fi

setup_tmp
trap cleanup_tmp EXIT

export CERT_DIR DYNAMIC_DIR CAROOT DOMAINS_FILE PROVIDER_TEMPLATE
export CERT_NAME PROVIDER_FILE
export CERT_SYNC_HOSTS="" CERT_SYNC_SSH_KEY_PATH="" SSL_DOMAINS=""
export RUNTIME_DIR SSH_KEY_RUNTIME RENEW_INTERVAL_SECONDS MAX_DOMAINS
export CHECK_INTERVAL_SECONDS RENEW_BEFORE_EXPIRY_SECONDS
# Avoid installing into the OS trust store during tests (CA still written to CAROOT).
export TRUST_STORES=java

# shellcheck source=../generate-certs.sh
. "$TESTS_DIR/../generate-certs.sh"

printf 'coolify.lan\n*.tools.lan\n' >"$DOMAINS_FILE"

resolve_caroot
assert_file_exists "$CAROOT/rootCA.pem" "CA cert created"
assert_file_exists "$CAROOT/rootCA-key.pem" "CA key created"

# Reuse existing CA
resolve_caroot
assert_file_exists "$CAROOT/rootCA.pem" "CA reused"

# Inconsistent CA state
rm -f "$CAROOT/rootCA-key.pem"
assert_fails "inconsistent CA (cert without key)" resolve_caroot

# Fresh CA for leaf generation
rm -rf "$CAROOT"
mkdir -p "$CAROOT"
resolve_caroot

read_domains
generate
assert_file_exists "$CERT_DIR/lan.cert" "leaf cert generated"
assert_file_exists "$CERT_DIR/lan.key" "leaf key generated"
assert_file_exists "$DYNAMIC_DIR/local-certs.yaml" "provider written after generate"
if [ -L "$CERT_DIR/lan.cert" ] && [ -L "$CERT_DIR/lan.key" ] && [ -L "$CERT_DIR/.leaf" ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: expected atomic symlink leaf layout (.leaf + name symlinks)\n'
fi

# No leftover tmp / aborted stage files from atomic publish
leftover="$(find "$CERT_DIR" "$DYNAMIC_DIR" \( -name '*.tmp.*' -o -name '.coolify-ssl-stage.*' \) 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "0" "$leftover" "no leftover .tmp or stage dirs after generate"
gen_count="$(find "$CERT_DIR" -type d -name '.gen.*' 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "1" "$gen_count" "exactly one active generation directory"

cert_size="$(wc -c <"$CERT_DIR/lan.cert" | tr -d ' ')"
key_size="$(wc -c <"$CERT_DIR/lan.key" | tr -d ' ')"
if [ "$cert_size" -gt 100 ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: cert too small (%s bytes)\n' "$cert_size"
fi
if [ "$key_size" -gt 100 ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: key too small (%s bytes)\n' "$key_size"
fi

# Leaf must include expected SANs and be currently valid.
sans="$(openssl x509 -in "$CERT_DIR/lan.cert" -noout -ext subjectAltName 2>/dev/null || true)"
if [ -z "$sans" ]; then
  # Older openssl: fall back to -text
  sans="$(openssl x509 -in "$CERT_DIR/lan.cert" -noout -text)"
fi
assert_contains "$sans" "coolify.lan" "leaf SAN includes coolify.lan"
assert_contains "$sans" "*.tools.lan" "leaf SAN includes *.tools.lan"

if openssl x509 -in "$CERT_DIR/lan.cert" -noout -checkend 86400 >/dev/null 2>&1; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: leaf cert not valid for at least 24h\n'
fi

# Cert and key must form a matching pair (works for RSA and EC).
cert_pub="$(openssl x509 -in "$CERT_DIR/lan.cert" -noout -pubkey | openssl pkey -pubin -outform DER 2>/dev/null | openssl sha256)"
key_pub="$(openssl pkey -in "$CERT_DIR/lan.key" -pubout -outform DER 2>/dev/null | openssl sha256)"
assert_eq "$cert_pub" "$key_pub" "leaf cert/key public key match"

# Smart renew: existing leaf with matching SANs and distant expiry → skip.
assert_fails "needs_renewal false when leaf is fresh and SANs match" needs_renewal

# SAN drift → renew.
printf 'coolify.lan\nextra.lan\n' >"$DOMAINS_FILE"
read_domains
assert_ok "needs_renewal when SANs drift" needs_renewal

# Restore matching domains; near-expiry window forces renew.
printf 'coolify.lan\n*.tools.lan\n' >"$DOMAINS_FILE"
read_domains
# Max allowed window still exceeds mkcert leaf lifetime → renew needed.
RENEW_BEFORE_EXPIRY_SECONDS=315360000
assert_ok "needs_renewal when within expiry window" needs_renewal
RENEW_BEFORE_EXPIRY_SECONDS=2592000
assert_fails "needs_renewal false again with normal window" needs_renewal

# --- IPv6 / mixed SAN canonicalization (no perpetual renew loop) ---
printf 'coolify.lan\n2001:db8::1\n::1\n10.0.0.4\n' >"$DOMAINS_FILE"
read_domains
generate
assert_fails "needs_renewal false with compressed IPv6 SANs matching leaf" needs_renewal

# Same addresses, different textual form / DNS case → still match.
DOMAINS_ARGS="Coolify.LAN 2001:DB8:0:0:0:0:0:1 0:0:0:0:0:0:0:1 10.0.0.4"
assert_ok "leaf_matches_domains with expanded IPv6 + DNS case fold" leaf_matches_domains
assert_fails "needs_renewal false after IPv6 form / DNS case rewrite" needs_renewal

print_summary
