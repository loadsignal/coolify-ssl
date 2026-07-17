#!/bin/sh
# Shared assert helpers for coolify-ssl tests (POSIX sh).
# shellcheck shell=sh
# Assignments in setup_tmp are for the sourced runtime / other test files.
# shellcheck disable=SC2034

PASS=0
FAIL=0
TMPROOT=

setup_tmp() {
  TMPROOT="$(mktemp -d "${TMPDIR:-/tmp}/coolify-ssl-test.XXXXXX")"
  # When tests source generate-certs.sh, $0 is the test file — set lib path explicitly.
  COOLIFY_SSL_LIB="$(CDPATH='' cd -- "$(dirname "$0")/../lib" && pwd)"
  export COOLIFY_SSL_LIB
  CERT_DIR="$TMPROOT/certs"
  DYNAMIC_DIR="$TMPROOT/dynamic"
  CAROOT="$TMPROOT/caroot"
  DOMAINS_FILE="$TMPROOT/domains.txt"
  PROVIDER_TEMPLATE="$TMPROOT/traefik-dynamic.yaml.tpl"
  RUNTIME_DIR="$TMPROOT/runtime"
  SSH_KEY_RUNTIME="$RUNTIME_DIR/cert-sync-key"
  CERT_NAME="lan"
  PROVIDER_FILE="local-certs.yaml"
  CERT_SYNC_HOSTS=""
  CERT_SYNC_SSH_KEY_PATH=""
  CERT_SYNC_STRICT="0"
  SSL_DOMAINS=""
  SSH_KNOWN_HOSTS_FILE="$CAROOT/ssh_known_hosts"
  REMOTE_CERT_DIR="/data/coolify/proxy/certs"
  REMOTE_DYNAMIC_DIR="/data/coolify/proxy/dynamic"
  RENEW_INTERVAL_SECONDS="2592000"
  CHECK_INTERVAL_SECONDS="2592000"
  RENEW_BEFORE_EXPIRY_SECONDS="2592000"
  MAX_DOMAINS="64"
  mkdir -p "$CERT_DIR" "$DYNAMIC_DIR" "$CAROOT" "$RUNTIME_DIR"
  cp "$(dirname "$0")/../traefik-dynamic.yaml.tpl" "$PROVIDER_TEMPLATE"
}

cleanup_tmp() {
  [ -n "$TMPROOT" ] && [ -d "$TMPROOT" ] && rm -rf "$TMPROOT"
}

assert_eq() {
  expected="$1"
  actual="$2"
  msg="${3:-}"
  if [ "$expected" = "$actual" ]; then
    PASS=$((PASS + 1))
    return 0
  fi
  FAIL=$((FAIL + 1))
  printf 'FAIL: %s\n  expected: %s\n  actual:   %s\n' "${msg:-values differ}" "$expected" "$actual"
}

assert_contains() {
  haystack="$1"
  needle="$2"
  msg="${3:-}"
  case "$haystack" in
    *"$needle"*) PASS=$((PASS + 1)); return 0 ;;
  esac
  FAIL=$((FAIL + 1))
  printf 'FAIL: %s\n  missing: %s\n  in: %s\n' "${msg:-substring not found}" "$needle" "$haystack"
}

assert_file_exists() {
  path="$1"
  msg="${2:-file should exist: $path}"
  if [ -e "$path" ]; then
    PASS=$((PASS + 1))
    return 0
  fi
  FAIL=$((FAIL + 1))
  printf 'FAIL: %s\n' "$msg"
}

assert_ok() {
  msg="$1"
  shift
  if ( "$@" ) >/dev/null 2>&1; then
    PASS=$((PASS + 1))
    return 0
  fi
  FAIL=$((FAIL + 1))
  printf 'FAIL: expected success: %s\n' "$msg"
}

assert_fails() {
  msg="$1"
  shift
  # Subshell so fail()/exit inside the script under test does not abort the suite.
  if ( "$@" ) >/dev/null 2>&1; then
    FAIL=$((FAIL + 1))
    printf 'FAIL: expected failure: %s\n' "$msg"
    return 0
  fi
  PASS=$((PASS + 1))
}

print_summary() {
  printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
  [ "$FAIL" -eq 0 ]
}
