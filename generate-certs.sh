#!/bin/sh
# Issue an internal TLS leaf (mkcert CA), write Traefik's file provider, optionally
# scp the leaf (never the CA) to peer hosts, then re-check on an interval and
# re-issue only when SANs drift, the leaf is near expiry, or material is missing.
#
# Implementation is split under lib/ (common, validate, san, domains, ca, provider,
# leaf, sync). This entrypoint loads libraries and runs the main loop.
set -eu

CERT_DIR="${CERT_DIR:-/certs}"
DYNAMIC_DIR="${DYNAMIC_DIR:-/dynamic}"
CERT_NAME="${CERT_NAME:-lan}"
DOMAINS_FILE="${DOMAINS_FILE:-/etc/ssl-gen/domains.txt}"
PROVIDER_TEMPLATE="${PROVIDER_TEMPLATE:-/etc/ssl-gen/traefik-dynamic.yaml.tpl}"
PROVIDER_FILE="${PROVIDER_FILE:-local-certs.yaml}"
# Legacy combined knob: when set alone, fills both check + near-expiry (default 30d).
# Prefer CHECK_INTERVAL_SECONDS and RENEW_BEFORE_EXPIRY_SECONDS.
RENEW_INTERVAL_SECONDS="${RENEW_INTERVAL_SECONDS:-}"
CHECK_INTERVAL_SECONDS="${CHECK_INTERVAL_SECONDS:-}"
RENEW_BEFORE_EXPIRY_SECONDS="${RENEW_BEFORE_EXPIRY_SECONDS:-}"
# Hard cap on SAN count (mkcert argv / operational sanity).
MAX_DOMAINS="${MAX_DOMAINS:-64}"

CERT_SYNC_HOSTS="${CERT_SYNC_HOSTS:-}"
CERT_SYNC_SSH_USER="${CERT_SYNC_SSH_USER:-root}"
CERT_SYNC_SSH_PORT="${CERT_SYNC_SSH_PORT:-22}"
CERT_SYNC_SSH_KEY_PATH="${CERT_SYNC_SSH_KEY_PATH:-}"
CERT_SYNC_STRICT="${CERT_SYNC_STRICT:-1}"
# Sleep before STRICT exit so Docker restart loops do not hammer peers (0 disables).
CERT_SYNC_FAIL_BACKOFF_SECONDS="${CERT_SYNC_FAIL_BACKOFF_SECONDS:-60}"
REMOTE_CERT_DIR="${REMOTE_CERT_DIR:-/data/coolify/proxy/certs}"
REMOTE_DYNAMIC_DIR="${REMOTE_DYNAMIC_DIR:-/data/coolify/proxy/dynamic}"

# Private runtime dir (not world-writable /tmp). Mount ONE sync key here.
RUNTIME_DIR="${RUNTIME_DIR:-/run/coolify-ssl}"
SSH_KEY_RUNTIME="$RUNTIME_DIR/cert-sync-key"
# Persisted with the CA volume by default (StrictHostKeyChecking=yes).
SSH_KNOWN_HOSTS_FILE="${SSH_KNOWN_HOSTS_FILE:-/caroot/ssh_known_hosts}"
# Exclusive writer lock (flock). Default: $CERT_DIR/.coolify-ssl.lock
LOCK_FILE="${LOCK_FILE:-}"

# Resolve lib/: explicit override (tests) → sibling of this script when executed → image path.
coolify_ssl_resolve_lib() {
  if [ -n "${COOLIFY_SSL_LIB:-}" ] && [ -d "$COOLIFY_SSL_LIB" ]; then
    return 0
  fi
  # When executed (not sourced), $0 is this script.
  case "${0##*/}" in
    generate-certs.sh)
      _root="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)"
      if [ -d "$_root/lib" ]; then
        COOLIFY_SSL_LIB="$_root/lib"
        return 0
      fi
      ;;
  esac
  if [ -d /usr/local/lib/coolify-ssl ]; then
    COOLIFY_SSL_LIB=/usr/local/lib/coolify-ssl
    return 0
  fi
  printf '%s ssl-gen: FATAL: cannot locate lib/ (set COOLIFY_SSL_LIB)\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >&2
  exit 1
}

coolify_ssl_resolve_lib
# shellcheck source=lib/common.sh
. "$COOLIFY_SSL_LIB/common.sh"
# shellcheck source=lib/validate.sh
. "$COOLIFY_SSL_LIB/validate.sh"
# shellcheck source=lib/san.sh
. "$COOLIFY_SSL_LIB/san.sh"
# shellcheck source=lib/domains.sh
. "$COOLIFY_SSL_LIB/domains.sh"
# shellcheck source=lib/ca.sh
. "$COOLIFY_SSL_LIB/ca.sh"
# shellcheck source=lib/provider.sh
. "$COOLIFY_SSL_LIB/provider.sh"
# shellcheck source=lib/leaf.sh
. "$COOLIFY_SSL_LIB/leaf.sh"
# shellcheck source=lib/sync.sh
. "$COOLIFY_SSL_LIB/sync.sh"

coolify_ssl_main() {
  trap on_signal INT TERM
  # mkdir-lock fallback cleanup (no-op when using flock).
  trap release_instance_lock EXIT

  validate_config
  log "intervals: check=${CHECK_INTERVAL_SECONDS}s renew_before_expiry=${RENEW_BEFORE_EXPIRY_SECONDS}s"
  mkdir -p "$CERT_DIR" "$DYNAMIC_DIR" "$RUNTIME_DIR"
  chmod 700 "$RUNTIME_DIR" 2>/dev/null || true
  # One writer per CERT_DIR (shared Coolify proxy mounts). Held until process exit.
  acquire_instance_lock
  cleanup_orphan_stages
  migrate_flat_leaf_if_needed
  resolve_caroot
  setup_ssh_key
  read_domains

  while [ "$STOP_REQUESTED" -eq 0 ]; do
    if needs_renewal; then
      generate
    else
      log "leaf still valid (SANs match, expiry beyond ${RENEW_BEFORE_EXPIRY_SECONDS}s) — skipping re-issue"
    fi
    # Sync when peers are configured; skip hosts whose remote leaf fingerprint already matches.
    distribute
    [ "$STOP_REQUESTED" -eq 0 ] || break
    log "next check in ${CHECK_INTERVAL_SECONDS}s"
    interruptible_sleep "$CHECK_INTERVAL_SECONDS"
    [ "$STOP_REQUESTED" -eq 0 ] || break
    read_domains
  done

  log "stopped"
}

# Run only when executed as a script (not when sourced by tests).
case "${0##*/}" in
  generate-certs.sh) coolify_ssl_main "$@" ;;
esac
