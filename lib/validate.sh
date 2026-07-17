# shellcheck shell=sh
# Config and path validation for coolify-ssl.

# CERT_NAME / PROVIDER_FILE basename: [A-Za-z0-9._-] only, no leading dot.
validate_name() {
  label="$1"
  value="$2"
  case "$value" in
    '' | .* | *..*) fail "invalid $label: empty, leading dot, or '..'" ;;
  esac
  case "$value" in
    *[!A-Za-z0-9._-]*) fail "invalid $label '$value' (allowed: A-Za-z0-9._-)" ;;
  esac
}

# Absolute path without shell metacharacters or path traversal.
validate_abs_path() {
  label="$1"
  value="$2"
  case "$value" in
    /*) ;;
    *) fail "invalid $label '$value' (must be an absolute path)" ;;
  esac
  case "$value" in
    *..*) fail "invalid $label '$value' (path traversal)" ;;
  esac
  case "$value" in
    *[!A-Za-z0-9/._+-]*) fail "invalid $label '$value' (disallowed characters)" ;;
  esac
}

validate_ssh_user() {
  case "$1" in
    '' | *[!A-Za-z0-9._-]*) fail "invalid CERT_SYNC_SSH_USER '$1'" ;;
  esac
}

validate_ssh_port() {
  case "$1" in
    '' | *[!0-9]*) fail "invalid CERT_SYNC_SSH_PORT '$1'" ;;
  esac
  if [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
    fail "invalid CERT_SYNC_SSH_PORT '$1' (1-65535)"
  fi
}

validate_interval_seconds() {
  label="$1"
  value="$2"
  case "$value" in
    '' | *[!0-9]*) fail "invalid $label '$value' (positive integer)" ;;
  esac
  if [ "$value" -lt 60 ]; then
    fail "invalid $label '$value' (minimum 60)"
  fi
  # Cap at 10 years to reject accidental overflow / absurd Coolify env typos.
  if [ "$value" -gt 315360000 ]; then
    fail "invalid $label '$value' (maximum 315360000 ≈ 10 years)"
  fi
}

# Fill CHECK_INTERVAL_SECONDS / RENEW_BEFORE_EXPIRY_SECONDS with backward-compatible defaults.
resolve_intervals() {
  legacy_default=2592000
  legacy="${RENEW_INTERVAL_SECONDS:-}"
  if [ -z "${CHECK_INTERVAL_SECONDS:-}" ]; then
    CHECK_INTERVAL_SECONDS="${legacy:-$legacy_default}"
  fi
  if [ -z "${RENEW_BEFORE_EXPIRY_SECONDS:-}" ]; then
    RENEW_BEFORE_EXPIRY_SECONDS="${legacy:-$legacy_default}"
  fi
  # Keep legacy var populated for logs / older compose snippets.
  if [ -z "$legacy" ]; then
    RENEW_INTERVAL_SECONDS="$CHECK_INTERVAL_SECONDS"
  fi
}

validate_max_domains() {
  case "$1" in
    '' | *[!0-9]*) fail "invalid MAX_DOMAINS '$1' (positive integer)" ;;
  esac
  if [ "$1" -lt 1 ] || [ "$1" -gt 256 ]; then
    fail "invalid MAX_DOMAINS '$1' (1-256)"
  fi
}

validate_backoff_seconds() {
  label="$1"
  value="$2"
  case "$value" in
    '' | *[!0-9]*) fail "invalid $label '$value' (non-negative integer)" ;;
  esac
  # 0 disables backoff (tests); cap at 1 hour to avoid absurd Coolify typos.
  if [ "$value" -gt 3600 ]; then
    fail "invalid $label '$value' (maximum 3600)"
  fi
}

validate_config() {
  resolve_intervals
  validate_name "CERT_NAME" "$CERT_NAME"
  validate_name "PROVIDER_FILE" "$PROVIDER_FILE"
  validate_abs_path "REMOTE_CERT_DIR" "$REMOTE_CERT_DIR"
  validate_abs_path "REMOTE_DYNAMIC_DIR" "$REMOTE_DYNAMIC_DIR"
  validate_ssh_user "$CERT_SYNC_SSH_USER"
  validate_ssh_port "$CERT_SYNC_SSH_PORT"
  validate_interval_seconds "CHECK_INTERVAL_SECONDS" "$CHECK_INTERVAL_SECONDS"
  validate_interval_seconds "RENEW_BEFORE_EXPIRY_SECONDS" "$RENEW_BEFORE_EXPIRY_SECONDS"
  validate_max_domains "$MAX_DOMAINS"
  case "$CERT_SYNC_STRICT" in
    0 | 1 | true | false | yes | no) ;;
    *) fail "invalid CERT_SYNC_STRICT '$CERT_SYNC_STRICT' (use 0 or 1)" ;;
  esac
  # Optional; default applied in strict_sync_fail when unset.
  if [ -n "${CERT_SYNC_FAIL_BACKOFF_SECONDS:-}" ]; then
    validate_backoff_seconds "CERT_SYNC_FAIL_BACKOFF_SECONDS" "$CERT_SYNC_FAIL_BACKOFF_SECONDS"
  fi
}

cert_sync_strict_enabled() {
  case "$CERT_SYNC_STRICT" in
    1 | true | yes) return 0 ;;
    *) return 1 ;;
  esac
}
