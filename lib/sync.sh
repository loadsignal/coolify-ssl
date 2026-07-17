# shellcheck shell=sh
# SSH leaf sync (never the CA) for coolify-ssl.
# Stages leaf + provider + lib/remote-publish.sh, then runs that script on the peer.

resolve_ssh_key_file() {
  # Only a single bind-mounted key under RUNTIME_DIR is accepted (no full-dir remap).
  # Rejects "..". Sets SSH_KEY_RESOLVED.
  key_ref="$1"
  case "$key_ref" in
    *..*) fail "invalid CERT_SYNC_SSH_KEY_PATH (path traversal): $key_ref" ;;
  esac
  [ -n "$key_ref" ] || fail "CERT_SYNC_SSH_KEY_PATH is empty"

  runtime_prefix="${RUNTIME_DIR%/}"

  case "$key_ref" in
    "$runtime_prefix"/*)
      SSH_KEY_RESOLVED="$key_ref"
      ;;
    /*)
      fail "CERT_SYNC_SSH_KEY_PATH must be under $runtime_prefix (mount one key file, e.g. /data/coolify/ssh/keys/ssh_key@<uuid>:$runtime_prefix/sync.key:ro). Full-directory key mounts are not supported."
      ;;
    *)
      fail "CERT_SYNC_SSH_KEY_PATH must be an absolute path under $runtime_prefix (got '$key_ref')"
      ;;
  esac

  if [ -s "$SSH_KEY_RESOLVED" ]; then
    return
  fi

  fail "SSH key not found: $SSH_KEY_RESOLVED (mount one key file at $runtime_prefix/sync.key:ro and set CERT_SYNC_SSH_KEY_PATH=$runtime_prefix/sync.key)"
}

setup_ssh_key() {
  [ -n "$CERT_SYNC_HOSTS" ] || return 0

  [ -n "$CERT_SYNC_SSH_KEY_PATH" ] ||
    fail "CERT_SYNC_HOSTS set without CERT_SYNC_SSH_KEY_PATH (e.g. /run/coolify-ssl/sync.key with a single-key bind mount)"

  # Normalize like SSL_DOMAINS (commas / newlines → spaces), then squeeze to one token list.
  CERT_SYNC_HOSTS="$(printf '%s' "$CERT_SYNC_HOSTS" | tr ',\n\r\t' '    ')"
  set -f
  # shellcheck disable=SC2086
  set -- $CERT_SYNC_HOSTS
  set +f
  [ "$#" -gt 0 ] || fail "CERT_SYNC_HOSTS is empty after normalizing separators"
  CERT_SYNC_HOSTS="$*"

  set -f
  for host in $CERT_SYNC_HOSTS; do
    validate_sync_host "CERT_SYNC_HOSTS entry" "$host"
  done
  set +f

  case "$CERT_SYNC_SSH_USER" in
    root)
      log "WARNING: CERT_SYNC_SSH_USER=root — sync key can write peer proxy paths as root. Prefer a dedicated user (docs/ssh-least-privilege.md)"
      ;;
  esac

  resolve_ssh_key_file "$CERT_SYNC_SSH_KEY_PATH"
  log "SSH key from $SSH_KEY_RESOLVED (CERT_SYNC_SSH_KEY_PATH=$CERT_SYNC_SSH_KEY_PATH)"
  mkdir -p "$RUNTIME_DIR"
  chmod 700 "$RUNTIME_DIR"
  cp "$SSH_KEY_RESOLVED" "$SSH_KEY_RUNTIME"
  # Local 600 copy: ssh refuses keys owned by another uid on a mounted volume.
  chmod 600 "$SSH_KEY_RUNTIME"

  mkdir -p "$(dirname "$SSH_KNOWN_HOSTS_FILE")"
  if [ ! -s "$SSH_KNOWN_HOSTS_FILE" ]; then
    fail "SSH known_hosts empty or missing at $SSH_KNOWN_HOSTS_FILE. Seed host keys (StrictHostKeyChecking=yes), e.g. on the Coolify host: ssh-keyscan -H <peer> >> /data/coolify/ca/ssh_known_hosts — see SECURITY.md"
  fi
  log "SSH known_hosts: $SSH_KNOWN_HOSTS_FILE (StrictHostKeyChecking=yes)"
}

ssh_run() {
  ssh -o BatchMode=yes -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$SSH_KNOWN_HOSTS_FILE" \
    -o IdentitiesOnly=yes -i "$SSH_KEY_RUNTIME" \
    "$@"
}

scp_run() {
  scp -o BatchMode=yes -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$SSH_KNOWN_HOSTS_FILE" \
    -o IdentitiesOnly=yes -i "$SSH_KEY_RUNTIME" \
    "$@"
}

# Path to the peer-side publish script shipped in the image / repo lib/.
remote_publish_script_path() {
  if [ -n "${REMOTE_PUBLISH_SCRIPT:-}" ] && [ -r "$REMOTE_PUBLISH_SCRIPT" ]; then
    printf '%s\n' "$REMOTE_PUBLISH_SCRIPT"
    return 0
  fi
  if [ -n "${COOLIFY_SSL_LIB:-}" ] && [ -r "$COOLIFY_SSL_LIB/remote-publish.sh" ]; then
    printf '%s\n' "$COOLIFY_SSL_LIB/remote-publish.sh"
    return 0
  fi
  fail "remote-publish.sh not found (set COOLIFY_SSL_LIB or REMOTE_PUBLISH_SCRIPT)"
}

# Return 0 when remote leaf cert DER fingerprint matches local_fp.
remote_leaf_fingerprint_matches() {
  dest="$1"
  remote_cert_q="$2"
  local_fp="$3"
  [ -n "$local_fp" ] || return 1
  remote_fp="$(
    ssh_run -p "$CERT_SYNC_SSH_PORT" "$dest" \
      "openssl x509 -in $remote_cert_q -noout 2>/dev/null && openssl x509 -in $remote_cert_q -outform DER 2>/dev/null | openssl sha256 2>/dev/null" |
      awk '{print $NF}'
  )" || return 1
  [ -n "$remote_fp" ] && [ "$remote_fp" = "$local_fp" ]
}

# Best-effort removal of staged remote .tmp files, aborted generation, and publish script.
cleanup_remote_tmps() {
  dest="$1"
  cert_tmp_q="$2"
  key_tmp_q="$3"
  provider_tmp_q="$4"
  remote_gen_q="$5"
  script_tmp_q="$6"
  ssh_run -p "$CERT_SYNC_SSH_PORT" "$dest" \
    "rm -f $cert_tmp_q $key_tmp_q $provider_tmp_q $script_tmp_q; if [ -d $remote_gen_q ] && [ ! -L $remote_gen_q ]; then rm -rf $remote_gen_q; fi" ||
    log "WARNING: could not clean remote staging leftovers on $dest"
}

# Abort after sync failures when STRICT is on (optional backoff avoids Docker restart storms).
strict_sync_fail() {
  backoff="${CERT_SYNC_FAIL_BACKOFF_SECONDS:-60}"
  case "$backoff" in
    '' | *[!0-9]*) backoff=60 ;;
  esac
  if [ "$backoff" -gt 0 ]; then
    log "CERT_SYNC_STRICT=1: backing off ${backoff}s before exit (set CERT_SYNC_FAIL_BACKOFF_SECONDS=0 to disable)"
    interruptible_sleep "$backoff"
  fi
  fail "CERT_SYNC_STRICT=1: one or more SSH sync targets failed"
}

distribute() {
  [ -n "$CERT_SYNC_HOSTS" ] || return 0
  provider_local="$DYNAMIC_DIR/$PROVIDER_FILE"
  publish_script="$(remote_publish_script_path)"
  sync_failed=0
  # Unique staging suffix per distribute() invocation (avoids peer collisions).
  stage_id="$$.$(date +%s)"
  gen_name="${GEN_PREFIX}${stage_id}"
  local_fp="$(leaf_cert_fingerprint "$CERT_DIR/$CERT_NAME.cert" || true)"
  set -f
  for host in $CERT_SYNC_HOSTS; do
    dest="$CERT_SYNC_SSH_USER@$host"
    remote_cert="$REMOTE_CERT_DIR/$CERT_NAME.cert"
    remote_key="$REMOTE_CERT_DIR/$CERT_NAME.key"
    remote_provider="$REMOTE_DYNAMIC_DIR/$PROVIDER_FILE"
    remote_cert_tmp="$remote_cert.tmp.$stage_id"
    remote_key_tmp="$remote_key.tmp.$stage_id"
    remote_provider_tmp="$remote_provider.tmp.$stage_id"
    remote_script_tmp="$REMOTE_CERT_DIR/.coolify-ssl-remote-publish.$stage_id"
    remote_gen="$REMOTE_CERT_DIR/$gen_name"

    remote_cert_q="$(shell_quote "$remote_cert")"
    remote_cert_tmp_q="$(shell_quote "$remote_cert_tmp")"
    remote_key_tmp_q="$(shell_quote "$remote_key_tmp")"
    remote_provider_tmp_q="$(shell_quote "$remote_provider_tmp")"
    remote_script_tmp_q="$(shell_quote "$remote_script_tmp")"
    remote_gen_q="$(shell_quote "$remote_gen")"

    # Skip when remote already has the same leaf (DER fingerprint match).
    # Requires openssl on the peer; if missing, check fails open and sync proceeds.
    if [ -n "$local_fp" ] && remote_leaf_fingerprint_matches "$dest" "$remote_cert_q" "$local_fp"; then
      log "skip sync to $host (remote leaf fingerprint matches)"
      continue
    fi

    # Build a single remote argv string: sh <script> <9 args> (all shell-quoted).
    remote_cmd="sh $(shell_quote "$remote_script_tmp") $(shell_quote "$REMOTE_CERT_DIR") $(shell_quote "$CERT_NAME") $(shell_quote "$gen_name") $(shell_quote "$remote_cert_tmp") $(shell_quote "$remote_key_tmp") $(shell_quote "$remote_provider_tmp") $(shell_quote "$remote_provider") $(shell_quote "$LEAF_LINK_NAME") $(shell_quote "$GEN_PREFIX")"

    log "distributing leaf to $dest"
    if ! scp_run -P "$CERT_SYNC_SSH_PORT" \
        "$CERT_DIR/$CERT_NAME.cert" "$dest:$remote_cert_tmp"; then
      log "ERROR: scp cert failed for $host"
      cleanup_remote_tmps "$dest" "$remote_cert_tmp_q" "$remote_key_tmp_q" "$remote_provider_tmp_q" "$remote_gen_q" "$remote_script_tmp_q"
      sync_failed=1
      continue
    fi
    if ! scp_run -P "$CERT_SYNC_SSH_PORT" \
        "$CERT_DIR/$CERT_NAME.key" "$dest:$remote_key_tmp"; then
      log "ERROR: scp key failed for $host"
      cleanup_remote_tmps "$dest" "$remote_cert_tmp_q" "$remote_key_tmp_q" "$remote_provider_tmp_q" "$remote_gen_q" "$remote_script_tmp_q"
      sync_failed=1
      continue
    fi
    if ! scp_run -P "$CERT_SYNC_SSH_PORT" \
        "$provider_local" "$dest:$remote_provider_tmp"; then
      log "ERROR: scp provider failed for $host"
      cleanup_remote_tmps "$dest" "$remote_cert_tmp_q" "$remote_key_tmp_q" "$remote_provider_tmp_q" "$remote_gen_q" "$remote_script_tmp_q"
      sync_failed=1
      continue
    fi
    if ! scp_run -P "$CERT_SYNC_SSH_PORT" \
        "$publish_script" "$dest:$remote_script_tmp"; then
      log "ERROR: scp remote-publish.sh failed for $host"
      cleanup_remote_tmps "$dest" "$remote_cert_tmp_q" "$remote_key_tmp_q" "$remote_provider_tmp_q" "$remote_gen_q" "$remote_script_tmp_q"
      sync_failed=1
      continue
    fi
    if ! ssh_run -p "$CERT_SYNC_SSH_PORT" "$dest" "$remote_cmd"; then
      log "ERROR: remote-publish.sh failed for $host"
      cleanup_remote_tmps "$dest" "$remote_cert_tmp_q" "$remote_key_tmp_q" "$remote_provider_tmp_q" "$remote_gen_q" "$remote_script_tmp_q"
      sync_failed=1
      continue
    fi
    # Best-effort: drop the staged script after success (leaf/provider already live).
    ssh_run -p "$CERT_SYNC_SSH_PORT" "$dest" "rm -f $remote_script_tmp_q" || true
    log "distribution OK to $host (provider updated; Traefik reloads if file watch is enabled)"
  done
  set +f

  if [ "$sync_failed" -ne 0 ]; then
    if cert_sync_strict_enabled; then
      strict_sync_fail
    fi
    log "WARNING: one or more SSH sync targets failed (CERT_SYNC_STRICT is off)"
  fi
}
