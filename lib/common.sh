# shellcheck shell=sh
# Shared logging, quoting, and signal helpers for coolify-ssl.

# Set by signal handlers so the renew loop can exit cleanly.
STOP_REQUESTED=0

log() { printf '%s ssl-gen: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
fail() { log "FATAL: $*"; exit 1; }

on_signal() {
  STOP_REQUESTED=1
  log "signal received — will stop after current step"
}

# Single-quote for remote sh (POSIX; no bash printf %q).
shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# Sleep in ≤60s chunks so SIGTERM/SIGINT can stop without 1Hz wakeups for 30d intervals.
interruptible_sleep() {
  remaining="$1"
  while [ "$remaining" -gt 0 ]; do
    [ "$STOP_REQUESTED" -eq 0 ] || return 0
    chunk=60
    if [ "$remaining" -lt "$chunk" ]; then
      chunk="$remaining"
    fi
    sleep "$chunk"
    remaining=$((remaining - chunk))
  done
}

# Set when using the mkdir fallback so EXIT can remove the lock directory.
LOCK_DIR_HELD=

release_instance_lock() {
  if [ -n "${LOCK_DIR_HELD:-}" ] && [ -d "$LOCK_DIR_HELD" ]; then
    rm -rf "$LOCK_DIR_HELD"
  fi
  LOCK_DIR_HELD=
}

# Exclusive writer lock on CERT_DIR. Prefer flock (Alpine/BusyBox; released on
# process exit). Fall back to a mkdir lock dir when flock is unavailable (e.g.
# macOS hosts running tests). Prevents two coolify-ssl writers on the same mounts.
acquire_instance_lock() {
  lock_file="${LOCK_FILE:-$CERT_DIR/.coolify-ssl.lock}"
  case "$lock_file" in
    '' | *..*) fail "invalid LOCK_FILE '$lock_file'" ;;
  esac

  if command -v flock >/dev/null 2>&1; then
    # FD 9 held for the lifetime of this process.
    exec 9>"$lock_file" || fail "cannot open lock file $lock_file"
    if ! flock -n 9; then
      fail "another coolify-ssl instance holds $lock_file (only one writer per CERT_DIR / LOCK_FILE)"
    fi
    log "instance lock acquired ($lock_file via flock)"
    return 0
  fi

  lock_dir="${lock_file}.d"
  if mkdir "$lock_dir" 2>/dev/null; then
    printf '%s\n' "$$" >"$lock_dir/pid"
    LOCK_DIR_HELD="$lock_dir"
    log "instance lock acquired ($lock_dir via mkdir; flock not available)"
    return 0
  fi

  # Stale leftover from a crashed process (mkdir locks are not kernel-held).
  if [ -f "$lock_dir/pid" ]; then
    old_pid="$(cat "$lock_dir/pid" 2>/dev/null || true)"
    if [ -n "$old_pid" ] && ! kill -0 "$old_pid" 2>/dev/null; then
      log "WARNING: removing stale lock dir $lock_dir (pid $old_pid not running)"
      rm -rf "$lock_dir"
      if mkdir "$lock_dir" 2>/dev/null; then
        printf '%s\n' "$$" >"$lock_dir/pid"
        LOCK_DIR_HELD="$lock_dir"
        log "instance lock acquired ($lock_dir via mkdir after stale cleanup)"
        return 0
      fi
    fi
  fi

  fail "another coolify-ssl instance holds $lock_dir (only one writer per CERT_DIR / LOCK_FILE)"
}
