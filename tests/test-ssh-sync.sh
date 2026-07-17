#!/bin/sh
# SSH leaf sync tests with stub ssh/scp (no real sshd required).
set -eu

TESTS_DIR="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
. "$TESTS_DIR/helpers.sh"

setup_tmp
trap cleanup_tmp EXIT

export CERT_DIR DYNAMIC_DIR CAROOT DOMAINS_FILE PROVIDER_TEMPLATE
export CERT_NAME PROVIDER_FILE
export CERT_SYNC_HOSTS CERT_SYNC_SSH_KEY_PATH SSL_DOMAINS
export SSH_KNOWN_HOSTS_FILE CERT_SYNC_STRICT REMOTE_CERT_DIR REMOTE_DYNAMIC_DIR
export RUNTIME_DIR SSH_KEY_RUNTIME RENEW_INTERVAL_SECONDS MAX_DOMAINS
export CHECK_INTERVAL_SECONDS RENEW_BEFORE_EXPIRY_SECONDS
export CERT_SYNC_SSH_USER CERT_SYNC_SSH_PORT
export CERT_SYNC_FAIL_BACKOFF_SECONDS=0
export TRUST_STORES=java
export REMOTE_PUBLISH_SCRIPT="$TESTS_DIR/../lib/remote-publish.sh"

# shellcheck source=../generate-certs.sh
. "$TESTS_DIR/../generate-certs.sh"

STUB_BIN="$TMPROOT/bin"
STUB_LOG="$TMPROOT/stub.log"
REMOTE_FS="$TMPROOT/remote-fs"
mkdir -p "$STUB_BIN" "$REMOTE_FS/data/coolify/proxy/certs" "$REMOTE_FS/data/coolify/proxy/dynamic"

cat >"$STUB_BIN/scp" <<EOF
#!/bin/sh
set -eu
printf 'SCP %s\n' "\$*" >>"$STUB_LOG"
src=""
dest=""
while [ "\$#" -gt 0 ]; do
  case "\$1" in
    -o|-i|-P|-F|-c|-S)
      shift
      [ "\$#" -gt 0 ] || exit 1
      shift
      ;;
    -*)
      shift
      ;;
    *)
      if [ -z "\$src" ]; then src="\$1"
      else dest="\$1"
      fi
      shift
      ;;
  esac
done
[ -n "\$src" ] && [ -n "\$dest" ] || { echo "stub scp: missing src/dest" >&2; exit 1; }
case "\$dest" in
  *:*)
    rpath="\${dest#*:}"
    case "\$rpath" in
      /*) out="$REMOTE_FS\$rpath" ;;
      *) out="$REMOTE_FS/\$rpath" ;;
    esac
    mkdir -p "\$(dirname "\$out")"
    cp "\$src" "\$out"
    ;;
  *)
    echo "stub scp: bad dest \$dest" >&2
    exit 1
    ;;
esac
EOF
chmod +x "$STUB_BIN/scp"

write_ssh_stub() {
  fail_publish="$1"
  cat >"$STUB_BIN/ssh" <<EOF
#!/bin/sh
set -eu
printf 'SSH %s\n' "\$*" >>"$STUB_LOG"
cmd=""
for a in "\$@"; do cmd="\$a"; done
# Fail only the publish invocation (sh …remote-publish…), not cleanup rm -f of the staged script.
case "\$cmd" in
  sh\ *coolify-ssl-remote-publish*|sh\ */remote-publish.sh*)
    if [ "$fail_publish" = "1" ]; then
      echo "stub ssh: remote-publish failed" >&2
      exit 1
    fi
    ;;
esac
# Rewrite Coolify paths onto the fake remote filesystem, then run.
rewritten=\$(printf '%s' "\$cmd" | sed "s|/data/|$REMOTE_FS/data/|g")
# shellcheck disable=SC2086
eval "\$rewritten"
EOF
  chmod +x "$STUB_BIN/ssh"
}

PATH="$STUB_BIN:$PATH"
write_ssh_stub 0

printf 'leaf-cert\n' >"$CERT_DIR/lan.cert"
printf 'leaf-key\n' >"$CERT_DIR/lan.key"
mkdir -p "$DYNAMIC_DIR"
printf 'tls: {}\n' >"$DYNAMIC_DIR/local-certs.yaml"

printf 'fake-key\n' >"$RUNTIME_DIR/sync.key"
chmod 600 "$RUNTIME_DIR/sync.key"
printf 'peer ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForUnitTests\n' >"$SSH_KNOWN_HOSTS_FILE"

CERT_SYNC_HOSTS="10.0.0.5"
CERT_SYNC_SSH_USER="root"
CERT_SYNC_SSH_PORT="22"
CERT_SYNC_SSH_KEY_PATH="$RUNTIME_DIR/sync.key"
CERT_SYNC_STRICT=0
SSH_KEY_RUNTIME="$RUNTIME_DIR/cert-sync-key"
cp "$RUNTIME_DIR/sync.key" "$SSH_KEY_RUNTIME"
chmod 600 "$SSH_KEY_RUNTIME"

# --- success path (use a real leaf so fingerprint skip works) ---
if command -v mkcert >/dev/null 2>&1; then
  export CAROOT TRUST_STORES=java
  mkdir -p "$CAROOT"
  mkcert -install >/dev/null 2>&1 || true
  mkcert -cert-file "$CERT_DIR/lan.cert" -key-file "$CERT_DIR/lan.key" sync-test.lan >/dev/null 2>&1
fi

: >"$STUB_LOG"
distribute
assert_file_exists "$REMOTE_FS/data/coolify/proxy/certs/lan.cert" "remote cert after success"
assert_file_exists "$REMOTE_FS/data/coolify/proxy/certs/lan.key" "remote key after success"
assert_file_exists "$REMOTE_FS/data/coolify/proxy/dynamic/local-certs.yaml" "remote provider after success"
if [ -L "$REMOTE_FS/data/coolify/proxy/certs/lan.cert" ] && [ -L "$REMOTE_FS/data/coolify/proxy/certs/.leaf" ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: remote leaf should use atomic .leaf symlink layout\n'
fi
tmp_left="$(find "$REMOTE_FS" \( -name '*.tmp*' -o -name '.coolify-ssl-remote-publish.*' \) 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "0" "$tmp_left" "no remote staging leftovers after success"
assert_contains "$(cat "$STUB_LOG")" ".tmp." "unique remote staging suffix used"
assert_contains "$(cat "$STUB_LOG")" "coolify-ssl-remote-publish" "remote-publish.sh scp'd and invoked"
assert_contains "$(cat "$STUB_LOG")" "remote-publish.sh" "publish script path present in scp/ssh log"

# --- skip when remote fingerprint already matches ---
if command -v mkcert >/dev/null 2>&1 && [ -s "$CERT_DIR/lan.cert" ]; then
  : >"$STUB_LOG"
  distribute
  scp_count="$(grep -c '^SCP ' "$STUB_LOG" || true)"
  assert_eq "0" "$scp_count" "no scp when remote fingerprint matches"
  assert_contains "$(cat "$STUB_LOG")" "openssl" "fingerprint check used openssl over ssh"
fi

# --- failure on remote-publish: staged .tmp must be cleaned ---
rm -f "$REMOTE_FS/data/coolify/proxy/certs/"* "$REMOTE_FS/data/coolify/proxy/dynamic/"* 2>/dev/null || true
rm -rf "$REMOTE_FS/data/coolify/proxy/certs/".* 2>/dev/null || true
mkdir -p "$REMOTE_FS/data/coolify/proxy/certs" "$REMOTE_FS/data/coolify/proxy/dynamic"
: >"$STUB_LOG"
write_ssh_stub 1

distribute
leftover="$(find "$REMOTE_FS" \( -name '*.tmp*' -o -name '.coolify-ssl-remote-publish.*' \) 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "0" "$leftover" "remote staging cleaned after publish failure"
assert_contains "$(cat "$STUB_LOG")" "rm -f" "cleanup invoked rm -f on failure"

if [ -e "$REMOTE_FS/data/coolify/proxy/certs/lan.cert" ]; then
  FAIL=$((FAIL + 1))
  printf 'FAIL: final remote cert should not exist after failed publish\n'
else
  PASS=$((PASS + 1))
fi

# --- CERT_SYNC_STRICT=1 aborts (backoff disabled for tests) ---
CERT_SYNC_STRICT=1
CERT_SYNC_FAIL_BACKOFF_SECONDS=0
assert_fails "strict mode aborts on sync failure" distribute
CERT_SYNC_STRICT=0

# --- sync still works when leaf already exists (no re-issue needed) ---
write_ssh_stub 0
rm -f "$REMOTE_FS/data/coolify/proxy/certs/"* "$REMOTE_FS/data/coolify/proxy/dynamic/"* 2>/dev/null || true
rm -rf "$REMOTE_FS/data/coolify/proxy/certs/".gen.* "$REMOTE_FS/data/coolify/proxy/certs/.leaf" 2>/dev/null || true
: >"$STUB_LOG"
# Opaque stub leaf (not a real PEM) — fingerprint check must not false-match empty DER.
printf 'local-leaf\n' >"$CERT_DIR/lan.cert"
printf 'local-key\n' >"$CERT_DIR/lan.key"
write_traefik_provider
distribute
assert_file_exists "$REMOTE_FS/data/coolify/proxy/certs/lan.cert" "sync succeeds without re-issue"
assert_eq "local-leaf" "$(cat "$REMOTE_FS/data/coolify/proxy/certs/lan.cert")" "peer receives current local leaf"
assert_contains "$(cat "$STUB_LOG")" "SCP " "stub leaf still scp'd when fingerprint unavailable"

# --- resolve single-key runtime path ---
resolve_ssh_key_file "$RUNTIME_DIR/sync.key"
assert_eq "$RUNTIME_DIR/sync.key" "$SSH_KEY_RESOLVED" "accept runtime single-key path"

# --- remote-publish.sh direct (no ssh) ---
rp_dir="$TMPROOT/rp-direct"
mkdir -p "$rp_dir/certs" "$rp_dir/dynamic"
printf 'direct-cert\n' >"$rp_dir/certs/lan.cert.tmp.1"
printf 'direct-key\n' >"$rp_dir/certs/lan.key.tmp.1"
printf 'tls: {}\n' >"$rp_dir/dynamic/local-certs.yaml.tmp.1"
sh "$REMOTE_PUBLISH_SCRIPT" \
  "$rp_dir/certs" lan .gen.direct \
  "$rp_dir/certs/lan.cert.tmp.1" "$rp_dir/certs/lan.key.tmp.1" \
  "$rp_dir/dynamic/local-certs.yaml.tmp.1" "$rp_dir/dynamic/local-certs.yaml" \
  .leaf .gen.
assert_eq "direct-cert" "$(cat "$rp_dir/certs/lan.cert")" "direct remote-publish cert"
assert_eq "direct-key" "$(cat "$rp_dir/certs/lan.key")" "direct remote-publish key"
if [ -L "$rp_dir/certs/lan.cert" ] && [ -L "$rp_dir/certs/.leaf" ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: direct remote-publish should install symlink layout\n'
fi

# Symlink prune must not follow / delete outside target
mkdir -p "$TMPROOT/precious"
printf 'keep\n' >"$TMPROOT/precious/file"
ln -s "$TMPROOT/precious" "$rp_dir/certs/.gen.evil-link"
# Create a second real generation then publish again so prune runs
printf 'c2\n' >"$rp_dir/certs/lan.cert.tmp.2"
printf 'k2\n' >"$rp_dir/certs/lan.key.tmp.2"
printf 'tls: {}\n' >"$rp_dir/dynamic/local-certs.yaml.tmp.2"
sh "$REMOTE_PUBLISH_SCRIPT" \
  "$rp_dir/certs" lan .gen.direct2 \
  "$rp_dir/certs/lan.cert.tmp.2" "$rp_dir/certs/lan.key.tmp.2" \
  "$rp_dir/dynamic/local-certs.yaml.tmp.2" "$rp_dir/dynamic/local-certs.yaml" \
  .leaf .gen. >/dev/null 2>&1 || true
assert_file_exists "$TMPROOT/precious/file" "prune must not follow generation symlink outside cert_dir"
if [ -L "$rp_dir/certs/.gen.evil-link" ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: evil generation symlink should remain (skipped, not removed via rm -rf follow)\n'
fi

print_summary
