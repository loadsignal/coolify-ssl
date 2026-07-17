#!/bin/sh
# Unit tests for generate-certs.sh (domains, SSH key resolve, Traefik provider).
set -eu

TESTS_DIR="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
. "$TESTS_DIR/helpers.sh"

setup_tmp
trap cleanup_tmp EXIT

# Override defaults before sourcing the script under test.
export CERT_DIR DYNAMIC_DIR CAROOT DOMAINS_FILE PROVIDER_TEMPLATE
export CERT_NAME PROVIDER_FILE
export CERT_SYNC_HOSTS CERT_SYNC_SSH_KEY_PATH SSL_DOMAINS
export SSH_KNOWN_HOSTS_FILE CERT_SYNC_STRICT REMOTE_CERT_DIR REMOTE_DYNAMIC_DIR
export RUNTIME_DIR SSH_KEY_RUNTIME RENEW_INTERVAL_SECONDS MAX_DOMAINS
export CHECK_INTERVAL_SECONDS RENEW_BEFORE_EXPIRY_SECONDS
# Avoid installing into the OS trust store during tests (CA still written to CAROOT).
export TRUST_STORES=java

# shellcheck source=../generate-certs.sh
. "$TESTS_DIR/../generate-certs.sh"

# --- validate_config / charset ---

CERT_NAME="lan"
PROVIDER_FILE="local-certs.yaml"
REMOTE_CERT_DIR="/data/coolify/proxy/certs"
REMOTE_DYNAMIC_DIR="/data/coolify/proxy/dynamic"
CERT_SYNC_SSH_USER="root"
CERT_SYNC_SSH_PORT="22"
CERT_SYNC_STRICT="0"
RENEW_INTERVAL_SECONDS="2592000"
CHECK_INTERVAL_SECONDS=""
RENEW_BEFORE_EXPIRY_SECONDS=""
# validate_config must run in this shell so resolve_intervals assignments persist.
validate_config
assert_eq "2592000" "$CHECK_INTERVAL_SECONDS" "legacy fills CHECK_INTERVAL_SECONDS"
assert_eq "2592000" "$RENEW_BEFORE_EXPIRY_SECONDS" "legacy fills RENEW_BEFORE_EXPIRY_SECONDS"
assert_ok "validate_config after legacy resolve" validate_config

CERT_NAME="lan;rm"
assert_fails "reject CERT_NAME with metachar" validate_config
CERT_NAME="lan"

CERT_NAME="../etc"
assert_fails "reject CERT_NAME path traversal" validate_config
CERT_NAME="lan"

REMOTE_CERT_DIR="/tmp/certs;evil"
assert_fails "reject REMOTE_CERT_DIR metachar" validate_config
REMOTE_CERT_DIR="/data/coolify/proxy/certs"

REMOTE_CERT_DIR="relative/path"
assert_fails "reject relative REMOTE_CERT_DIR" validate_config
REMOTE_CERT_DIR="/data/coolify/proxy/certs"

# Decoupled intervals
CHECK_INTERVAL_SECONDS="59"
RENEW_BEFORE_EXPIRY_SECONDS="3600"
assert_fails "reject CHECK_INTERVAL_SECONDS below 60" validate_config
CHECK_INTERVAL_SECONDS="3600"
RENEW_BEFORE_EXPIRY_SECONDS="59"
assert_fails "reject RENEW_BEFORE_EXPIRY_SECONDS below 60" validate_config
CHECK_INTERVAL_SECONDS="3600"
RENEW_BEFORE_EXPIRY_SECONDS="86400"
validate_config
assert_eq "3600" "$CHECK_INTERVAL_SECONDS" "CHECK_INTERVAL_SECONDS preserved"
assert_eq "86400" "$RENEW_BEFORE_EXPIRY_SECONDS" "RENEW_BEFORE_EXPIRY_SECONDS preserved"

# Legacy alone still works
CHECK_INTERVAL_SECONDS=""
RENEW_BEFORE_EXPIRY_SECONDS=""
RENEW_INTERVAL_SECONDS="60"
validate_config
assert_eq "60" "$CHECK_INTERVAL_SECONDS" "legacy RENEW_INTERVAL_SECONDS=60 fills check"
assert_eq "60" "$RENEW_BEFORE_EXPIRY_SECONDS" "legacy RENEW_INTERVAL_SECONDS=60 fills renew-before"
RENEW_INTERVAL_SECONDS="315360001"
CHECK_INTERVAL_SECONDS=""
RENEW_BEFORE_EXPIRY_SECONDS=""
assert_fails "reject legacy RENEW_INTERVAL_SECONDS above max" validate_config
RENEW_INTERVAL_SECONDS="2592000"
CHECK_INTERVAL_SECONDS="2592000"
RENEW_BEFORE_EXPIRY_SECONDS="2592000"

MAX_DOMAINS="0"
assert_fails "reject MAX_DOMAINS=0" validate_config
MAX_DOMAINS="257"
assert_fails "reject MAX_DOMAINS above 256" validate_config
MAX_DOMAINS="64"
assert_ok "accept MAX_DOMAINS=64" validate_config

assert_ok "valid domain" validate_domain_or_host domain "app.example.lan"
assert_ok "valid wildcard" validate_domain_or_host domain "*.app.example.lan"
assert_ok "valid ipv4" validate_domain_or_host domain "10.0.0.4"
assert_ok "valid ipv6" validate_domain_or_host domain "2001:db8::1"
assert_ok "valid ipv6 loopback" validate_domain_or_host domain "::1"
assert_ok "valid ipv6 unspecified" validate_domain_or_host domain "::"
assert_ok "valid ipv6 full form" validate_domain_or_host domain "1:2:3:4:5:6:7:8"
assert_fails "reject ipv6 with 9 hextets" validate_domain_or_host domain "1:2:3:4:5:6:7:8:9"
assert_fails "reject ipv6 oversized hextet" validate_domain_or_host domain "12345::1"
assert_fails "reject ipv6 double compression" validate_domain_or_host domain "1::2::3"
assert_fails "reject ipv6 zone id" validate_domain_or_host domain "fe80::1%eth0"
assert_fails "reject ipv6 with too many explicit hextets around ::" validate_domain_or_host domain "1:2:3:4:5:6:7:8::"
assert_fails "reject injection domain" validate_domain_or_host domain "app.lan;evil"
assert_fails "reject bare wildcard TLD" validate_domain_or_host domain "*.lan"
assert_fails "reject mid wildcard" validate_domain_or_host domain "foo.*.lan"
assert_fails "reject invalid ipv4 octet" validate_domain_or_host domain "999.999.999.999"
assert_fails "reject leading hyphen hostname" validate_domain_or_host domain "-bad.lan"
assert_fails "reject trailing hyphen label" validate_domain_or_host domain "bad-.lan"

quoted="$(shell_quote "path/with'quote")"
assert_eq "'path/with'\\''quote'" "$quoted" "shell_quote escapes single quotes"

# --- canonicalize_san (IPv6/IPv4/DNS) ---
assert_eq "2001:DB8:0:0:0:0:0:1" "$(canonicalize_san '2001:db8::1')" "canonicalize compressed IPv6"
assert_eq "0:0:0:0:0:0:0:1" "$(canonicalize_san '::1')" "canonicalize loopback IPv6"
assert_eq "0:0:0:0:0:0:0:0" "$(canonicalize_san '::')" "canonicalize unspecified IPv6"
assert_eq "2001:DB8:0:0:0:0:0:1" "$(canonicalize_san '2001:DB8:0:0:0:0:0:1')" "canonicalize already-expanded IPv6"
assert_eq "10.0.0.4" "$(canonicalize_san '10.0.0.4')" "canonicalize IPv4 unchanged"
assert_eq "app.example.lan" "$(canonicalize_san 'App.Example.LAN')" "canonicalize DNS lowercase"
assert_eq "*.tools.lan" "$(canonicalize_san '*.Tools.LAN')" "canonicalize wildcard lowercase"

# --- read_domains ---

printf '# comment\ncoolify.lan\ngrafana.lan  # inline\n\n*.tools.lan\n' >"$DOMAINS_FILE"
SSL_DOMAINS=""
read_domains
assert_eq "coolify.lan grafana.lan *.tools.lan" "$DOMAINS_ARGS" "domains from file (comments/blanks)"

rm -f "$DOMAINS_FILE"
: >"$DOMAINS_FILE" # empty file → fall through to SSL_DOMAINS
SSL_DOMAINS="a.lan,b.lan
c.lan"
read_domains
assert_eq "a.lan b.lan c.lan" "$DOMAINS_ARGS" "domains from SSL_DOMAINS (commas/newlines)"

rm -f "$DOMAINS_FILE"
SSL_DOMAINS=""
assert_fails "no domains configured" read_domains

printf '   \n# only comments\n' >"$DOMAINS_FILE"
SSL_DOMAINS=""
assert_fails "domains file with no tokens" read_domains

# File Mount wins over SSL_DOMAINS when non-empty
printf 'from-file.lan\n' >"$DOMAINS_FILE"
SSL_DOMAINS="from-env.lan"
read_domains
assert_eq "from-file.lan" "$DOMAINS_ARGS" "non-empty domains file beats SSL_DOMAINS"

printf 'good.lan\nbad;host\n' >"$DOMAINS_FILE"
SSL_DOMAINS=""
assert_fails "reject malicious domain in file" read_domains

# Too many SANs
i=1
: >"$DOMAINS_FILE"
while [ "$i" -le 65 ]; do
  printf 'host%d.lan\n' "$i" >>"$DOMAINS_FILE"
  i=$((i + 1))
done
SSL_DOMAINS=""
MAX_DOMAINS=64
assert_fails "reject more than MAX_DOMAINS SANs" read_domains
MAX_DOMAINS=64
printf 'ok.lan\n' >"$DOMAINS_FILE"
read_domains
assert_eq "ok.lan" "$DOMAINS_ARGS" "accept within MAX_DOMAINS"

# --- write_traefik_provider ---

CERT_NAME="lan"
write_traefik_provider
assert_file_exists "$DYNAMIC_DIR/local-certs.yaml"
provider="$(cat "$DYNAMIC_DIR/local-certs.yaml")"
assert_contains "$provider" "/traefik/certs/lan.cert" "provider cert path"
assert_contains "$provider" "/traefik/certs/lan.key" "provider key path"

CERT_NAME="custom"
write_traefik_provider
provider="$(cat "$DYNAMIC_DIR/local-certs.yaml")"
assert_contains "$provider" "/traefik/certs/custom.cert" "provider uses CERT_NAME"

# Fallback when template missing
rm -f "$PROVIDER_TEMPLATE"
CERT_NAME="fallback"
write_traefik_provider
provider="$(cat "$DYNAMIC_DIR/local-certs.yaml")"
assert_contains "$provider" "fallback.cert" "inline provider fallback"
# restore template for later tests
cp "$TESTS_DIR/../traefik-dynamic.yaml.tpl" "$PROVIDER_TEMPLATE"
CERT_NAME="lan"

# --- resolve_ssh_key_file (runtime single-key only) ---

printf 'direct-key\n' >"$RUNTIME_DIR/sync.key"
chmod 600 "$RUNTIME_DIR/sync.key"
resolve_ssh_key_file "$RUNTIME_DIR/sync.key"
assert_eq "$RUNTIME_DIR/sync.key" "$SSH_KEY_RESOLVED" "accept single-key runtime mount path"

assert_fails "reject path traversal" resolve_ssh_key_file "$RUNTIME_DIR/../etc/passwd"
assert_fails "reject legacy host keys path" resolve_ssh_key_file "/data/coolify/ssh/keys/ssh_key@abc"
assert_fails "reject path outside runtime dir" resolve_ssh_key_file "/etc/passwd"
assert_fails "reject bare basename" resolve_ssh_key_file "ssh_key@abc"
assert_fails "reject missing key" resolve_ssh_key_file "$RUNTIME_DIR/missing-key"

# --- setup_ssh_key ---

CERT_SYNC_HOSTS=""
assert_ok "setup_ssh_key no-op without CERT_SYNC_HOSTS" setup_ssh_key

CERT_SYNC_HOSTS="10.0.0.5"
CERT_SYNC_SSH_KEY_PATH=""
assert_fails "CERT_SYNC_HOSTS without key path" setup_ssh_key

CERT_SYNC_SSH_KEY_PATH="$RUNTIME_DIR/sync.key"
rm -f "$SSH_KNOWN_HOSTS_FILE"
assert_fails "setup_ssh_key requires known_hosts" setup_ssh_key

printf 'peer ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForUnitTests\n' >"$SSH_KNOWN_HOSTS_FILE"
CERT_SYNC_SSH_USER=root
setup_log="$(setup_ssh_key 2>&1)"
assert_contains "$setup_log" "WARNING: CERT_SYNC_SSH_USER=root" "warn when sync user is root"
assert_file_exists "$SSH_KEY_RUNTIME" "runtime key copy created"
perms="$(stat -f '%Lp' "$SSH_KEY_RUNTIME" 2>/dev/null || stat -c '%a' "$SSH_KEY_RUNTIME")"
assert_eq "600" "$perms" "runtime key mode 600"
runtime_perms="$(stat -f '%Lp' "$RUNTIME_DIR" 2>/dev/null || stat -c '%a' "$RUNTIME_DIR")"
assert_eq "700" "$runtime_perms" "runtime dir mode 700"

CERT_SYNC_HOSTS="10.0.0.5;rm"
assert_fails "reject malicious CERT_SYNC_HOSTS" setup_ssh_key
CERT_SYNC_HOSTS="2001:db8::1"
assert_fails "reject ipv6 CERT_SYNC_HOSTS" setup_ssh_key

# Commas / newlines normalized like SSL_DOMAINS
CERT_SYNC_HOSTS="10.0.0.5, 10.0.0.6"
setup_ssh_key
assert_eq "10.0.0.5 10.0.0.6" "$CERT_SYNC_HOSTS" "CERT_SYNC_HOSTS commas/spaces normalized"
CERT_SYNC_HOSTS="10.0.0.5"

# --- generate: DNS wildcards must not pathname-expand ---

mkdir -p "$TMPROOT/bin" "$TMPROOT/cwd"
cat >"$TMPROOT/bin/mkcert" <<EOF
#!/bin/sh
set -eu
args_file="$TMPROOT/mkcert-args"
: >"\$args_file"
cert_out=""
key_out=""
while [ "\$#" -gt 0 ]; do
  case "\$1" in
    -cert-file) cert_out="\$2"; shift 2 ;;
    -key-file) key_out="\$2"; shift 2 ;;
    -*) shift ;;
    *) printf '%s\n' "\$1" >>"\$args_file"; shift ;;
  esac
done
[ -n "\$cert_out" ] && [ -n "\$key_out" ] || exit 1
printf 'stub-cert\n' >"\$cert_out"
printf 'stub-key\n' >"\$key_out"
EOF
chmod +x "$TMPROOT/bin/mkcert"

printf 'app.lan\n*.tools.lan\n' >"$DOMAINS_FILE"
SSL_DOMAINS=""
read_domains
assert_eq "app.lan *.tools.lan" "$DOMAINS_ARGS" "wildcard preserved in DOMAINS_ARGS"

# Matching cwd files would expand *.tools.lan without noglob in generate().
cd "$TMPROOT/cwd"
touch matching.tools.lan other.tools.lan
PATH="$TMPROOT/bin:$PATH"
generate
cd "$TMPROOT"

assert_file_exists "$TMPROOT/mkcert-args" "stub mkcert recorded args"
assert_eq "app.lan
*.tools.lan" "$(cat "$TMPROOT/mkcert-args")" "mkcert received literal wildcard SAN (no glob)"
assert_file_exists "$CERT_DIR/lan.cert" "stub leaf cert written"
assert_file_exists "$CERT_DIR/lan.key" "stub leaf key written"
if [ -L "$CERT_DIR/lan.cert" ] && [ -L "$CERT_DIR/lan.key" ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: leaf paths should be symlinks into .leaf/\n'
fi
if [ -L "$CERT_DIR/.leaf" ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: .leaf generation symlink missing\n'
fi
leftover_stage="$(find "$CERT_DIR" -type d \( -name '.coolify-ssl-stage.*' -o -name '.gen.*' \) 2>/dev/null | wc -l | tr -d ' ')"
# Exactly one active generation directory should remain.
assert_eq "1" "$leftover_stage" "exactly one leaf generation after generate"

# --- cleanup_orphan_stages ---

mkdir -p "$CERT_DIR/.coolify-ssl-stage.99999" "$CERT_DIR/.coolify-ssl-stage.88888"
printf 'orphan-key\n' >"$CERT_DIR/.coolify-ssl-stage.99999/lan.key"
printf 'orphan-key\n' >"$CERT_DIR/.coolify-ssl-stage.88888/lan.key"
# Extra aborted generation (not pointed by .leaf)
mkdir -p "$CERT_DIR/.gen.orphan.old"
printf 'old\n' >"$CERT_DIR/.gen.orphan.old/lan.key"
cleanup_orphan_stages
orphan_left="$(find "$CERT_DIR" -type d -name '.coolify-ssl-stage.*' 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "0" "$orphan_left" "cleanup_orphan_stages removes leftover stage dirs"
orphan_gen="$(find "$CERT_DIR" -type d -name '.gen.orphan.old' 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "0" "$orphan_gen" "cleanup_orphan_stages prunes non-active generations"
assert_ok "cleanup_orphan_stages is no-op when clean" cleanup_orphan_stages

# --- migrate flat leaf ---
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"
printf 'flat-cert\n' >"$CERT_DIR/lan.cert"
printf 'flat-key\n' >"$CERT_DIR/lan.key"
migrate_flat_leaf_if_needed
assert_eq "flat-cert" "$(cat "$CERT_DIR/lan.cert")" "migrated leaf cert readable via stable path"
assert_eq "flat-key" "$(cat "$CERT_DIR/lan.key")" "migrated leaf key readable via stable path"
if [ -L "$CERT_DIR/lan.cert" ] && [ -L "$CERT_DIR/.leaf" ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: migrate_flat_leaf_if_needed should install symlink layout\n'
fi

# Hybrid leaf (one symlink, one flat) must fail hard
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"
printf 'flat-key\n' >"$CERT_DIR/lan.key"
ln -s "somewhere" "$CERT_DIR/lan.cert"
assert_fails "reject hybrid leaf layout" migrate_flat_leaf_if_needed

# Prune must refuse to follow a .gen.* symlink outside CERT_DIR
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR" "$TMPROOT/precious-unit"
printf 'keep\n' >"$TMPROOT/precious-unit/file"
mkdir -p "$CERT_DIR/.gen.active"
printf 'c\n' >"$CERT_DIR/.gen.active/lan.cert"
printf 'k\n' >"$CERT_DIR/.gen.active/lan.key"
ln -sfn .gen.active "$CERT_DIR/.leaf"
ensure_leaf_name_symlinks
ln -s "$TMPROOT/precious-unit" "$CERT_DIR/.gen.evil"
prune_old_generations
assert_file_exists "$TMPROOT/precious-unit/file" "local prune must not follow .gen symlink"
if [ -L "$CERT_DIR/.gen.evil" ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  printf 'FAIL: .gen.evil symlink should be skipped, not removed via follow\n'
fi

# --- needs_renewal (stub leaf without real openssl material) ---

rm -f "$CERT_DIR/lan.cert" "$CERT_DIR/lan.key"
DOMAINS_ARGS="app.lan *.tools.lan"
assert_ok "needs_renewal when leaf missing" needs_renewal

# --- acquire_instance_lock (single writer) ---

LOCK_FILE="$CERT_DIR/.coolify-ssl.lock"
acquire_instance_lock
if command -v flock >/dev/null 2>&1; then
  assert_file_exists "$LOCK_FILE" "lock file created (flock)"
  assert_fails "second writer cannot take same flock" \
    sh -c "exec 8>\"$LOCK_FILE\" && flock -n 8"
else
  assert_file_exists "${LOCK_FILE}.d" "lock dir created (mkdir fallback)"
  assert_fails "second writer cannot take same mkdir lock" \
    mkdir "${LOCK_FILE}.d"
fi
# Release mkdir fallback before switching LOCK_FILE (flock path: reopen FD 9).
release_instance_lock
# Drop flock FD if held so the next acquire can target another path cleanly.
exec 9>&- 2>/dev/null || true
LOCK_FILE="$CERT_DIR/.coolify-ssl-other.lock"
acquire_instance_lock
if command -v flock >/dev/null 2>&1; then
  assert_file_exists "$LOCK_FILE" "alternate LOCK_FILE accepted"
else
  assert_file_exists "${LOCK_FILE}.d" "alternate LOCK_FILE dir accepted"
fi
release_instance_lock
exec 9>&- 2>/dev/null || true

# --- TRUST_STORES default for CA bootstrap ---

unset TRUST_STORES || true
# resolve_caroot sets default before mkcert; reuse existing CA path without reinstall.
mkdir -p "$CAROOT"
printf 'placeholder\n' >"$CAROOT/rootCA.pem"
printf 'placeholder\n' >"$CAROOT/rootCA-key.pem"
resolve_caroot
assert_eq "java" "$TRUST_STORES" "TRUST_STORES defaults to java when unset"

# --- cert_sync_strict ---

CERT_SYNC_STRICT=1
assert_ok "strict mode enabled" cert_sync_strict_enabled
CERT_SYNC_STRICT=0
assert_fails "strict mode disabled" cert_sync_strict_enabled

print_summary
