# shellcheck shell=sh
# mkcert CA bootstrap for coolify-ssl.

resolve_caroot() {
  caroot="${CAROOT:-/caroot}"
  mkdir -p "$caroot"
  export CAROOT="$caroot"
  # mkcert treats unset TRUST_STORES as "install into every store". Default to
  # java so -install still writes CAROOT material without mutating system/NSS
  # trust stores (clients install rootCA.pem explicitly — see README).
  export TRUST_STORES="${TRUST_STORES:-java}"
  cert="$caroot/rootCA.pem"
  key="$caroot/rootCA-key.pem"

  if [ -r "$cert" ] && [ -r "$key" ]; then
    log "reusing existing CA ($caroot)"
  elif [ ! -e "$cert" ] && [ ! -e "$key" ]; then
    log "no CA in $caroot — creating (mkcert -install, TRUST_STORES=$TRUST_STORES)"
    mkcert -install
    { [ -r "$cert" ] && [ -r "$key" ]; } || fail "mkcert -install did not produce a CA in $caroot"
    log "CA created ($caroot) — distribute rootCA.pem to clients (see README)"
  else
    fail "inconsistent CA state in $caroot (only one of rootCA.pem / rootCA-key.pem present)"
  fi

  if ! chmod 644 "$cert" 2>/dev/null; then
    log "WARNING: could not chmod 644 $cert (check volume mount permissions)"
  fi
  if ! chmod 600 "$key" 2>/dev/null; then
    log "WARNING: could not chmod 600 $key (check volume mount permissions)"
  fi
}
