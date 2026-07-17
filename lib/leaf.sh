# shellcheck shell=sh
# Leaf cert generation, renewal checks, and atomic publish for coolify-ssl.
#
# Layout under CERT_DIR (Coolify-compatible stable names):
#   .gen.<id>/{CERT_NAME}.cert|key   — immutable generation
#   .leaf → .gen.<id>                — flipped atomically via ln -sfn
#   {CERT_NAME}.cert → .leaf/...     — stable paths Traefik already watches
# Flipping .leaf updates cert+key together; provider is written last.

LEAF_LINK_NAME=".leaf"
GEN_PREFIX=".gen."

# Install or replace a relative symlink at dest → target (works if dest is a regular file).
install_rel_symlink() {
  target="$1"
  dest="$2"
  if [ -L "$dest" ]; then
    ln -sfn "$target" "$dest"
  elif [ -e "$dest" ]; then
    rm -f "$dest"
    ln -s "$target" "$dest"
  else
    ln -s "$target" "$dest"
  fi
}

# Ensure CERT_NAME.cert / .key are symlinks into .leaf/ (Traefik keeps stable paths).
ensure_leaf_name_symlinks() {
  install_rel_symlink "${LEAF_LINK_NAME}/${CERT_NAME}.cert" "$CERT_DIR/${CERT_NAME}.cert"
  install_rel_symlink "${LEAF_LINK_NAME}/${CERT_NAME}.key" "$CERT_DIR/${CERT_NAME}.key"
}

# Remove a generation/stage directory only if it is a real directory (never follow symlinks).
safe_rm_tree() {
  path="$1"
  if [ -L "$path" ]; then
    log "WARNING: refusing to remove symlink $path"
    return 0
  fi
  if [ -d "$path" ]; then
    rm -rf "$path"
  elif [ -e "$path" ]; then
    rm -f "$path"
  fi
}

# Migrate pre-0.1 flat files into one generation so upgrades keep working.
migrate_flat_leaf_if_needed() {
  cert_path="$CERT_DIR/${CERT_NAME}.cert"
  key_path="$CERT_DIR/${CERT_NAME}.key"
  cert_link=0
  key_link=0
  [ -L "$cert_path" ] && cert_link=1
  [ -L "$key_path" ] && key_link=1
  if [ "$cert_link" -ne "$key_link" ]; then
    fail "inconsistent leaf layout: one of ${CERT_NAME}.cert / ${CERT_NAME}.key is a symlink and the other is not (repair or remove both under $CERT_DIR)"
  fi
  if [ "$cert_link" -eq 1 ]; then
    return 0
  fi
  if [ ! -f "$cert_path" ] || [ ! -f "$key_path" ]; then
    return 0
  fi
  gen_id="migrate.$$.$(date +%s)"
  gen_dir="$CERT_DIR/${GEN_PREFIX}${gen_id}"
  mkdir -p "$gen_dir"
  mv -f "$cert_path" "$gen_dir/${CERT_NAME}.cert"
  mv -f "$key_path" "$gen_dir/${CERT_NAME}.key"
  chmod 644 "$gen_dir/${CERT_NAME}.cert" 2>/dev/null || true
  chmod 600 "$gen_dir/${CERT_NAME}.key" 2>/dev/null || true
  ln -sfn "${GEN_PREFIX}${gen_id}" "$CERT_DIR/${LEAF_LINK_NAME}"
  ensure_leaf_name_symlinks
  log "migrated flat leaf into atomic generation ${GEN_PREFIX}${gen_id}"
}

prune_old_generations() {
  current=
  if [ -L "$CERT_DIR/${LEAF_LINK_NAME}" ]; then
    current="$(readlink "$CERT_DIR/${LEAF_LINK_NAME}" 2>/dev/null || true)"
  fi
  # Intentional unquoted glob after directory prefix (POSIX; no nullglob).
  # shellcheck disable=SC2231
  for d in "$CERT_DIR"/${GEN_PREFIX}*; do
    [ -e "$d" ] || continue
    if [ -L "$d" ]; then
      log "WARNING: skipping symlink during prune: $d"
      continue
    fi
    [ -d "$d" ] || continue
    base="$(basename "$d")"
    if [ -n "$current" ] && [ "$base" = "$current" ]; then
      continue
    fi
    log "removing old leaf generation: $d"
    safe_rm_tree "$d"
  done
}

# Remove leftover stage dirs / aborted generations (may contain private keys).
cleanup_orphan_stages() {
  mkdir -p "$CERT_DIR"
  # Glob stays literal when unmatched (no nullglob in POSIX sh).
  for d in "$CERT_DIR"/.coolify-ssl-stage.*; do
    [ -e "$d" ] || continue
    log "removing orphan stage dir: $d"
    safe_rm_tree "$d"
  done
  # Drop incomplete generations that are not the active .leaf target.
  if [ -L "$CERT_DIR/${LEAF_LINK_NAME}" ]; then
    prune_old_generations
  else
    # shellcheck disable=SC2231
    for d in "$CERT_DIR"/${GEN_PREFIX}*; do
      [ -e "$d" ] || continue
      log "removing orphan generation dir: $d"
      safe_rm_tree "$d"
    done
  fi
}

# Sorted unique configured SANs (one per line, canonicalized). Uses DOMAINS_ARGS.
configured_sans_list() {
  set -f
  # shellcheck disable=SC2086
  for san in $DOMAINS_ARGS; do
    canonicalize_san "$san"
  done | LC_ALL=C sort -u
  set +f
}

# Sorted unique SANs from an existing leaf cert (DNS / IP Address), canonicalized.
leaf_sans_list() {
  cert="$1"
  # Prefer -ext when available; fall back to -text for older openssl.
  text="$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null || true)"
  if [ -z "$text" ] || {
    ! printf '%s' "$text" | grep -q 'DNS:' && ! printf '%s' "$text" | grep -q 'IP Address:'
  }; then
    text="$(openssl x509 -in "$cert" -noout -text 2>/dev/null || true)"
  fi
  printf '%s\n' "$text" | tr ',' '\n' | sed -n \
    -e 's/^[[:space:]]*DNS://p' \
    -e 's/^[[:space:]]*IP Address://p' |
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
    grep -v '^$' |
    while IFS= read -r san; do
      canonicalize_san "$san"
    done | LC_ALL=C sort -u
}

# Return 0 when leaf SANs match configured domains (order-independent, canonical).
leaf_matches_domains() {
  cert="$CERT_DIR/$CERT_NAME.cert"
  [ -s "$cert" ] || return 1
  expected="$(configured_sans_list)"
  actual="$(leaf_sans_list "$cert")"
  [ -n "$expected" ] && [ "$expected" = "$actual" ]
}

# Return 0 when a new leaf should be issued (missing, mismatch, SAN drift, near expiry).
needs_renewal() {
  cert="$CERT_DIR/$CERT_NAME.cert"
  key="$CERT_DIR/$CERT_NAME.key"

  if [ ! -s "$cert" ] || [ ! -s "$key" ]; then
    log "renewal needed: leaf cert/key missing"
    return 0
  fi

  cert_pub="$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl sha256 2>/dev/null || true)"
  key_pub="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | openssl sha256 2>/dev/null || true)"
  if [ -z "$cert_pub" ] || [ -z "$key_pub" ] || [ "$cert_pub" != "$key_pub" ]; then
    log "renewal needed: leaf cert/key public key mismatch or unreadable"
    return 0
  fi

  if ! leaf_matches_domains; then
    log "renewal needed: SANs differ from configured domains"
    return 0
  fi

  if ! openssl x509 -in "$cert" -noout -checkend "$RENEW_BEFORE_EXPIRY_SECONDS" >/dev/null 2>&1; then
    log "renewal needed: leaf expires within ${RENEW_BEFORE_EXPIRY_SECONDS}s"
    return 0
  fi

  return 1
}

# SHA-256 hex of leaf cert DER (stable across PEM re-encoding). Empty/fails if unreadable.
# Note: `openssl sha256` hashes empty stdin successfully — always validate the cert first.
leaf_cert_fingerprint() {
  cert="$1"
  [ -s "$cert" ] || return 1
  openssl x509 -in "$cert" -noout >/dev/null 2>&1 || return 1
  openssl x509 -in "$cert" -outform DER 2>/dev/null | openssl sha256 2>/dev/null |
    awk '{print $NF}'
}

# Activate a fully written generation directory (atomic .leaf flip), then write provider.
publish_generation() {
  gen_dir="$1"
  gen_id="$2"
  staged_cert="$gen_dir/$CERT_NAME.cert"
  staged_key="$gen_dir/$CERT_NAME.key"
  [ -s "$staged_cert" ] && [ -s "$staged_key" ] || fail "staged leaf incomplete in $gen_dir"
  chmod 644 "$staged_cert"
  chmod 600 "$staged_key"

  # Point stable names at .leaf/ before flipping so Traefik always resolves a pair.
  ensure_leaf_name_symlinks
  ln -sfn "${GEN_PREFIX}${gen_id}" "$CERT_DIR/${LEAF_LINK_NAME}"
  prune_old_generations
  # Provider last: reload sees cert+key already consistent via .leaf.
  write_traefik_provider
}

generate() {
  mkdir -p "$CERT_DIR"
  migrate_flat_leaf_if_needed
  gen_id="$$.$(date +%s)"
  gen_dir="$CERT_DIR/${GEN_PREFIX}${gen_id}"
  safe_rm_tree "$gen_dir"
  mkdir -p "$gen_dir"
  cert_tmp="$gen_dir/$CERT_NAME.cert"
  key_tmp="$gen_dir/$CERT_NAME.key"

  # Validated charset; word-split required for mkcert SAN args.
  # Keep noglob on: DNS wildcards like *.tools.lan must not expand against cwd.
  set -f
  # shellcheck disable=SC2086
  if ! mkcert -cert-file "$cert_tmp" -key-file "$key_tmp" $DOMAINS_ARGS; then
    set +f
    safe_rm_tree "$gen_dir"
    fail "mkcert failed"
  fi
  set +f
  publish_generation "$gen_dir" "$gen_id"
  log "certificate generated ($CERT_DIR/$CERT_NAME.cert) for: $DOMAINS_ARGS"
}

# Backward-compatible name used by older comments/tests mental model.
publish_leaf_pair() {
  stage_dir="$1"
  gen_id="$$.$(date +%s)"
  gen_dir="$CERT_DIR/${GEN_PREFIX}${gen_id}"
  mkdir -p "$gen_dir"
  mv -f "$stage_dir/$CERT_NAME.cert" "$gen_dir/$CERT_NAME.cert"
  mv -f "$stage_dir/$CERT_NAME.key" "$gen_dir/$CERT_NAME.key"
  if [ -L "$stage_dir" ]; then
    log "WARNING: refusing to remove symlink stage $stage_dir"
  else
    rmdir "$stage_dir" 2>/dev/null || safe_rm_tree "$stage_dir"
  fi
  publish_generation "$gen_dir" "$gen_id"
}
