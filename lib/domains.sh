# shellcheck shell=sh
# Domain list loading for coolify-ssl.

read_domains() {
  set --
  # Prevent pathname expansion of wildcards like *.example.lan.
  set -f
  if [ -s "$DOMAINS_FILE" ]; then
    while IFS= read -r line; do
      stripped="${line%%#*}"
      for token in $stripped; do set -- "$@" "$token"; done
    done <"$DOMAINS_FILE"
    source_description="$DOMAINS_FILE"
  elif [ -n "${SSL_DOMAINS:-}" ]; then
    normalized="$(printf '%s' "$SSL_DOMAINS" | tr ',\n\r\t' '    ')"
    for token in $normalized; do set -- "$@" "$token"; done
    source_description="SSL_DOMAINS"
  else
    fail "no domains: set SSL_DOMAINS or mount a non-empty file at $DOMAINS_FILE"
  fi
  set +f
  [ "$#" -gt 0 ] || fail "no valid domains in $source_description"
  if [ "$#" -gt "$MAX_DOMAINS" ]; then
    fail "too many domains ($# > MAX_DOMAINS=$MAX_DOMAINS)"
  fi
  for token in "$@"; do
    validate_domain_or_host "domain" "$token"
  done
  # Consumed by leaf.sh / main when libraries are sourced together.
  # shellcheck disable=SC2034
  DOMAINS_ARGS="$*"
  log "domains loaded from $source_description"
}
