# shellcheck shell=sh
# SAN / host validation and canonicalization for coolify-ssl.

# Return 0 if $1 is a dotted IPv4 with each octet in 0-255.
is_ipv4() {
  value="$1"
  case "$value" in
    *[!0-9.]* | '' | .* | *.) return 1 ;;
  esac
  dots=$(printf '%s' "$value" | tr -cd '.' | wc -c | tr -d ' ')
  [ "$dots" -eq 3 ] || return 1
  o1="${value%%.*}"
  rest="${value#*.}"
  o2="${rest%%.*}"
  rest="${rest#*.}"
  o3="${rest%%.*}"
  o4="${rest#*.}"
  case "$o4" in
    *.*) return 1 ;;
  esac
  for o in "$o1" "$o2" "$o3" "$o4"; do
    case "$o" in
      '' | *[!0-9]*) return 1 ;;
    esac
    # Reject leading zeros like 01 (except single 0).
    case "$o" in
      0) ;;
      0*) return 1 ;;
    esac
    if [ "$o" -gt 255 ]; then
      return 1
    fi
  done
  return 0
}

# Validate one IPv6 hextet group (colon-separated, no compression). Sets HEXTETS.
# Empty string → 0 hextets. Rejects empty slots and hextets longer than 4 hex digits.
ipv6_count_hextets() {
  side="$1"
  HEXTETS=0
  if [ -z "$side" ]; then
    return 0
  fi
  case "$side" in
    :* | *:) return 1 ;;
  esac
  old_ifs=$IFS
  set -f
  IFS=:
  # shellcheck disable=SC2086
  set -- $side
  IFS=$old_ifs
  set +f
  for h in "$@"; do
    case "$h" in
      '' | *[!0-9A-Fa-f]*) return 1 ;;
    esac
    len=$(printf '%s' "$h" | wc -c | tr -d ' ')
    [ "$len" -ge 1 ] && [ "$len" -le 4 ] || return 1
    HEXTETS=$((HEXTETS + 1))
  done
  return 0
}

# Conservative IPv6 check (hex + colons only; at most one ::; ≤8 hextets expanded).
# Rejects zone IDs, dotted embedded IPv4, oversized hextets, and >8 hextets.
is_ipv6() {
  value="$1"
  case "$value" in
    *[!0-9A-Fa-f:]* | '' | *:::*) return 1 ;;
  esac
  # Must contain a colon (distinguish from bare hex labels).
  case "$value" in
    *:*) ;;
    *) return 1 ;;
  esac

  compressed=0
  left=$value
  right=
  case "$value" in
    *::*)
      compressed=1
      left="${value%%::*}"
      right="${value#*::}"
      case "$right" in
        *::*) return 1 ;;
      esac
      ;;
  esac

  ipv6_count_hextets "$left" || return 1
  left_n=$HEXTETS
  ipv6_count_hextets "$right" || return 1
  right_n=$HEXTETS
  total=$((left_n + right_n))

  if [ "$compressed" -eq 1 ]; then
    # :: stands for at least one zero hextet → at most 7 explicit hextets.
    [ "$total" -le 7 ] || return 1
  else
    [ "$total" -eq 8 ] || return 1
  fi
  return 0
}

# Expand IPv6 to OpenSSL-like form: 8 uppercase hextets, no compression, no leading zeros.
canonicalize_ipv6() {
  value="$1"
  left=
  right=
  compressed=0
  case "$value" in
    *::*)
      compressed=1
      left="${value%%::*}"
      right="${value#*::}"
      ;;
    *)
      left="$value"
      ;;
  esac

  left_list=
  left_n=0
  if [ -n "$left" ]; then
    old_ifs=$IFS
    set -f
    IFS=:
    # shellcheck disable=SC2086
    set -- $left
    IFS=$old_ifs
    set +f
    for h in "$@"; do
      c=$(printf '%s' "$h" | tr 'a-f' 'A-F' | sed 's/^0*//')
      [ -n "$c" ] || c=0
      left_list="$left_list$c "
      left_n=$((left_n + 1))
    done
  fi

  right_list=
  right_n=0
  if [ -n "$right" ]; then
    old_ifs=$IFS
    set -f
    IFS=:
    # shellcheck disable=SC2086
    set -- $right
    IFS=$old_ifs
    set +f
    for h in "$@"; do
      c=$(printf '%s' "$h" | tr 'a-f' 'A-F' | sed 's/^0*//')
      [ -n "$c" ] || c=0
      right_list="$right_list$c "
      right_n=$((right_n + 1))
    done
  fi

  zeros=0
  if [ "$compressed" -eq 1 ]; then
    zeros=$((8 - left_n - right_n))
  fi

  out=
  for h in $left_list; do
    if [ -z "$out" ]; then out="$h"; else out="$out:$h"; fi
  done
  i=0
  while [ "$i" -lt "$zeros" ]; do
    if [ -z "$out" ]; then out="0"; else out="$out:0"; fi
    i=$((i + 1))
  done
  for h in $right_list; do
    if [ -z "$out" ]; then out="$h"; else out="$out:$h"; fi
  done
  printf '%s\n' "$out"
}

# Canonical SAN for comparison: IPv4 as-is, IPv6 expanded, DNS/wildcard lowercased.
canonicalize_san() {
  value="$1"
  case "$value" in
    *[!0-9.]*) ;;
    *.*.*.*)
      if is_ipv4 "$value"; then
        printf '%s\n' "$value"
        return 0
      fi
      ;;
  esac
  if is_ipv6 "$value"; then
    canonicalize_ipv6 "$value"
    return 0
  fi
  printf '%s\n' "$value" | tr '[:upper:]' '[:lower:]'
}

# DNS label: 1-63 chars, alnum, internal hyphens only (no leading/trailing -).
is_dns_label() {
  label="$1"
  case "$label" in
    '' | -* | *- | *[!A-Za-z0-9-]*) return 1 ;;
  esac
  # Length ≤ 63 (POSIX portable: count bytes via wc).
  len=$(printf '%s' "$label" | wc -c | tr -d ' ')
  [ "$len" -ge 1 ] && [ "$len" -le 63 ]
}

# Hostname / FQDN without wildcard (labels validated).
is_hostname() {
  value="$1"
  case "$value" in
    '' | *..* | .* | *.) return 1 ;;
    *[!A-Za-z0-9.-]*) return 1 ;;
  esac
  old_ifs=$IFS
  set -f
  IFS=.
  # shellcheck disable=SC2086
  set -- $value
  IFS=$old_ifs
  set +f
  [ "$#" -ge 1 ] || return 1
  for lab in "$@"; do
    is_dns_label "$lab" || return 1
  done
  return 0
}

# SAN / sync target: hostname, IPv4, IPv6, or DNS wildcard (*.a.b).
# Sync hosts (SSH) should be hostname or IPv4 — IPv6 needs careful quoting; allowed for SANs.
validate_domain_or_host() {
  label="$1"
  value="$2"
  case "$value" in
    '' | *..* | .* | *.) fail "invalid $label '$value'" ;;
  esac

  # Dotted-decimal lookalikes must be valid IPv4 (do not fall through to hostname).
  case "$value" in
    *[!0-9.]*) ;;
    *.*.*.*)
      if is_ipv4 "$value"; then
        return 0
      fi
      fail "invalid $label '$value' (bad IPv4)"
      ;;
  esac

  if is_ipv6 "$value"; then
    return 0
  fi

  case "$value" in
    \*.*)
      rest="${value#*.}"
      case "$rest" in
        *\**) fail "invalid $label '$value' (wildcard only as leading *.)" ;;
      esac
      if ! is_hostname "$rest"; then
        fail "invalid $label '$value' (wildcard base must be a valid hostname with ≥2 labels)"
      fi
      case "$rest" in
        *.*) ;;
        *) fail "invalid $label '$value' (wildcard needs at least two labels, e.g. *.app.lan)" ;;
      esac
      return 0
      ;;
    *\**) fail "invalid $label '$value' (wildcard only as leading *.)" ;;
  esac

  if is_hostname "$value"; then
    return 0
  fi
  fail "invalid $label '$value' (expected hostname, IPv4, IPv6, or *.label.tld)"
}

# Sync peers: hostname or IPv4 only (OpenSSH IPv6 literals need brackets).
validate_sync_host() {
  label="$1"
  value="$2"
  case "$value" in
    *[!0-9.]*) ;;
    *.*.*.*)
      if is_ipv4 "$value"; then
        return 0
      fi
      fail "invalid $label '$value' (bad IPv4)"
      ;;
  esac
  if is_hostname "$value"; then
    return 0
  fi
  fail "invalid $label '$value' (CERT_SYNC_HOSTS: hostname or IPv4 only)"
}
