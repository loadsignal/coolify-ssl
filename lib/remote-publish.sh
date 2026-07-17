#!/bin/sh
# Remote atomic leaf publish for coolify-ssl (runs on CERT_SYNC_HOSTS peers).
# Invoked by lib/sync.sh after scp of leaf + provider + this script.
#
# Usage (all paths absolute; CERT_NAME charset-validated by the source host):
#   sh remote-publish.sh \
#     <cert_dir> <cert_name> <gen_name> \
#     <cert_tmp> <key_tmp> <provider_tmp> <provider_dest> \
#     <leaf_link_name> <gen_prefix>
#
# Layout (same as local lib/leaf.sh):
#   .gen.<id>/{name}.cert|key  — immutable generation
#   .leaf → .gen.<id>          — flipped with ln -sfn
#   {name}.cert → .leaf/...    — stable Traefik paths
# Provider is written last so reload sees a consistent pair.
set -eu

usage() {
  printf 'usage: %s <cert_dir> <cert_name> <gen_name> <cert_tmp> <key_tmp> <provider_tmp> <provider_dest> <leaf_link_name> <gen_prefix>\n' \
    "${0##*/}" >&2
  exit 2
}

[ "$#" -eq 9 ] || usage

cert_dir=$1
cert_name=$2
gen_name=$3
cert_tmp=$4
key_tmp=$5
provider_tmp=$6
provider_dest=$7
leaf_link_name=$8
gen_prefix=$9

# Refuse path traversal / empty required args (defense in depth; source already validates).
for v in "$cert_dir" "$cert_name" "$gen_name" "$cert_tmp" "$key_tmp" "$provider_tmp" "$provider_dest" "$leaf_link_name" "$gen_prefix"; do
  case "$v" in
    '' | *..*)
      printf 'remote-publish: invalid argument (empty or ..)\n' >&2
      exit 1
      ;;
  esac
done

case "$cert_dir" in
  /*) ;;
  *)
    printf 'remote-publish: cert_dir must be absolute\n' >&2
    exit 1
    ;;
esac

case "$provider_dest" in
  /*) ;;
  *)
    printf 'remote-publish: provider_dest must be absolute\n' >&2
    exit 1
    ;;
esac

gen_dir="$cert_dir/$gen_name"
leaf_link="$cert_dir/$leaf_link_name"
stable_cert="$cert_dir/$cert_name.cert"
stable_key="$cert_dir/$cert_name.key"

# Remove a generation directory only if it is a real directory (never follow symlinks).
safe_rm_gen() {
  path=$1
  if [ -L "$path" ]; then
    printf 'remote-publish: refusing to remove symlink %s\n' "$path" >&2
    return 0
  fi
  if [ -d "$path" ]; then
    rm -rf "$path"
  fi
}

install_rel_symlink() {
  target=$1
  dest=$2
  if [ -L "$dest" ]; then
    ln -sfn "$target" "$dest"
  elif [ -e "$dest" ]; then
    rm -f "$dest"
    ln -s "$target" "$dest"
  else
    ln -s "$target" "$dest"
  fi
}

prune_old_generations() {
  current=
  if [ -L "$leaf_link" ]; then
    current=$(readlink "$leaf_link" 2>/dev/null || true)
  fi
  # Intentional unquoted glob (POSIX; no nullglob).
  # shellcheck disable=SC2231
  for d in "$cert_dir"/${gen_prefix}*; do
    [ -e "$d" ] || continue
    if [ -L "$d" ]; then
      printf 'remote-publish: skipping symlink during prune: %s\n' "$d" >&2
      continue
    fi
    [ -d "$d" ] || continue
    base=$(basename "$d")
    if [ -n "$current" ] && [ "$base" = "$current" ]; then
      continue
    fi
    safe_rm_gen "$d"
  done
}

# Staged material must exist before we touch the live layout.
[ -s "$cert_tmp" ] || {
  printf 'remote-publish: missing staged cert %s\n' "$cert_tmp" >&2
  exit 1
}
[ -s "$key_tmp" ] || {
  printf 'remote-publish: missing staged key %s\n' "$key_tmp" >&2
  exit 1
}
[ -s "$provider_tmp" ] || {
  printf 'remote-publish: missing staged provider %s\n' "$provider_tmp" >&2
  exit 1
}

mkdir -p "$gen_dir"
mv -f "$key_tmp" "$gen_dir/$cert_name.key"
mv -f "$cert_tmp" "$gen_dir/$cert_name.cert"
chmod 644 "$gen_dir/$cert_name.cert"
chmod 600 "$gen_dir/$cert_name.key"

# Stable names → .leaf/ before flip so Traefik always resolves a pair.
install_rel_symlink "$leaf_link_name/$cert_name.cert" "$stable_cert"
install_rel_symlink "$leaf_link_name/$cert_name.key" "$stable_key"
ln -sfn "$gen_name" "$leaf_link"
prune_old_generations

# Provider last: file-watch reload sees cert+key already consistent.
mkdir -p "$(dirname "$provider_dest")"
mv -f "$provider_tmp" "$provider_dest"
