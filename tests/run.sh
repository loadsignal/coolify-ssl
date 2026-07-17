#!/bin/sh
# Run all coolify-ssl tests.
set -eu

TESTS_DIR="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)"
failed=0

for t in "$TESTS_DIR"/test-*.sh; do
  [ -f "$t" ] || continue
  name="$(basename "$t")"
  printf '==> %s\n' "$name"
  if sh "$t"; then
    printf 'OK %s\n\n' "$name"
  else
    printf 'FAILED %s\n\n' "$name"
    failed=1
  fi
done

[ "$failed" -eq 0 ]
