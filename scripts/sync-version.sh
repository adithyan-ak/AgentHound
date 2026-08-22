#!/usr/bin/env bash
# Rewrite every live public release-version reference to one version.

set -euo pipefail

cd "$(dirname "$0")/.."

source scripts/release-version-pins.sh

ver="${1:-}"
if [ -z "$ver" ]; then
  ver=$(grep -m1 -E '^## (0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([[:space:]]|$)' CHANGELOG.md \
    | sed -nE 's/^## ((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)).*/\1/p' || true)
fi
if ! printf '%s\n' "$ver" | grep -qE '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  echo "sync-version: '${ver:-<empty>}' is not a valid X.Y.Z version"
  exit 1
fi

# Validate every location before mutating any file. This prevents a duplicate
# or missing reference from producing a partially synchronized release diff.
total=0
while IFS='|' read -r kind file expected_count; do
  if [ ! -f "$file" ]; then
    echo "sync-version: missing release-version file: $file"
    exit 1
  fi
  pattern=$(release_version_pin_pattern "$kind")
  count=$(grep -oE "$pattern" "$file" | wc -l | tr -d '[:space:]' || true)
  if [ "$count" -ne "$expected_count" ]; then
    echo "sync-version: $file has $count $kind references, expected exactly $expected_count"
    exit 1
  fi
  total=$((total + expected_count))
done < <(release_version_pin_specs)

sedi() {
  if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi
}

while IFS='|' read -r kind file expected_count; do
  pattern=$(release_version_pin_pattern "$kind")
  replacement=$(release_version_pin_replacement "$kind" "$ver")
  sedi -E "s#${pattern}#${replacement}#g" "$file"
  echo "sync-version: set $expected_count $kind reference(s) in $file to $ver"
done < <(release_version_pin_specs)

echo "sync-version: updated exactly $total live release references. Run 'make version-check' to confirm."
