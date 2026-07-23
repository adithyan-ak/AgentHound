#!/usr/bin/env bash
# Rewrite the repository's two tagged installer URLs to a release version.

set -euo pipefail

cd "$(dirname "$0")/.."

ver="${1:-}"
ver="${ver#v}"
if [ -z "$ver" ]; then
  ver=$(grep -m1 -E '^## v[0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$)' CHANGELOG.md \
    | sed -nE 's/^## v([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' || true)
fi
if ! printf '%s\n' "$ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "sync-version: '${ver:-<empty>}' is not a valid X.Y.Z version"
  exit 1
fi

pin_pattern='https://raw\.githubusercontent\.com/adithyan-ak/agenthound/v[0-9]+\.[0-9]+\.[0-9]+/install\.sh'
files=(install.sh README.md)

# Validate both files before mutating either one. This prevents a duplicate or
# missing URL from producing a partially synchronized release-prep diff.
for file in "${files[@]}"; do
  count=$(grep -oE "$pin_pattern" "$file" | wc -l | tr -d '[:space:]' || true)
  if [ "$count" -ne 1 ]; then
    echo "sync-version: $file has $count tagged installer URLs, expected exactly 1"
    exit 1
  fi
done

sedi() {
  if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi
}

replacement="https://raw.githubusercontent.com/adithyan-ak/agenthound/v${ver}/install.sh"
for file in "${files[@]}"; do
  sedi -E "s#${pin_pattern}#${replacement}#g" "$file"
  echo "sync-version: set v${ver} pin in $file"
done
echo "sync-version: updated exactly 2 tagged installer URLs. Run 'make version-check' to confirm."
