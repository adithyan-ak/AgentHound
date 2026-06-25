#!/usr/bin/env bash
# sync-version.sh [X.Y.Z] — rewrite the install.sh + README install-pin
# examples so they match a version. With no argument the version is taken from
# the first "## vX.Y.Z" header in CHANGELOG.md (the source of truth).
#
# Release prep:
#   1. write the new "## vX.Y.Z" section in CHANGELOG.md
#   2. make sync-version
#   3. make version-check   (or make prerelease)

set -euo pipefail

cd "$(dirname "$0")/.."

ver="${1:-}"
ver="${ver#v}"
if [ -z "$ver" ]; then
  ver=$(grep -m1 -oE '^## v[0-9]+\.[0-9]+\.[0-9]+' CHANGELOG.md | sed 's/^## v//' || true)
fi
if [ -z "$ver" ]; then
  echo "sync-version: no version given and no '## vX.Y.Z' header in CHANGELOG.md"
  exit 1
fi
# Guard the substitution: a non-X.Y.Z value (typo'd VERSION= or sed-special
# characters like & or #) would otherwise mutate / corrupt the pins in place.
if ! echo "$ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "sync-version: '$ver' is not a valid X.Y.Z version"
  exit 1
fi

# Portable in-place sed (GNU uses -i; BSD/macOS needs -i '').
sedi() {
  if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi
}

for f in install.sh README.md; do
  sedi -E "s#agenthound/v[0-9]+\.[0-9]+\.[0-9]+/install\.sh#agenthound/v${ver}/install.sh#g" "$f"
  echo "sync-version: set v${ver} pin in $f"
done
echo "sync-version: done. Run 'make version-check' to confirm."
