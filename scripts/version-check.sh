#!/usr/bin/env bash
# Assert that release metadata agrees with CHANGELOG.md, the version SSOT.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
release_header=$(grep -m1 -E '^## v[0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$)' CHANGELOG.md || true)
ver=$(printf '%s\n' "$release_header" | sed -nE 's/^## v([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
if [ -z "$ver" ]; then
  echo "version-check: FAIL — no '## vX.Y.Z' release header found in CHANGELOG.md"
  exit 1
fi
echo "version-check: CHANGELOG source of truth = v$ver"

unreleased_count=$(grep -cE '^## Unreleased[[:space:]]*$' CHANGELOG.md || true)
unreleased_line=$(grep -n -m1 -E '^## Unreleased[[:space:]]*$' CHANGELOG.md | cut -d: -f1 || true)
release_line=$(grep -n -m1 -E '^## v[0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$)' CHANGELOG.md | cut -d: -f1 || true)
if [ "$unreleased_count" -ne 1 ] || [ -z "$unreleased_line" ] || [ "$unreleased_line" -ge "$release_line" ]; then
  echo "  FAIL: CHANGELOG.md must contain exactly one '## Unreleased' before the newest release"
  fail=1
fi

pin_pattern='https://raw\.githubusercontent\.com/adithyan-ak/agenthound/v[0-9]+\.[0-9]+\.[0-9]+/install\.sh'
for file in install.sh README.md; do
  matches=$(grep -oE "$pin_pattern" "$file" || true)
  count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d '[:space:]')
  if [ "$count" -ne 1 ]; then
    echo "  FAIL: $file has $count tagged installer URLs, expected exactly 1"
    fail=1
    continue
  fi

  found=$(printf '%s\n' "$matches" | sed -nE 's#^.*/(v[0-9]+\.[0-9]+\.[0-9]+)/install\.sh$#\1#p')
  if [ "$found" != "v$ver" ]; then
    echo "  FAIL: $file pins $found, expected v$ver"
    fail=1
  else
    echo "  ok: $file -> $found"
  fi
done

# GitHub supplies these variables for a tag-triggered workflow. A release tag
# must name the CHANGELOG version, and Unreleased must already be empty so the
# published notes cannot omit last-minute changes.
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  if [ "${GITHUB_REF_NAME:-}" != "v$ver" ]; then
    echo "  FAIL: tag ${GITHUB_REF_NAME:-<none>} != CHANGELOG v$ver"
    fail=1
  else
    echo "  ok: tag ${GITHUB_REF_NAME} matches CHANGELOG"
  fi

  unreleased_body=$(awk '
    /^## Unreleased[[:space:]]*$/ { in_unreleased = 1; next }
    in_unreleased && /^## / { exit }
    in_unreleased && /[^[:space:]]/ { print }
  ' CHANGELOG.md)
  if [ -n "$unreleased_body" ]; then
    echo "  FAIL: CHANGELOG.md Unreleased section must be empty on a tag build"
    fail=1
  else
    echo "  ok: Unreleased is empty for tag build"
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "version-check: FAILED — prepare CHANGELOG.md, then run 'make sync-version' (or fix the tag)."
  exit 1
fi
echo "version-check: all release metadata is consistent (v$ver)."
