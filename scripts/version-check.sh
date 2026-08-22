#!/usr/bin/env bash
# Assert that release metadata agrees with CHANGELOG.md, the version SSOT.

set -euo pipefail

cd "$(dirname "$0")/.."

source scripts/release-version-pins.sh

fail=0
release_header=$(grep -m1 -E '^## (0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([[:space:]]|$)' CHANGELOG.md || true)
ver=$(printf '%s\n' "$release_header" | sed -nE 's/^## ((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)).*/\1/p')
if [ -z "$ver" ]; then
  echo "version-check: FAIL — no '## X.Y.Z' release header found in CHANGELOG.md"
  exit 1
fi
echo "version-check: CHANGELOG source of truth = $ver"

unreleased_count=$(grep -cE '^## Unreleased[[:space:]]*$' CHANGELOG.md || true)
unreleased_line=$(grep -n -m1 -E '^## Unreleased[[:space:]]*$' CHANGELOG.md | cut -d: -f1 || true)
release_line=$(grep -n -m1 -E '^## (0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([[:space:]]|$)' CHANGELOG.md | cut -d: -f1 || true)
if [ "$unreleased_count" -ne 1 ] || [ -z "$unreleased_line" ] || [ "$unreleased_line" -ge "$release_line" ]; then
  echo "  FAIL: CHANGELOG.md must contain exactly one '## Unreleased' before the newest release"
  fail=1
fi

while IFS='|' read -r kind file expected_count; do
  if [ ! -f "$file" ]; then
    echo "  FAIL: missing release-version file: $file"
    fail=1
    continue
  fi

  pattern=$(release_version_pin_pattern "$kind")
  expected=$(release_version_pin_replacement "$kind" "$ver")
  matches=$(grep -oE "$pattern" "$file" || true)
  count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d '[:space:]')
  if [ "$count" -ne "$expected_count" ]; then
    echo "  FAIL: $file has $count $kind references, expected exactly $expected_count"
    fail=1
    continue
  fi

  mismatches=$(printf '%s\n' "$matches" | grep -Fvx "$expected" || true)
  if [ -n "$mismatches" ]; then
    echo "  FAIL: $file has a $kind reference that does not pin $ver"
    fail=1
  else
    echo "  ok: $file $kind ($expected_count) -> $ver"
  fi
done < <(release_version_pin_specs)

# GitHub supplies these variables for a tag-triggered workflow. A release tag
# must name the CHANGELOG version. RELEASE_CHECK=1 gives the pre-tag
# `make prerelease` gate the same empty-Unreleased safety check, before the
# immutable tag exists.
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  if [ "${GITHUB_REF_NAME:-}" != "$ver" ]; then
    echo "  FAIL: tag ${GITHUB_REF_NAME:-<none>} != CHANGELOG $ver"
    fail=1
  else
    echo "  ok: tag ${GITHUB_REF_NAME} matches CHANGELOG"
  fi
fi

if [ "${GITHUB_REF_TYPE:-}" = "tag" ] || [ "${RELEASE_CHECK:-}" = "1" ]; then
  unreleased_body=$(awk '
    /^## Unreleased[[:space:]]*$/ { in_unreleased = 1; next }
    in_unreleased && /^## / { exit }
    in_unreleased && /[^[:space:]]/ { print }
  ' CHANGELOG.md)
  if [ -n "$unreleased_body" ]; then
    echo "  FAIL: CHANGELOG.md Unreleased section must be empty for a release"
    fail=1
  else
    echo "  ok: Unreleased is empty for release"
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "version-check: FAILED — prepare CHANGELOG.md, then run 'make sync-version' (or fix the tag)."
  exit 1
fi
echo "version-check: all release metadata is consistent ($ver)."
