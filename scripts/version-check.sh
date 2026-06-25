#!/usr/bin/env bash
# version-check.sh — assert the hand-maintained version pins agree with the
# CHANGELOG, the single source of truth (SSOT). GoReleaser injects the
# binary / Docker / Homebrew versions from the git tag, so the only strings
# that can silently drift are the install.sh + README curl examples.
#
# SSOT: the first "## vX.Y.Z" header in CHANGELOG.md. "## Unreleased" sits
# above it during a cycle and is skipped, so mid-cycle this resolves to the
# last released version — which the pins already match.
#
# Run via `make version-check`; also runs inside `make prerelease`, so the
# release pipeline (release.yml -> make prerelease) cannot publish a release
# whose pins disagree with the CHANGELOG. On a tag build it additionally
# asserts the pushed tag equals the CHANGELOG version.
#
# Blocking gate: returns non-zero on any mismatch.

set -euo pipefail

cd "$(dirname "$0")/.."

ver=$(grep -m1 -oE '^## v[0-9]+\.[0-9]+\.[0-9]+' CHANGELOG.md | sed 's/^## v//' || true)
if [ -z "$ver" ]; then
  echo "version-check: FAIL — no '## vX.Y.Z' release header found in CHANGELOG.md"
  exit 1
fi
echo "version-check: CHANGELOG source of truth = v$ver"

fail=0
check_pin() {
  local file="$1" found
  found=$(grep -oE 'agenthound/v[0-9]+\.[0-9]+\.[0-9]+/install\.sh' "$file" \
            | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
  if [ -z "$found" ]; then
    echo "  FAIL: no 'agenthound/vX.Y.Z/install.sh' pin found in $file"
    fail=1
  elif [ "$found" != "v$ver" ]; then
    echo "  FAIL: $file pins $found, expected v$ver"
    fail=1
  else
    echo "  ok: $file -> $found"
  fi
}
check_pin install.sh
check_pin README.md

# Release context: the pushed tag must also match the CHANGELOG. GitHub Actions
# sets GITHUB_REF_TYPE / GITHUB_REF_NAME automatically; locally they are unset
# and this block is skipped.
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  if [ "${GITHUB_REF_NAME:-}" != "v$ver" ]; then
    echo "  FAIL: tag ${GITHUB_REF_NAME:-<none>} != CHANGELOG v$ver"
    fail=1
  else
    echo "  ok: tag ${GITHUB_REF_NAME} matches CHANGELOG"
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "version-check: FAILED — write the CHANGELOG section, then run 'make sync-version' (or fix the tag)."
  exit 1
fi
echo "version-check: all version references consistent (v$ver)."
