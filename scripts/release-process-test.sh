#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
test_root=$(mktemp -d)
pin_base=https://raw.githubusercontent.com/adithyan-ak/agenthound
trap 'rm -rf "$test_root"' EXIT

new_fixture() {
  local name=$1 root="$test_root/$1"
  mkdir -p "$root/scripts"
  cp "$repo_root/scripts/version-check.sh" "$root/scripts/"
  cp "$repo_root/scripts/sync-version.sh" "$root/scripts/"
  cp "$repo_root/scripts/release-notes.sh" "$root/scripts/"
  cat > "$root/CHANGELOG.md" <<'EOF'
# AgentHound Changelog

## Unreleased

## v1.0.1 — Release (2026-07-22)

Release body.

## v1.0.0 — Historical (2026-07-20)

Historical body.
EOF
  printf '# curl -sSfL %s/v1.0.1/install.sh | sh\n' "$pin_base" > "$root/install.sh"
  printf 'curl -sSfL %s/v1.0.1/install.sh | sh\n' "$pin_base" > "$root/README.md"
  printf '%s\n' "$root"
}

expect_failure() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "release-process-test: expected failure: $description" >&2
    exit 1
  fi
}

happy=$(new_fixture happy)
(cd "$happy" && bash scripts/version-check.sh >/dev/null)
(cd "$happy" && GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.0.1 bash scripts/version-check.sh >/dev/null)

mismatch=$(new_fixture mismatch)
sed -i.bak 's/v1\.0\.1/v1.0.0/' "$mismatch/README.md"
rm "$mismatch/README.md.bak"
expect_failure "mismatched installer pin" bash "$mismatch/scripts/version-check.sh"

duplicate=$(new_fixture duplicate)
printf '%s/v1.0.1/install.sh\n' "$pin_base" >> "$duplicate/README.md"
expect_failure "duplicate installer pin" bash "$duplicate/scripts/version-check.sh"
before_sync=$(cksum "$duplicate/install.sh" "$duplicate/README.md")
expect_failure "sync with duplicate installer pin" bash "$duplicate/scripts/sync-version.sh" 1.0.2
after_sync=$(cksum "$duplicate/install.sh" "$duplicate/README.md")
if [ "$before_sync" != "$after_sync" ]; then
  echo "release-process-test: failed sync mutated a fixture" >&2
  exit 1
fi

unreleased=$(new_fixture unreleased)
sed -i.bak '/## Unreleased/a\
Pending change.' "$unreleased/CHANGELOG.md"
rm "$unreleased/CHANGELOG.md.bak"
expect_failure "non-empty Unreleased on tag" env GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.0.1 \
  bash "$unreleased/scripts/version-check.sh"

sync=$(new_fixture sync)
(cd "$sync" && bash scripts/sync-version.sh 1.0.2 >/dev/null)
if [ "$(grep -RhoE 'agenthound/v[0-9]+\.[0-9]+\.[0-9]+/install\.sh' "$sync/install.sh" "$sync/README.md" | sort -u)" != "agenthound/v1.0.2/install.sh" ]; then
  echo "release-process-test: sync did not update both pins" >&2
  exit 1
fi

notes=$(new_fixture notes)
rendered=$(cd "$notes" && sh scripts/release-notes.sh CHANGELOG.md v1.0.1)
printf '%s\n' "$rendered" | grep -Fq '## v1.0.1 — Release'
if printf '%s\n' "$rendered" | grep -Fq '## v1.0.0'; then
  echo "release-process-test: release notes included a historical section" >&2
  exit 1
fi
expect_failure "release-notes version mismatch" sh "$notes/scripts/release-notes.sh" "$notes/CHANGELOG.md" v1.0.2

formula_fixture="$test_root/agenthound.rb"
checksums_fixture="$test_root/checksums.txt"
for platform in darwin linux; do
  for arch in amd64 arm64; do
    asset="agenthound_1.0.1_${platform}_${arch}.tar.gz"
    checksum=$(printf '%064d' "$(( ${#platform} + ${#arch} ))")
    printf '  url "https://github.com/adithyan-ak/AgentHound/releases/download/v1.0.1/%s"\n' "$asset" >> "$formula_fixture"
    printf '  sha256 "%s"\n' "$checksum" >> "$formula_fixture"
    printf '%s  %s\n' "$checksum" "$asset" >> "$checksums_fixture"
  done
done
sed -i.bak '1i\
  version "1.0.1"' "$formula_fixture"
rm "$formula_fixture.bak"
bash "$repo_root/scripts/verify-homebrew-formula.sh" \
  agenthound 1.0.1 v1.0.1 "$formula_fixture" "$checksums_fixture"

bad_formula="$test_root/agenthound-bad.rb"
cp "$formula_fixture" "$bad_formula"
sed -i.bak 's/linux_arm64/windows_arm64/' "$bad_formula"
rm "$bad_formula.bak"
expect_failure "unexpected Homebrew archive" bash "$repo_root/scripts/verify-homebrew-formula.sh" \
  agenthound 1.0.1 v1.0.1 "$bad_formula" "$checksums_fixture"

echo "release-process-test: all checks passed"
