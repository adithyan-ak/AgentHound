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
  cp "$repo_root/scripts/release-tag-check.sh" "$root/scripts/"
  cat > "$root/CHANGELOG.md" <<'EOF'
# AgentHound Changelog

## Unreleased

## 1.0.0 — Release (2026-07-27)

Release body.
EOF
  printf '# curl -sSfL %s/1.0.0/install.sh | sh\n' "$pin_base" > "$root/install.sh"
  printf 'curl -sSfL %s/1.0.0/install.sh | sh\n' "$pin_base" > "$root/README.md"
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
(cd "$happy" && GITHUB_REF_TYPE=tag GITHUB_REF_NAME=1.0.0 bash scripts/version-check.sh >/dev/null)

mismatch=$(new_fixture mismatch)
sed -i.bak 's/1\.0\.0/1.0.1/' "$mismatch/README.md"
rm "$mismatch/README.md.bak"
expect_failure "mismatched installer pin" bash "$mismatch/scripts/version-check.sh"

duplicate=$(new_fixture duplicate)
printf '%s/1.0.0/install.sh\n' "$pin_base" >> "$duplicate/README.md"
expect_failure "duplicate installer pin" bash "$duplicate/scripts/version-check.sh"
before_sync=$(cksum "$duplicate/install.sh" "$duplicate/README.md")
expect_failure "sync with duplicate installer pin" bash "$duplicate/scripts/sync-version.sh" 1.0.2
after_sync=$(cksum "$duplicate/install.sh" "$duplicate/README.md")
if [ "$before_sync" != "$after_sync" ]; then
  echo "release-process-test: failed sync mutated a fixture" >&2
  exit 1
fi

leading_zero=$(new_fixture leading-zero)
sed -i.bak 's/## 1\.0\.0/## 01.0.0/' "$leading_zero/CHANGELOG.md"
rm "$leading_zero/CHANGELOG.md.bak"
expect_failure "leading-zero release version" bash "$leading_zero/scripts/version-check.sh"
expect_failure "leading-zero sync argument" bash "$leading_zero/scripts/sync-version.sh" 01.0.0

unreleased=$(new_fixture unreleased)
sed -i.bak '/## Unreleased/a\
Pending change.' "$unreleased/CHANGELOG.md"
rm "$unreleased/CHANGELOG.md.bak"
expect_failure "non-empty Unreleased on tag" env GITHUB_REF_TYPE=tag GITHUB_REF_NAME=1.0.0 \
  bash "$unreleased/scripts/version-check.sh"

sync=$(new_fixture sync)
(cd "$sync" && bash scripts/sync-version.sh 1.0.2 >/dev/null)
if [ "$(grep -RhoE 'agenthound/[0-9]+\.[0-9]+\.[0-9]+/install\.sh' "$sync/install.sh" "$sync/README.md" | sort -u)" != "agenthound/1.0.2/install.sh" ]; then
  echo "release-process-test: sync did not update both pins" >&2
  exit 1
fi

notes=$(new_fixture notes)
rendered=$(cd "$notes" && sh scripts/release-notes.sh CHANGELOG.md 1.0.0)
printf '%s\n' "$rendered" | grep -Fq '## 1.0.0 — Release'
if printf '%s\n' "$rendered" | grep -Fq '## Unreleased'; then
  echo "release-process-test: release notes included a historical section" >&2
  exit 1
fi
expect_failure "release-notes version mismatch" sh "$notes/scripts/release-notes.sh" "$notes/CHANGELOG.md" 1.0.2

formula_fixture="$test_root/agenthound.rb"
checksums_fixture="$test_root/checksums.txt"
printf '  version "1.0.0"\n' > "$formula_fixture"
for platform in darwin linux; do
  for arch in amd64 arm64; do
    asset="agenthound_1.0.0_${platform}_${arch}.tar.gz"
    checksum=$(printf '%064d' "$(( ${#platform} + ${#arch} ))")
    printf '  url "https://github.com/adithyan-ak/AgentHound/releases/download/1.0.0/%s"\n' "$asset" >> "$formula_fixture"
    printf '  sha256 "%s"\n' "$checksum" >> "$formula_fixture"
    printf '%s  %s\n' "$checksum" "$asset" >> "$checksums_fixture"
  done
done
bash "$repo_root/scripts/verify-homebrew-formula.sh" \
  agenthound 1.0.0 1.0.0 "$formula_fixture" "$checksums_fixture"

bad_formula="$test_root/agenthound-bad.rb"
cp "$formula_fixture" "$bad_formula"
sed -i.bak 's/linux_arm64/windows_arm64/' "$bad_formula"
rm "$bad_formula.bak"
expect_failure "unexpected Homebrew archive" bash "$repo_root/scripts/verify-homebrew-formula.sh" \
  agenthound 1.0.0 1.0.0 "$bad_formula" "$checksums_fixture"

new_git_fixture() {
  local name=$1 root="$test_root/git-$1"
  mkdir -p "$root"
  (
    cd "$root"
    git init -q
    git config user.name "Release Test"
    git config user.email "release-test@example.invalid"
    printf 'base\n' > state
    git add state
    git commit -qm base
  )
  mkdir -p "$root/scripts"
  cp "$repo_root/scripts/release-tag-check.sh" "$root/scripts/"
  printf '%s\n' "$root"
}

migration=$(new_git_fixture migration)
(
  cd "$migration"
  migration_main=$(git rev-parse HEAD)
  printf 'candidate\n' >> state
  git commit -qam candidate
  git tag 1.0.0
  [ "$(bash scripts/release-tag-check.sh candidate 1.0.0 v1.0.1 "$migration_main")" = migration ]
  expect_failure "published main has not advanced" \
    bash scripts/release-tag-check.sh published 1.0.0 "$migration_main"
  bash scripts/release-tag-check.sh published 1.0.0 HEAD >/dev/null
)

wrong_parent=$(new_git_fixture wrong-parent)
(
  cd "$wrong_parent"
  old_main=$(git rev-parse HEAD)
  printf 'intermediate\n' >> state
  git commit -qam intermediate
  printf 'candidate\n' >> state
  git commit -qam candidate
  git tag 1.0.0
  expect_failure "migration parent is not current main" \
    bash scripts/release-tag-check.sh candidate 1.0.0 v1.0.1 "$old_main"
)

merge_candidate=$(new_git_fixture merge)
(
  cd "$merge_candidate"
  base=$(git rev-parse HEAD)
  primary=$(git branch --show-current)
  git switch -qc side
  printf 'side\n' > side
  git add side
  git commit -qm side
  git switch -q "$primary"
  printf 'main\n' > main
  git add main
  git commit -qm main
  git merge -q --no-ff side -m merge
  git tag 1.0.0
  expect_failure "migration candidate is a merge commit" \
    bash scripts/release-tag-check.sh candidate 1.0.0 v1.0.1 "$base"
)

invalid_migration=$(new_git_fixture invalid-migration)
(
  cd "$invalid_migration"
  main=$(git rev-parse HEAD)
  printf 'candidate\n' >> state
  git commit -qam candidate
  git tag 1.0.1
  expect_failure "migration tag other than 1.0.0" \
    bash scripts/release-tag-check.sh candidate 1.0.1 v1.0.1 "$main"
  git tag 1.0.0
  expect_failure "migration exception with a different latest release" \
    bash scripts/release-tag-check.sh candidate 1.0.0 v1.0.0 "$main"
)

normal=$(new_git_fixture normal)
(
  cd "$normal"
  printf 'candidate\n' >> state
  git commit -qam candidate
  git tag 1.0.1
  [ "$(bash scripts/release-tag-check.sh candidate 1.0.1 1.0.0 HEAD)" = normal ]
  expect_failure "duplicate normal version" \
    bash scripts/release-tag-check.sh candidate 1.0.1 1.0.1 HEAD
  git tag 0.9.0
  expect_failure "lower normal version" \
    bash scripts/release-tag-check.sh candidate 0.9.0 1.0.0 HEAD
)

normal_off_main=$(new_git_fixture normal-off-main)
(
  cd "$normal_off_main"
  main=$(git rev-parse HEAD)
  git switch -qc release
  printf 'candidate\n' >> state
  git commit -qam candidate
  git tag 1.0.1
  expect_failure "normal release tag is not contained in main" \
    bash scripts/release-tag-check.sh candidate 1.0.1 1.0.0 "$main"
)

echo "release-process-test: all checks passed"
