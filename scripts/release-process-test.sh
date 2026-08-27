#!/usr/bin/env bash

set -euo pipefail

# The release workflow itself runs on a tag. Fixtures set tag context only for
# the cases that exercise it; inheriting the real release tag would make every
# synthetic version fixture fail for the wrong reason.
unset GITHUB_REF_TYPE GITHUB_REF_NAME

repo_root=$(cd "$(dirname "$0")/.." && pwd)
test_root=$(mktemp -d)
pin_base=https://raw.githubusercontent.com/adithyan-ak/agenthound
trap 'rm -rf "$test_root"' EXIT

new_fixture() {
  local name=$1 root="$test_root/$1"
  mkdir -p "$root/scripts" "$root/docs/getting-started" "$root/docs/operator" "$root/docker"
  cp "$repo_root/scripts/version-check.sh" "$root/scripts/"
  cp "$repo_root/scripts/sync-version.sh" "$root/scripts/"
  cp "$repo_root/scripts/release-version-pins.sh" "$root/scripts/"
  cp "$repo_root/scripts/release-notes.sh" "$root/scripts/"
  cp "$repo_root/scripts/release-tag-check.sh" "$root/scripts/"
  cat > "$root/CHANGELOG.md" <<'EOF'
# AgentHound Changelog

## Unreleased

## 1.0.0 — Release (2026-07-27)

Release body.
EOF
  cat > "$root/install.sh" <<EOF
# curl -sSfL ${pin_base}/1.0.0/install.sh \\
#   | AGENTHOUND_VERSION=1.0.0 sh
EOF
  cat > "$root/README.md" <<EOF
Install the 1.0.0 static binary:
curl -sSfL ${pin_base}/1.0.0/install.sh \\
  | AGENTHOUND_VERSION=1.0.0 sh
curl -sSfL ${pin_base}/1.0.0/docker/docker-compose.public.yml
EOF
  cat > "$root/docs/getting-started/install.md" <<EOF
curl -sSfL ${pin_base}/1.0.0/install.sh \\
  | AGENTHOUND_VERSION=1.0.0 sh
curl -sSfL ${pin_base}/1.0.0/docker/docker-compose.public.yml
EOF
  printf 'curl -sSfL %s/1.0.0/docker/docker-compose.public.yml\n' "$pin_base" \
    > "$root/docs/getting-started/quickstart.md"
  cat > "$root/docs/operator/deployment.md" <<EOF
curl -sSfL ${pin_base}/1.0.0/docker/docker-compose.public.yml
curl -sSfL ${pin_base}/1.0.0/docker/docker-compose.public.yml
EOF
  cat > "$root/docker/docker-compose.public.yml" <<'EOF'
services:
  agenthound:
    image: ghcr.io/adithyan-ak/agenthound-server:1.0.0
EOF
  printf '%s\n' "$root"
}

fixture_checksum() {
  local root=$1
  (
    cd "$root"
    cksum install.sh README.md docs/getting-started/install.md \
      docs/getting-started/quickstart.md docs/operator/deployment.md \
      docker/docker-compose.public.yml | sort
  )
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
sed -i.bak 's/AGENTHOUND_VERSION=1\.0\.0/AGENTHOUND_VERSION=1.0.1/' "$mismatch/README.md"
rm "$mismatch/README.md.bak"
expect_failure "mismatched environment pin" bash "$mismatch/scripts/version-check.sh"

compose_mismatch=$(new_fixture compose-mismatch)
sed -i.bak 's#/1\.0\.0/docker/#/1.0.1/docker/#' \
  "$compose_mismatch/docs/getting-started/quickstart.md"
rm "$compose_mismatch/docs/getting-started/quickstart.md.bak"
expect_failure "mismatched documentation Compose pin" \
  bash "$compose_mismatch/scripts/version-check.sh"

server_image_mismatch=$(new_fixture server-image-mismatch)
sed -i.bak 's/agenthound-server:1\.0\.0/agenthound-server:1.0.1/' \
  "$server_image_mismatch/docker/docker-compose.public.yml"
rm "$server_image_mismatch/docker/docker-compose.public.yml.bak"
expect_failure "mismatched Compose server image pin" \
  bash "$server_image_mismatch/scripts/version-check.sh"

server_image_missing=$(new_fixture server-image-missing)
sed -i.bak '/agenthound-server:/d' "$server_image_missing/docker/docker-compose.public.yml"
rm "$server_image_missing/docker/docker-compose.public.yml.bak"
expect_failure "missing Compose server image pin" \
  bash "$server_image_missing/scripts/version-check.sh"
before_sync=$(fixture_checksum "$server_image_missing")
expect_failure "sync with missing Compose server image pin" \
  bash "$server_image_missing/scripts/sync-version.sh" 1.0.2
after_sync=$(fixture_checksum "$server_image_missing")
if [ "$before_sync" != "$after_sync" ]; then
  echo "release-process-test: failed image-pin sync mutated a fixture" >&2
  exit 1
fi

server_image_duplicate=$(new_fixture server-image-duplicate)
printf '    image: ghcr.io/adithyan-ak/agenthound-server:1.0.0\n' \
  >> "$server_image_duplicate/docker/docker-compose.public.yml"
expect_failure "duplicate Compose server image pin" \
  bash "$server_image_duplicate/scripts/version-check.sh"
before_sync=$(fixture_checksum "$server_image_duplicate")
expect_failure "sync with duplicate Compose server image pin" \
  bash "$server_image_duplicate/scripts/sync-version.sh" 1.0.2
after_sync=$(fixture_checksum "$server_image_duplicate")
if [ "$before_sync" != "$after_sync" ]; then
  echo "release-process-test: failed duplicate image-pin sync mutated a fixture" >&2
  exit 1
fi

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
expect_failure "non-empty Unreleased in pre-tag release mode" env RELEASE_CHECK=1 \
  bash "$unreleased/scripts/version-check.sh"

sync=$(new_fixture sync)
(sed -i.bak 's/## 1\.0\.0 —/## 1.0.2 —/' "$sync/CHANGELOG.md" && rm "$sync/CHANGELOG.md.bak")
(cd "$sync" && bash scripts/sync-version.sh 1.0.2 >/dev/null)
(cd "$sync" && RELEASE_CHECK=1 bash scripts/version-check.sh >/dev/null)
grep -Fqx '    image: ghcr.io/adithyan-ak/agenthound-server:1.0.2' \
  "$sync/docker/docker-compose.public.yml"

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

normal=$(new_git_fixture normal)
(
  cd "$normal"
  printf 'candidate\n' >> state
  git commit -qam candidate
  git tag 1.0.1
  tag_commit=$(git rev-parse HEAD)
  [ "$(bash scripts/release-tag-check.sh candidate 1.0.1 1.0.0 HEAD)" = "$tag_commit" ]
  bash scripts/release-tag-check.sh published 1.0.1 HEAD >/dev/null
  printf 'later main change\n' >> state
  git commit -qam later
  bash scripts/release-tag-check.sh published 1.0.1 HEAD >/dev/null
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
  expect_failure "published release tag is not contained in main" \
    bash scripts/release-tag-check.sh published 1.0.1 "$main"
)

echo "release-process-test: all checks passed"
