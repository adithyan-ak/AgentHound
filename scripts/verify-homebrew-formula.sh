#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 <formula> <version> <tag> <formula-file> <checksums-file>" >&2
  exit 2
fi

formula=$1
version=$2
tag=$3
formula_file=$4
checksums_file=$5

if [ ! -r "$formula_file" ] || [ ! -r "$checksums_file" ]; then
  echo "Homebrew verification inputs are not readable" >&2
  exit 1
fi

if ! grep -Fq "version \"${version}\"" "$formula_file"; then
  echo "Homebrew formula ${formula} does not declare version ${version}" >&2
  exit 1
fi

formula_urls=()
while IFS= read -r formula_url; do
  formula_urls[${#formula_urls[@]}]=$formula_url
done < <(sed -nE 's/^[[:space:]]*url "([^"]+)".*/\1/p' "$formula_file")
formula_sums=()
while IFS= read -r formula_sum; do
  formula_sums[${#formula_sums[@]}]=$formula_sum
done < <(sed -nE 's/^[[:space:]]*sha256 "([0-9a-f]{64})".*/\1/p' "$formula_file")
if (( ${#formula_urls[@]} != 4 || ${#formula_urls[@]} != ${#formula_sums[@]} )); then
  echo "Homebrew formula ${formula} must contain four paired URL/checksum entries" >&2
  exit 1
fi

expected_assets=$(printf '%s\n' \
  "${formula}_${version}_darwin_amd64.tar.gz" \
  "${formula}_${version}_darwin_arm64.tar.gz" \
  "${formula}_${version}_linux_amd64.tar.gz" \
  "${formula}_${version}_linux_arm64.tar.gz" | sort)
actual_assets=$(
  for formula_url in "${formula_urls[@]}"; do
    printf '%s\n' "${formula_url##*/}"
  done | sort
)
if [ "$actual_assets" != "$expected_assets" ]; then
  echo "Homebrew formula ${formula} does not reference the expected macOS/Linux archives" >&2
  exit 1
fi

for index in "${!formula_urls[@]}"; do
  formula_url=${formula_urls[$index]}
  formula_sum=${formula_sums[$index]}
  asset=${formula_url##*/}
  expected_url="https://github.com/adithyan-ak/AgentHound/releases/download/${tag}/${asset}"
  if [ "$formula_url" != "$expected_url" ]; then
    echo "Unexpected Homebrew URL for ${formula}: ${formula_url}" >&2
    exit 1
  fi

  release_sum=$(awk -v asset="$asset" '$2 == asset { print $1 }' "$checksums_file")
  if [ -z "$release_sum" ] || [ "$formula_sum" != "$release_sum" ]; then
    echo "Homebrew checksum mismatch for ${asset}" >&2
    exit 1
  fi
done
