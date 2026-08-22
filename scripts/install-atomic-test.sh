#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
  linux) test_os=linux ;;
  darwin) test_os=darwin ;;
  *) printf 'installer atomic test: unsupported test OS\n' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) test_arch=amd64 ;;
  aarch64|arm64) test_arch=arm64 ;;
  *) printf 'installer atomic test: unsupported test architecture\n' >&2; exit 1 ;;
esac

case_root=$(mktemp -d)
trap 'rm -rf "$case_root"' EXIT
install_dir="${case_root}/installed-bin"
publisher_dir="${case_root}/publisher"
shim_dir="${case_root}/shims"
mkdir -p "$install_dir" "$publisher_dir/archive" "$shim_dir"

printf '%s\n' '#!/bin/sh' 'printf old-sentinel' >"${install_dir}/agenthound"
chmod 0755 "${install_dir}/agenthound"

# The downloaded binary runs successfully in staging, then fails only from the
# final destination. This exercises post-promotion rollback rather than merely
# rejecting an archive before installation.
printf '%s\n' \
  '#!/bin/sh' \
  'if [ "$0" = "$FAIL_INSTALL_PATH" ]; then exit 1; fi' \
  'printf "agenthound version 1.1.0 (installer atomic test)\n"' \
  >"${publisher_dir}/archive/agenthound"
chmod 0755 "${publisher_dir}/archive/agenthound"

archive="${publisher_dir}/agenthound_1.1.0_${test_os}_${test_arch}.tar.gz"
tar -czf "$archive" -C "${publisher_dir}/archive" agenthound
if command -v sha256sum >/dev/null 2>&1; then
  archive_hash=$(sha256sum "$archive" | awk '{print $1}')
else
  archive_hash=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
printf '%s  %s\n' "$archive_hash" "$(basename "$archive")" >"${publisher_dir}/checksums.txt"

printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'out=' \
  'url=' \
  'while [ "$#" -gt 0 ]; do' \
  '  case "$1" in' \
  '    -o) out=$2; shift 2 ;;' \
  '    -*) shift ;;' \
  '    *) url=$1; shift ;;' \
  '  esac' \
  'done' \
  'case "$url" in' \
  '  */checksums.txt.sigstore.json) : >"$out" ;;' \
  '  */checksums.txt) cp "$TEST_PUBLISHER/checksums.txt" "$out" ;;' \
  '  */agenthound_*.tar.gz) cp "$TEST_ARCHIVE" "$out" ;;' \
  '  *) exit 22 ;;' \
  'esac' \
  >"${shim_dir}/curl"
printf '%s\n' '#!/bin/sh' 'exit 0' >"${shim_dir}/cosign"
chmod 0755 "${shim_dir}/curl" "${shim_dir}/cosign"

if env \
  PATH="${shim_dir}:${PATH}" \
  HOME="${case_root}/home" \
  AGENTHOUND_VERSION=1.1.0 \
  AGENTHOUND_INSTALL_DIR="$install_dir" \
  FAIL_INSTALL_PATH="${install_dir}/agenthound" \
  TEST_ARCHIVE="$archive" \
  TEST_PUBLISHER="$publisher_dir" \
  sh "${repo_root}/install.sh" >/dev/null 2>&1; then
  printf 'installer unexpectedly accepted a binary that failed after promotion\n' >&2
  exit 1
fi

if [ "$("${install_dir}/agenthound")" != old-sentinel ]; then
  printf 'installer did not restore the previous working binary\n' >&2
  exit 1
fi
if find "$install_dir" -maxdepth 1 \( -name '.agenthound.install.*' -o -name '.agenthound.backup.*' \) | grep -q .; then
  printf 'installer left private promotion files behind after rollback\n' >&2
  exit 1
fi

printf 'installer atomic replacement rollback: pass\n'
