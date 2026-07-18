#!/usr/bin/env bash
set -Eeuo pipefail

DOWNLOAD_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOWNLOAD_TEST_INFRA_DIR="$(cd "${DOWNLOAD_SCRIPT_DIR}/.." && pwd)"
MODEL_DIR="${DOWNLOAD_TEST_INFRA_DIR}/fixtures/models"
MODEL_PATH="${MODEL_DIR}/stories260K.gguf"
MODEL_URL='https://huggingface.co/ggml-org/models/resolve/499bc8821c6b12b4e53c5bffcb21ec206f212d81/tinyllamas/stories260K.gguf'
MODEL_SHA256='270cba1bd5109f42d03350f60406024560464db173c0e387d91f0426d3bd256d'

mkdir -p "${MODEL_DIR}"
if [[ ! -f "${MODEL_PATH}" ]] || [[ "$(sha256_file "${MODEL_PATH}")" != "${MODEL_SHA256}" ]]; then
  curl --fail --location --retry 3 --output "${MODEL_PATH}.tmp" "${MODEL_URL}"
  [[ "$(sha256_file "${MODEL_PATH}.tmp")" == "${MODEL_SHA256}" ]] || {
    rm -f "${MODEL_PATH}.tmp"
    fail 'official GGUF checksum did not match UPSTREAMS.md'
  }
  mv "${MODEL_PATH}.tmp" "${MODEL_PATH}"
fi

[[ "$(LC_ALL=C od -An -tx1 -N4 "${MODEL_PATH}" | tr -d ' \n')" == '47475546' ]] ||
  fail 'official GGUF does not have the standard GGUF byte magic'
printf 'Verified official GGUF fixture (%s).\n' "${MODEL_SHA256}"
