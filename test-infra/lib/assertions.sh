#!/usr/bin/env bash

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  return 1
}

pass() {
  printf 'PASS: %s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 ||
    fail "required command not found: $1"
}

assert_json() {
  local name="$1"
  local artifact="$2"
  local expectation="$3"
  local output

  if [[ ! -f "${artifact}" ]]; then
    fail "${name}: missing artifact ${artifact}"
    return 1
  fi
  if [[ ! -f "${expectation}" ]]; then
    fail "${name}: missing expectation ${expectation}"
    return 1
  fi

  if output="$(jq -e -f "${expectation}" "${artifact}" 2>&1)"; then
    pass "${name}"
    return 0
  fi

  printf 'FAIL: %s\n' "${name}" >&2
  printf '  artifact: %s\n' "${artifact}" >&2
  printf '  expectation: %s\n' "${expectation}" >&2
  printf '  jq output: %s\n' "${output:-<none>}" >&2
  printf '  expectation source:\n' >&2
  while IFS= read -r line; do
    printf '    %s\n' "${line}" >&2
  done <"${expectation}"
  return 1
}

assert_eq() {
  local name="$1"
  local got="$2"
  local want="$3"
  if [[ "${got}" == "${want}" ]]; then
    pass "${name}"
    return 0
  fi
  fail "${name}: got '$(printf '%s' "${got}" | tr '\n' ' ')', want '$(printf '%s' "${want}" | tr '\n' ' ')'"
}

assert_contains() {
  local name="$1"
  local haystack="$2"
  local needle="$3"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    pass "${name}"
    return 0
  fi
  fail "${name}: expected to contain '${needle}'"
}

assert_not_contains() {
  local name="$1"
  local haystack="$2"
  local needle="$3"
  if [[ "${haystack}" != *"${needle}"* ]]; then
    pass "${name}"
    return 0
  fi
  fail "${name}: did not expect '${needle}'"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

sha256_text() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | awk '{print $1}'
  else
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  fi
}

write_status_json() {
  local path="$1"
  shift
  mkdir -p "$(dirname "${path}")"
  jq -n "$@" >"${path}.tmp"
  mv "${path}.tmp" "${path}"
}
