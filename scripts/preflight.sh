#!/bin/sh
# AgentHound build preflight.
#
# Checks that the tools needed for a target are present on $PATH and
# meet minimum major versions. Fails fast with an actionable error block
# when something is missing; warns (but does not fail) when a tool exists
# but is below the project's pinned major version.
#
# Usage:
#   scripts/preflight.sh build              # go + node + npm
#   scripts/preflight.sh build-collector    # go only
#   scripts/preflight.sh build-server       # go + node + npm
#
# Bypass (e.g. CI that already vets tools):
#   AGENTHOUND_SKIP_PREFLIGHT=1 make build

set -e

TARGET="${1:-build}"

if [ "${AGENTHOUND_SKIP_PREFLIGHT:-0}" = "1" ]; then
  echo ">>> AgentHound preflight skipped (AGENTHOUND_SKIP_PREFLIGHT=1)"
  exit 0
fi

# Project pins (kept in sync with go.mod + .github/workflows/ci.yml).
GO_MIN_MAJOR=1
GO_MIN_MINOR=25
NODE_MIN_MAJOR=20

# Accumulators. POSIX sh has no arrays, so newline-separated strings.
MISSING=""
HAS_WARN=0

# print_status <state> <tool> <version> <note>
#   state ∈ OK | WARN | FAIL
print_status() {
  printf '    [%-4s] %-5s %-10s %s\n' "$1" "$2" "$3" "$4"
}

# Compare two dotted versions: returns 0 if $1 >= $2.
# Only looks at the first two components (major.minor).
ge_version() {
  have_major=$(echo "$1" | awk -F. '{print $1+0}')
  have_minor=$(echo "$1" | awk -F. '{print $2+0}')
  need_major=$(echo "$2" | awk -F. '{print $1+0}')
  need_minor=$(echo "$2" | awk -F. '{print $2+0}')
  if [ "$have_major" -gt "$need_major" ]; then return 0; fi
  if [ "$have_major" -lt "$need_major" ]; then return 1; fi
  if [ "$have_minor" -ge "$need_minor" ]; then return 0; fi
  return 1
}

check_go() {
  if ! command -v go >/dev/null 2>&1; then
    print_status FAIL go "not found" ""
    MISSING="${MISSING}go\n"
    return
  fi
  # `go version` -> "go version go1.25.11 darwin/arm64"
  ver=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
  need="${GO_MIN_MAJOR}.${GO_MIN_MINOR}"
  if ge_version "$ver" "$need"; then
    print_status OK go "$ver" "(need >= ${need})"
  else
    print_status WARN go "$ver" "(project pins >= ${need} — CI uses 1.25.11)"
    HAS_WARN=1
  fi
}

check_node() {
  if ! command -v node >/dev/null 2>&1; then
    print_status FAIL node "not found" ""
    MISSING="${MISSING}node\n"
    return
  fi
  # `node -v` -> "v20.18.0"
  ver=$(node -v 2>/dev/null | sed 's/^v//')
  need="${NODE_MIN_MAJOR}"
  if ge_version "$ver" "${need}.0"; then
    print_status OK node "v${ver}" "(need >= v${need})"
  else
    print_status WARN node "v${ver}" "(project pins >= v${need} — CI uses Node 20)"
    HAS_WARN=1
  fi
}

check_npm() {
  if ! command -v npm >/dev/null 2>&1; then
    print_status FAIL npm "not found" ""
    MISSING="${MISSING}npm\n"
    return
  fi
  ver=$(npm -v 2>/dev/null)
  print_status OK npm "$ver" "(bundled with Node)"
}

echo ">>> AgentHound preflight (target: ${TARGET})"

case "$TARGET" in
  build|build-server)
    check_go
    check_node
    check_npm
    ;;
  build-collector)
    check_go
    ;;
  *)
    # Unknown targets: be conservative and check everything.
    check_go
    check_node
    check_npm
    ;;
esac

if [ -n "$MISSING" ]; then
  echo ""
  echo "  Missing prerequisites:"
  # shellcheck disable=SC2059
  printf "$MISSING" | while IFS= read -r tool; do
    [ -z "$tool" ] && continue
    case "$tool" in
      go)   echo "    go    — install Go 1.25+ from https://go.dev/dl/" ;;
      node) echo "    node  — install Node.js 20+ from https://nodejs.org/en/download" ;;
      npm)  echo "    npm   — usually installed with Node.js. https://nodejs.org/en/download" ;;
      *)    echo "    $tool — see project README" ;;
    esac
  done
  echo ""
  echo "  Re-run after installing, or set AGENTHOUND_SKIP_PREFLIGHT=1 to bypass."
  echo ""
  exit 1
fi

if [ "$HAS_WARN" = "1" ]; then
  echo ">>> Preflight passed (with warnings)."
else
  echo ">>> Preflight passed."
fi
