#!/bin/sh
# AgentHound build preflight.
#
# Checks that the tools needed for a target are present on $PATH and
# meet minimum versions. Fails fast with an actionable error block when a
# required tool is missing or Go is older than the version declared in go.mod;
# warns when Node is below the supported major version.
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
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GO_REQUIRED=$(awk '$1 == "go" { print $2; exit }' "${SCRIPT_DIR}/../go.mod")

if [ -z "${GO_REQUIRED}" ]; then
  echo "preflight: could not read the required Go version from go.mod" >&2
  exit 1
fi

if [ "${AGENTHOUND_SKIP_PREFLIGHT:-0}" = "1" ]; then
  echo ">>> AgentHound preflight skipped (AGENTHOUND_SKIP_PREFLIGHT=1)"
  exit 0
fi

# Project pins. Go is read from go.mod so local checks and CI cannot drift.
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
ge_version() {
  awk -v have="$1" -v need="$2" 'BEGIN {
    split(have, h, "."); split(need, n, ".")
    for (i = 1; i <= 3; i++) {
      hv = h[i] + 0; nv = n[i] + 0
      if (hv > nv) exit 0
      if (hv < nv) exit 1
    }
    exit 0
  }'
}

check_go() {
  if ! command -v go >/dev/null 2>&1; then
    print_status FAIL go "not found" ""
    MISSING="${MISSING}go\n"
    return
  fi
  # `go version` -> "go version go1.25.13 darwin/arm64"
  ver=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
  need="${GO_REQUIRED}"
  if ge_version "$ver" "$need"; then
    print_status OK go "$ver" "(need >= ${need})"
  else
    print_status FAIL go "$ver" "(project requires >= ${need})"
    MISSING="${MISSING}go-version\n"
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

check_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    print_status FAIL docker "not found" ""
    MISSING="${MISSING}docker\n"
    return
  fi
  # `docker --version` -> "Docker version 27.4.0, build ..."
  ver=$(docker --version 2>/dev/null | awk '{print $3}' | sed 's/,$//')
  if [ -z "$ver" ]; then
    ver="present"
  fi
  # Daemon liveness check: `docker info` fails if dockerd isn't running.
  if ! docker info >/dev/null 2>&1; then
    print_status FAIL docker "$ver" "(daemon not reachable)"
    MISSING="${MISSING}docker-daemon\n"
    return
  fi
  print_status OK docker "$ver" ""
}

check_docker_compose() {
  # Every caller in this repo invokes `docker compose` (v2 plugin
  # syntax): Makefile up/down and all docs. The
  # legacy `docker-compose` v1 binary uses a different invocation
  # (`docker-compose -f ...`) and would fail the actual `make up`
  # immediately after a "passing" preflight — so accepting v1 here is
  # a false positive. Require v2.
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ver=$(docker compose version --short 2>/dev/null)
    [ -z "$ver" ] && ver="v2"
    print_status OK "compose" "$ver" "(docker compose plugin)"
    return
  fi
  print_status FAIL "compose" "not found" "(v2 plugin required)"
  MISSING="${MISSING}docker-compose\n"
}

check_curl() {
  if ! command -v curl >/dev/null 2>&1; then
    print_status FAIL curl "not found" ""
    MISSING="${MISSING}curl\n"
    return
  fi
  ver=$(curl --version 2>/dev/null | awk 'NR==1 {print $2}')
  [ -z "$ver" ] && ver="present"
  print_status OK curl "$ver" ""
}

check_python3() {
  if ! command -v python3 >/dev/null 2>&1; then
    print_status FAIL python3 "not found" ""
    MISSING="${MISSING}python3\n"
    return
  fi
  ver=$(python3 --version 2>/dev/null | awk '{print $2}')
  [ -z "$ver" ] && ver="present"
  print_status OK python3 "$ver" ""
}

check_server_running() {
  # Honor AGENTHOUND_URL (the var seed-test-data.sh uses); fall back
  # to AGENTHOUND_BIND_URL for backward compat with earlier preflight
  # versions.
  url="${AGENTHOUND_URL:-${AGENTHOUND_BIND_URL:-http://localhost:8080}}"
  # `make seed` and any other server-running consumer requires curl —
  # both for this probe and downstream (seed-test-data.sh runs curl
  # against /api/v1/ingest). Treat missing curl as a hard FAIL so the
  # user installs it before the seed run, not after a cryptic failure.
  if ! command -v curl >/dev/null 2>&1; then
    print_status FAIL curl "not found" ""
    MISSING="${MISSING}curl\n"
    return
  fi
  # Probe the REAL health endpoint (/api/v1/health). The bare /health
  # path also returns HTTP 200 because the React SPA fallback catches
  # it — that would be a false positive ("server up" when actually it's
  # only the embedded UI fallback page responding). Verify the JSON
  # body claims status:ok so we know the API + DBs are actually wired.
  body=$(curl -fsSL --max-time 2 "${url}/api/v1/health" 2>/dev/null || true)
  if [ -n "$body" ] && printf '%s' "$body" | grep -q '"status":"ok"'; then
    print_status OK server "up" "(${url}/api/v1/health)"
    return
  fi
  print_status FAIL server "not reachable" "(${url}/api/v1/health)"
  MISSING="${MISSING}server\n"
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
  docker)
    check_docker
    ;;
  docker-compose)
    check_docker
    check_docker_compose
    ;;
  server-running)
    check_server_running
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
      go)             echo "    go              — install Go ${GO_REQUIRED}+ from https://go.dev/dl/" ;;
      go-version)     echo "    go              — upgrade to Go ${GO_REQUIRED}+ from https://go.dev/dl/" ;;
      node)           echo "    node            — install Node.js 20+ from https://nodejs.org/en/download" ;;
      npm)            echo "    npm             — usually installed with Node.js. https://nodejs.org/en/download" ;;
      docker)         echo "    docker          — install Docker Desktop / Engine from https://docs.docker.com/engine/install/" ;;
      docker-daemon)  echo "    docker daemon   — Docker is installed but the daemon isn't running. Start Docker Desktop or 'sudo systemctl start docker'." ;;
      docker-compose) echo "    docker compose  — install the v2 plugin (https://docs.docker.com/compose/install/) — comes with Docker Desktop by default." ;;
      curl)           echo "    curl            — install curl (preinstalled on most systems; on Debian/Ubuntu: 'sudo apt install curl', on macOS via Homebrew: 'brew install curl')." ;;
      python3)        echo "    python3         — install Python 3 or ensure it is on PATH." ;;
      server)         echo "    agenthound-server — start the server first with: docker compose -f docker/docker-compose.yml up -d  (or 'make up')" ;;
      *)              echo "    $tool — see https://docs.agenthound.io/getting-started/install/" ;;
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
