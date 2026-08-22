#!/usr/bin/env bash
# Required CI smoke: configured MCP credential -> local planner proof -> manual ingest.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.smoke.yml"
PROJECT="agenthound-smoke-${GITHUB_RUN_ID:-local}-$$"
WORK_DIR="$(mktemp -d)"
BIN_DIR="${WORK_DIR}/bin"
HOME_DIR="${WORK_DIR}/home"
ARTIFACT="${WORK_DIR}/scan.json"
FINDINGS="${WORK_DIR}/findings.json"
TOKEN=agenthound-smoke-bearer-not-production
STACK_STARTED=0

case "$(uname -s)" in
  Darwin)
    CLAUDE_CONFIG="${HOME_DIR}/Library/Application Support/Claude/claude_desktop_config.json"
    ;;
  *)
    CLAUDE_CONFIG="${HOME_DIR}/.config/Claude/claude_desktop_config.json"
    ;;
esac

compose() {
  docker compose --project-name "${PROJECT}" -f "${COMPOSE_FILE}" "$@"
}

cleanup() {
  local exit_code=$?
  if ((STACK_STARTED == 1)); then
    if ((exit_code != 0)); then
      printf '\n==> Smoke stack logs\n' >&2
      compose logs --no-color >&2 || true
    fi
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "${WORK_DIR}"
  exit "${exit_code}"
}
trap cleanup EXIT

for command in docker go jq; do
  command -v "${command}" >/dev/null || {
    printf 'missing required command: %s\n' "${command}" >&2
    exit 1
  }
done
docker compose version >/dev/null

mkdir -p \
  "${BIN_DIR}" \
  "${HOME_DIR}/.cursor" \
  "$(dirname "${CLAUDE_CONFIG}")"

cd "${REPO_ROOT}"
printf '==> Building collector and server\n'
go build -trimpath -o "${BIN_DIR}/agenthound" ./collector/cmd/agenthound
go build -trimpath -o "${BIN_DIR}/agenthound-server" ./server/cmd/agenthound-server

printf '==> Starting minimal MCP and analysis stack\n'
STACK_STARTED=1
compose up -d --wait --build

published_port() {
  local address
  address="$(compose port "$1" "$2")"
  printf '%s\n' "${address##*:}"
}

MCP_PORT="$(published_port mcp-bearer-gate 3003)"
MCP_PUBLIC_PORT="$(published_port mcp-streamable 3001)"
PG_PORT="$(published_port postgres 5432)"
NEO4J_PORT="$(published_port neo4j 7687)"
MCP_URL="http://127.0.0.1:${MCP_PORT}/mcp"
MCP_PUBLIC_URL="http://127.0.0.1:${MCP_PUBLIC_PORT}/mcp"

jq -n \
  --arg url "${MCP_PUBLIC_URL}" '{
  mcpServers: {
    "agenthound-public-source": {
      url: $url
    }
  }
}' >"${HOME_DIR}/.cursor/mcp.json"

jq -n \
  --arg url "${MCP_URL}" \
  --arg authorization "Bearer ${TOKEN}" '{
  mcpServers: {
    "agenthound-proof-gate": {
      url: $url,
      headers: {Authorization: $authorization}
    }
  }
}' >"${CLAUDE_CONFIG}"

printf '==> Running active targetless scan\n'
(
  cd "${HOME_DIR}"
  HOME="${HOME_DIR}" "${BIN_DIR}/agenthound" scan \
    --timeout 2m \
    --output "${ARTIFACT}" \
    --quiet
)

printf '==> Validating planner proof artifact\n'
jq -e --arg token "${TOKEN}" '
  .meta.version == 1 and
  .meta.collector == "scan" and
  .meta.extra.scan_execution.status == "completed" and
  .meta.extra.scan_execution.summary.cleanup_failures == 0 and
  any(.graph.nodes[];
    (.kinds | index("Credential")) != null and
    .properties.value == $token and
    (.properties.value_hash | type == "string" and length > 0)) and
  any(.graph.nodes[];
    (.kinds | index("MCPResource")) != null) and
  any(.graph.edges[];
    .kind == "CREDENTIAL_ACCESS_OBSERVED" and
    .properties.action == "credential_reach" and
    .properties.proof_type == "differential_resource_read" and
    .properties.control_status == "denied" and
    .properties.credential_status == "allowed" and
    .properties.credential_resource_addressed == true)
' "${ARTIFACT}" >/dev/null

export AGENTHOUND_PG_URI="postgres://agenthound:agenthound-smoke@127.0.0.1:${PG_PORT}/agenthound?sslmode=disable"
export AGENTHOUND_NEO4J_URI="bolt://127.0.0.1:${NEO4J_PORT}"
export AGENTHOUND_NEO4J_USER=neo4j
export AGENTHOUND_NEO4J_PASSWORD=agenthound-smoke
export AGENTHOUND_EXPECTED_NEO4J_MAJOR=4

printf '==> Manually ingesting scan artifact\n'
"${BIN_DIR}/agenthound-server" ingest "${ARTIFACT}"

printf '==> Verifying published finding proof\n'
"${BIN_DIR}/agenthound-server" query --findings --format json >"${FINDINGS}"
jq -e '
  .scope.available == true and
  .scope.projection_status == "complete" and
  any(.findings[];
    .evidence.state == "verified" and
    .evidence.proof.action == "credential_reach" and
    .evidence.proof.proof_type == "differential_resource_read" and
    .evidence.proof.control_status == "denied" and
    .evidence.proof.credential_status == "allowed")
' "${FINDINGS}" >/dev/null

printf 'PASS: collector proof, artifact, manual ingest, and verified finding\n'
