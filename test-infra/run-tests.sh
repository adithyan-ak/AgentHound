#!/usr/bin/env bash
# Manual end-to-end harness for the unified autonomous collector.
set -Eeuo pipefail

KEEP=0
for arg in "$@"; do
  case "${arg}" in
    --keep) KEEP=1 ;;
    -h | --help)
      printf 'Usage: bash test-infra/run-tests.sh [--keep]\n'
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "${arg}" >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ARTIFACTS_DIR="${SCRIPT_DIR}/artifacts/${RUN_ID}"
BIN_DIR="${SCRIPT_DIR}/services/workstation/bin"
ACTIVE_CONTAINER_PATH=/tmp/agenthound-active.json
STEALTH_CONTAINER_PATH=/tmp/agenthound-stealth.json
ACTIVE_ARTIFACT="${ARTIFACTS_DIR}/active.json"
STEALTH_ARTIFACT="${ARTIFACTS_DIR}/stealth.json"
STACK_STARTED=0

compose() { docker compose -f "${COMPOSE_FILE}" "$@"; }
ws() { compose exec -T workstation "$@"; }

# shellcheck source=lib/wait-ready.sh
source "${SCRIPT_DIR}/lib/wait-ready.sh"

cleanup() {
  local ec=$?
  if ((STACK_STARTED == 1 && KEEP == 0)); then
    compose --profile analysis down -v --remove-orphans >/dev/null 2>&1 || true
  elif ((STACK_STARTED == 1)); then
    printf 'Stack retained: docker compose -f %s ps\n' "${COMPOSE_FILE}" >&2
    printf 'Artifacts: %s\n' "${ARTIFACTS_DIR}" >&2
  fi
  exit "${ec}"
}
trap cleanup EXIT

for command in docker go jq; do
  command -v "${command}" >/dev/null || {
    printf 'missing required command: %s\n' "${command}" >&2
    exit 1
  }
done

cd "${REPO_ROOT}"
mkdir -p "${ARTIFACTS_DIR}" "${BIN_DIR}" "${SCRIPT_DIR}/fixtures"

printf '==> Building collector and server\n'
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags='-s -w' -o "${BIN_DIR}/agenthound" ./collector/cmd/agenthound
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags='-s -w' -o "${BIN_DIR}/agenthound-server" ./server/cmd/agenthound-server

printf '==> Starting and seeding upstream services\n'
STACK_STARTED=1
compose up -d --wait --build
wait_ready "${COMPOSE_FILE}" 1200
bash "${SCRIPT_DIR}/lib/seed-services.sh" "${COMPOSE_FILE}"
bash "${SCRIPT_DIR}/lib/verify-upstreams.sh" \
  "${COMPOSE_FILE}" "${SCRIPT_DIR}/fixtures/upstream-truth.json"

CONTEXTFORGE_TOKEN="$(jq -er '.contextforge.token' "${SCRIPT_DIR}/fixtures/runtime.json")"
MASTER_KEY="$(ws sh -c 'printf %s "$AGENTHOUND_LITELLM_MASTER_KEY"')"

printf '==> Running one deep active scan\n'
compose exec -T -e "AGENTHOUND_CONTEXTFORGE_TOKEN=${CONTEXTFORGE_TOKEN}" workstation \
  agenthound scan 10.20.30.0/24 --deep --timeout 15m \
  --output "${ACTIVE_CONTAINER_PATH}" --quiet

printf '==> Running one targetless stealth scan\n'
compose exec -T -e "AGENTHOUND_CONTEXTFORGE_TOKEN=${CONTEXTFORGE_TOKEN}" workstation \
  agenthound scan --stealth --timeout 5m \
  --output "${STEALTH_CONTAINER_PATH}" --quiet

WORKSTATION_ID="$(compose ps -q workstation)"
docker cp "${WORKSTATION_ID}:${ACTIVE_CONTAINER_PATH}" "${ACTIVE_ARTIFACT}" >/dev/null
docker cp "${WORKSTATION_ID}:${STEALTH_CONTAINER_PATH}" "${STEALTH_ARTIFACT}" >/dev/null

printf '==> Validating unified artifact contracts\n'
jq -e --arg master "${MASTER_KEY}" '
  .meta.version == 1 and
  .meta.collector == "scan" and
  .meta.extra.scan_execution.version == 1 and
  .meta.extra.scan_execution.mode == "active" and
  .meta.extra.scan_execution.deep == true and
  .meta.extra.scan_execution.status == "completed" and
  (.meta.extra.scan_execution.actions | type == "array") and
  (.meta.extra.scan_execution.recovery | type == "array") and
  (.meta.extra.scan_execution.summary.cleanup_failures == 0) and
  any(.graph.nodes[]; (.kinds | index("Credential")) != null and .properties.value == $master) and
  any(.graph.nodes[]; (.kinds | index("LiteLLMGateway")) != null) and
  any(.graph.nodes[]; (.kinds | index("OllamaInstance")) != null) and
  any(.graph.nodes[]; (.kinds | index("QdrantInstance")) != null) and
  any(.meta.extra.scan_execution.actions[];
    .action == "ollama.embedding.invoke" and
    .status == "succeeded" and
    .outcome == "embedding_compute_observed") and
  all(.graph.nodes[]; (.kinds | index("ExtractedTrainingSignal")) == null) and
  all(.graph.edges[]; .kind != "EXTRACTED_FROM" and .kind != "CREDENTIAL_REACH_VERIFIED")
' "${ACTIVE_ARTIFACT}" >/dev/null

jq -e '
  .meta.version == 1 and
  .meta.collector == "scan" and
  .meta.extra.scan_execution.mode == "stealth" and
  .meta.extra.scan_execution.deep == false and
  .meta.extra.scan_execution.status == "completed" and
  all(.meta.extra.scan_execution.actions[];
    .action != "credential_reach" and
    .action != "mcp.description.roundtrip" and
    .action != "a2a.credential.collect" and
    .action != "ollama.embedding.invoke" and
    .outcome != "embedding_compute_observed")
' "${STEALTH_ARTIFACT}" >/dev/null

printf '==> Manually ingesting the active artifact\n'
compose --profile analysis up -d --wait analysis-postgres analysis-neo4j
compose cp "${ACTIVE_ARTIFACT}" "workstation:${ACTIVE_CONTAINER_PATH}"
ws agenthound-server ingest "${ACTIVE_CONTAINER_PATH}" \
  >"${ARTIFACTS_DIR}/ingest.out" 2>"${ARTIFACTS_DIR}/ingest.stderr"

printf 'PASS: unified active/stealth scan and manual ingest\n'
