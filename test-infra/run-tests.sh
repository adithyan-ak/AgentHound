#!/usr/bin/env bash
# Manual collector compatibility harness. Upstream validation is a hard gate;
# collector mismatches are aggregated so one defect never hides another.
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
EXPECTED_DIR="${SCRIPT_DIR}/expected"
BIN_DIR="${SCRIPT_DIR}/services/workstation/bin"
COLLECTOR_BIN="${BIN_DIR}/agenthound"
HOST_COLLECTOR_BIN="${BIN_DIR}/agenthound-host"
RESULTS_FILE="${ARTIFACTS_DIR}/results.ndjson"

# shellcheck source=lib/assertions.sh
source "${SCRIPT_DIR}/lib/assertions.sh"
# shellcheck source=lib/wait-ready.sh
source "${SCRIPT_DIR}/lib/wait-ready.sh"

require_command curl
require_command docker
require_command go
require_command jq

[[ "$(go env GOOS)" == darwin ]] ||
  fail 'full harness requires macOS for the host-native Claude Desktop path lane'

STACK_STARTED=0
RUN_PHASE=harness_validation
COLLECTOR_FAILURES=0

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

ws() {
  local -a env_args=()
  if [[ -n "${AGENTHOUND_CONTEXTFORGE_TOKEN:-}" ]]; then
    env_args+=( -e "AGENTHOUND_CONTEXTFORGE_TOKEN=${AGENTHOUND_CONTEXTFORGE_TOKEN}" )
  fi
  if [[ -n "${AGENTHOUND_CAMPAIGN_CREDENTIAL:-}" ]]; then
    env_args+=( -e "AGENTHOUND_CAMPAIGN_CREDENTIAL=${AGENTHOUND_CAMPAIGN_CREDENTIAL}" )
  fi
  compose exec -T "${env_args[@]}" workstation "$@"
}

cleanup() {
  local ec=$?
  if ((ec != 0)) && [[ -d "${ARTIFACTS_DIR}" ]] &&
    [[ ! -f "${ARTIFACTS_DIR}/summary.json" ]]; then
    if [[ -f "${RESULTS_FILE}" ]]; then
      jq -s --arg run_id "${RUN_ID}" --arg phase "${RUN_PHASE}" '
        {
          run_id:$run_id,
          harness_status:"invalid",
          failure_phase:$phase,
          collector_status:"not_evaluated",
          collector_failures:0,
          results:.
        }
      ' "${RESULTS_FILE}" >"${ARTIFACTS_DIR}/summary.json" 2>/dev/null || true
    fi
  fi
  if ((STACK_STARTED == 0)); then
    return
  fi
  if ((KEEP == 0)); then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    return
  fi
  printf '\nStack retained for inspection:\n  docker compose -f %s ps\n' "${COMPOSE_FILE}" >&2
  printf 'Artifacts: %s\n' "${ARTIFACTS_DIR}" >&2
}
trap cleanup EXIT

record_result() {
  local name="$1"
  local status="$2"
  local reason="${3:-}"
  jq -nc \
    --arg name "${name}" \
    --arg status "${status}" \
    --arg reason "${reason}" \
    '{name:$name,status:$status,reason:$reason}' >>"${RESULTS_FILE}"
  if [[ "${status}" == collector_failure ]]; then
    COLLECTOR_FAILURES=$((COLLECTOR_FAILURES + 1))
  fi
}

collector_failure() {
  local name="$1"
  local reason="$2"
  fail "${name}: ${reason}" || true
  record_result "${name}" collector_failure "${reason}"
}

assert_no_raw_secrets() {
  local name="$1"
  shift
  local path secret
  local -a secrets=(
    'sk-local-agenthound-master-key-not-production'
    'sk-agenthound-openwebui-upstream-not-production'
    'sk-placeholder-openai-key-not-real'
    'sk-ant-placeholder-key-not-real'
    'sk-placeholder-decoy-key-not-real'
    'sk-placeholder-qdrant-key-not-real'
    'sk-placeholder-support-key-not-real'
    'sk-placeholder-jupyter-openai-key-not-real'
    'sk-ant-placeholder-jupyter-key-not-real'
    'agenthound-jupyter-token'
    'litellm-local-password'
    'Harness-Admin-Password-2026!'
    'Harness-OpenWebUI-Password-2026!'
    'agenthound-contextforge-jwt-secret-32-bytes-minimum'
    'agenthound-contextforge-encryption-secret-32-bytes'
    "${AGENTHOUND_CONTEXTFORGE_TOKEN:-}"
    "${OPENWEBUI_TOKEN:-}"
  )
  for path in "$@"; do
    [[ -f "${path}" ]] || continue
    for secret in "${secrets[@]}"; do
      [[ -n "${secret}" ]] || continue
      if grep -F -- "${secret}" "${path}" >/dev/null; then
        fail "${name}: raw credential leaked into $(basename "${path}")"
        return 1
      fi
    done
  done
}

run_json() {
  local name="$1"
  shift
  local artifact="${ARTIFACTS_DIR}/${name}.json"
  local stderr_path="${ARTIFACTS_DIR}/${name}.stderr"
  local expectation="${EXPECTED_DIR}/${name}.jq"
  local ec=0

  printf '\n==> %s\n' "${name}"
  set +e
  ws agenthound --quiet "$@" >"${artifact}" 2>"${stderr_path}"
  ec=$?
  set -e

  if ((ec != 0)); then
    collector_failure "${name}" "collector exited ${ec}; see ${stderr_path}"
    return 0
  fi
  if ! jq -e . "${artifact}" >/dev/null 2>&1; then
    collector_failure "${name}" 'collector output is not valid JSON'
    return 0
  fi
  if ! assert_no_raw_secrets "${name}" "${artifact}" "${stderr_path}"; then
    collector_failure "${name}" 'raw credential disclosure'
    return 0
  fi
  if ! assert_json "${name}" "${artifact}" "${expectation}"; then
    collector_failure "${name}" 'output disagrees with independently verified upstream truth'
    return 0
  fi
  record_result "${name}" pass
}

run_host_json() {
  local name=scan-config-host
  local artifact="${ARTIFACTS_DIR}/${name}.json"
  local stderr_path="${ARTIFACTS_DIR}/${name}.stderr"
  local ec=0

  printf '\n==> %s\n' "${name}"
  set +e
  HOME="${SCRIPT_DIR}/host-home" "${HOST_COLLECTOR_BIN}" --quiet \
    scan --config --output - >"${artifact}" 2>"${stderr_path}"
  ec=$?
  set -e
  if ((ec != 0)); then
    collector_failure "${name}" "collector exited ${ec}; see ${stderr_path}"
    return
  fi
  if ! assert_no_raw_secrets "${name}" "${artifact}" "${stderr_path}"; then
    collector_failure "${name}" 'raw credential disclosure'
    return
  fi
  if ! assert_json "${name}" "${artifact}" "${EXPECTED_DIR}/${name}.jq"; then
    collector_failure "${name}" 'macOS Claude Desktop discovery disagrees with the real path/format'
    return
  fi
  record_result "${name}" pass
}

run_smoke() {
  local name="$1"
  shift
  local ec=0
  set +e
  ws agenthound --quiet "$@" >"${ARTIFACTS_DIR}/${name}.out" 2>"${ARTIFACTS_DIR}/${name}.stderr"
  ec=$?
  set -e
  if ((ec != 0)); then
    collector_failure "${name}" "collector exited ${ec}"
    return
  fi
  pass "${name}"
  record_result "${name}" pass
}

file_sha_in_ws() {
  ws sha256sum "$1" | awk '{print $1}'
}

contextforge_description() {
  ws curl -fsS \
    -H "Authorization: Bearer ${AGENTHOUND_CONTEXTFORGE_TOKEN}" \
    "http://contextforge:4444/v1/tools/${CONTEXTFORGE_TOOL_ID}" |
    jq -er '.description'
}

contextforge_set_description() {
  local description="$1"
  ws curl -fsS -X PUT \
    -H "Authorization: Bearer ${AGENTHOUND_CONTEXTFORGE_TOKEN}" \
    -H 'Content-Type: application/json' \
    --data "$(jq -nc --arg description "${description}" '{description:$description}')" \
    "http://contextforge:4444/v1/tools/${CONTEXTFORGE_TOOL_ID}" >/dev/null
}

restore_contextforge_description() {
  local expected="$1"
  local current
  current="$(contextforge_description 2>/dev/null || true)"
  if [[ "${current}" != "${expected}" ]]; then
    contextforge_set_description "${expected}" || true
  fi
}

refresh_contextforge_token() {
  AGENTHOUND_CONTEXTFORGE_TOKEN="$(jq -er '.contextforge.token' "${SCRIPT_DIR}/fixtures/runtime.json")"
  export AGENTHOUND_CONTEXTFORGE_TOKEN
}

run_contextforge_poison() {
  local name=poison-mcp
  local engagement=RTV-POISON-MCP
  local inject=TAMPERED-BY-AGENTHOUND-OFFLINE-HARNESS
  local before after restored ec=0
  before="$(contextforge_description)"

  set +e
  ws agenthound --quiet poison "${CONTEXTFORGE_MCP_URL}" \
    --type mcp.tool.description \
    --adapter contextforge \
    --management-url http://contextforge:4444 \
    --target-id support-lookup \
    --inject "${inject}" \
    --commit --engagement-id "${engagement}" \
    >"${ARTIFACTS_DIR}/${name}.out" 2>"${ARTIFACTS_DIR}/${name}.stderr"
  ec=$?
  set -e
  after="$(contextforge_description)"

  if ((ec != 0)); then
    if [[ "${after}" != "${before}" ]]; then
      ws agenthound --quiet revert "${engagement}" \
        >"${ARTIFACTS_DIR}/${name}-cleanup.out" \
        2>"${ARTIFACTS_DIR}/${name}-cleanup.stderr" || true
    fi
    restore_contextforge_description "${before}"
    collector_failure "${name}" "collector is incompatible with the real ContextForge management API (exit ${ec})"
    return
  fi
  if [[ "${after}" != *"${inject}"* ]]; then
    restore_contextforge_description "${before}"
    collector_failure "${name}" 'collector reported success but the real tool was not changed'
    return
  fi
  if ! ws agenthound --quiet revert "${engagement}" \
    >"${ARTIFACTS_DIR}/${name}-revert.out" \
    2>"${ARTIFACTS_DIR}/${name}-revert.stderr"; then
    restore_contextforge_description "${before}"
    collector_failure "${name}" 'revert failed against real ContextForge'
    return
  fi
  restored="$(contextforge_description)"
  if [[ "${restored}" != "${before}" ]]; then
    restore_contextforge_description "${before}"
    collector_failure "${name}" 'revert did not restore the exact upstream description'
    return
  fi
  write_status_json "${ARTIFACTS_DIR}/${name}.json" \
    --arg engagement "${engagement}" \
    --arg before "${before}" --arg after "${after}" --arg restored "${restored}" \
    '{ok:true,engagement_id:$engagement,mutated:($before != $after),reverted:($before == $restored),before:$before,after:$after,restored:$restored}'
  if ! assert_json "${name}" "${ARTIFACTS_DIR}/${name}.json" "${EXPECTED_DIR}/${name}.jq"; then
    collector_failure "${name}" 'mutation state oracle failed'
    return
  fi
  record_result "${name}" pass
}

run_instruction_poison() {
  local name=poison-instruction
  local engagement=RTV-POISON-INSTR
  local path=/root/projects/example/CLAUDE.md
  local before after restored ec=0
  ws /usr/local/bin/workstation-entrypoint restore-fixtures
  before="$(file_sha_in_ws "${path}")"
  set +e
  ws agenthound --quiet poison workstation \
    --type instruction.file --file "${path}" \
    --inject TAMPERED-INSTRUCTION-BLOCK \
    --commit --engagement-id "${engagement}" \
    >"${ARTIFACTS_DIR}/${name}.out" 2>"${ARTIFACTS_DIR}/${name}.stderr"
  ec=$?
  set -e
  if ((ec != 0)); then
    ws /usr/local/bin/workstation-entrypoint restore-fixtures || true
    collector_failure "${name}" "collector exited ${ec}"
    return
  fi
  after="$(file_sha_in_ws "${path}")"
  if ! ws agenthound --quiet revert "${engagement}" \
    >"${ARTIFACTS_DIR}/${name}-revert.out" 2>"${ARTIFACTS_DIR}/${name}-revert.stderr"; then
    ws /usr/local/bin/workstation-entrypoint restore-fixtures || true
    collector_failure "${name}" 'revert failed'
    return
  fi
  restored="$(file_sha_in_ws "${path}")"
  write_status_json "${ARTIFACTS_DIR}/${name}.json" \
    --arg before "${before}" --arg after "${after}" --arg restored "${restored}" \
    '{ok:true,engagement_id:"RTV-POISON-INSTR",mutated:($before != $after),reverted:($before == $restored),before_hash:$before,after_hash:$after,restored_hash:$restored}'
  if ! assert_json "${name}" "${ARTIFACTS_DIR}/${name}.json" "${EXPECTED_DIR}/${name}.jq"; then
    collector_failure "${name}" 'mutation/revert oracle failed'
    return
  fi
  record_result "${name}" pass
}

run_config_implant() {
  local name=implant-mcp-config
  local engagement=RTV-IMPLANT
  local path=/root/.cursor/mcp.json
  local server_name=agenthound-implant-fixture
  local inject='{"command":"/usr/local/bin/mcp-server-everything","args":["stdio"]}'
  local before after restored before_canon restored_canon ec=0
  ws /usr/local/bin/workstation-entrypoint restore-fixtures
  before="$(file_sha_in_ws "${path}")"
  before_canon="$(ws jq -S -c . "${path}")"
  set +e
  ws agenthound --quiet implant workstation \
    --type mcp.config.malicious-server --file "${path}" \
    --server-name "${server_name}" --inject "${inject}" \
    --commit --engagement-id "${engagement}" \
    >"${ARTIFACTS_DIR}/${name}.out" 2>"${ARTIFACTS_DIR}/${name}.stderr"
  ec=$?
  set -e
  if ((ec != 0)); then
    ws /usr/local/bin/workstation-entrypoint restore-fixtures || true
    collector_failure "${name}" "collector exited ${ec}"
    return
  fi
  after="$(file_sha_in_ws "${path}")"
  if ! ws jq -e --arg name "${server_name}" \
    '.mcpServers[$name].command == "/usr/local/bin/mcp-server-everything" and .mcpServers[$name].args == ["stdio"]' \
    "${path}" >/dev/null; then
    ws /usr/local/bin/workstation-entrypoint restore-fixtures || true
    collector_failure "${name}" 'implant did not create a launchable real MCP entry'
    return
  fi
  if ! ws agenthound --quiet revert "${engagement}" \
    >"${ARTIFACTS_DIR}/${name}-revert.out" 2>"${ARTIFACTS_DIR}/${name}-revert.stderr"; then
    ws /usr/local/bin/workstation-entrypoint restore-fixtures || true
    collector_failure "${name}" 'revert failed'
    return
  fi
  restored="$(file_sha_in_ws "${path}")"
  restored_canon="$(ws jq -S -c . "${path}")"
  write_status_json "${ARTIFACTS_DIR}/${name}.json" \
    --arg before "${before}" --arg after "${after}" --arg restored "${restored}" \
    --arg server "${server_name}" \
    --argjson semantic_reverted "$([[ "${restored_canon}" == "${before_canon}" ]] && printf true || printf false)" \
    '{ok:true,engagement_id:"RTV-IMPLANT",server_name:$server,mutated:($before != $after),reverted:$semantic_reverted,semantic_reverted:$semantic_reverted,before_hash:$before,after_hash:$after,restored_hash:$restored}'
  if ! assert_json "${name}" "${ARTIFACTS_DIR}/${name}.json" "${EXPECTED_DIR}/${name}.jq"; then
    collector_failure "${name}" 'implant/revert oracle failed'
    return
  fi
  record_result "${name}" pass
}

run_contextforge_roundtrip() {
  local name=campaign-mcp-roundtrip
  local engagement=RTV-MCP-ROUNDTRIP
  local before after ec=0
  before="$(contextforge_description)"
  set +e
  ws agenthound --quiet campaign "${CONTEXTFORGE_MCP_URL}" \
    --scenario mcp-poison-roundtrip \
    --adapter contextforge \
    --management-url http://contextforge:4444 \
    --target-id support-lookup \
    --commit --engagement-id "${engagement}" \
    >"${ARTIFACTS_DIR}/${name}.out" 2>"${ARTIFACTS_DIR}/${name}.stderr"
  ec=$?
  set -e
  after="$(contextforge_description)"
  if ((ec != 0)); then
    if [[ "${after}" != "${before}" ]]; then
      ws agenthound --quiet revert "${engagement}" >/dev/null 2>&1 || true
    fi
    restore_contextforge_description "${before}"
    collector_failure "${name}" "collector is incompatible with the real ContextForge management API (exit ${ec})"
    return
  fi
  write_status_json "${ARTIFACTS_DIR}/${name}.json" \
    --arg before "${before}" --arg after "${after}" \
    --rawfile stderr "${ARTIFACTS_DIR}/${name}.stderr" \
    '{ok:true,engagement_id:"RTV-MCP-ROUNDTRIP",restored:($before == $after),standalone:($stderr | contains("STANDALONE") or contains("RUN_REPORT")),before:$before,after:$after}'
  if ! assert_json "${name}" "${ARTIFACTS_DIR}/${name}.json" "${EXPECTED_DIR}/${name}.jq"; then
    restore_contextforge_description "${before}"
    collector_failure "${name}" 'round-trip state oracle failed'
    return
  fi
  record_result "${name}" pass
}

cd "${REPO_ROOT}"
mkdir -p "${ARTIFACTS_DIR}" "${BIN_DIR}" "${SCRIPT_DIR}/fixtures"
: >"${RESULTS_FILE}"

printf '==> Downloading and independently validating immutable data fixtures\n'
# shellcheck source=lib/download-fixtures.sh
source "${SCRIPT_DIR}/lib/download-fixtures.sh"

jq -e '
  .mcpServers["everything-stdio"] == {
    command:"npx",
    args:["--yes","@modelcontextprotocol/server-everything@2026.7.4","stdio"]
  }
' "${SCRIPT_DIR}/host-home/Library/Application Support/Claude/claude_desktop_config.json" \
  >/dev/null || fail 'host-native Claude Desktop fixture is invalid'

printf '==> Building collector binaries\n'
GOOS=linux GOARCH="$(go env GOARCH)" CGO_ENABLED=0 \
  go build -trimpath -ldflags='-s -w' -o "${COLLECTOR_BIN}" ./collector/cmd/agenthound
go build -trimpath -o "${HOST_COLLECTOR_BIN}" ./collector/cmd/agenthound

printf '==> Starting real upstream topology\n'
STACK_STARTED=1
compose up -d --wait --build
wait_ready "${COMPOSE_FILE}" 1200

printf '==> Seeding through real upstream APIs\n'
bash "${SCRIPT_DIR}/lib/seed-services.sh" "${COMPOSE_FILE}"

printf '==> Verifying upstream truth independently of the collector\n'
bash "${SCRIPT_DIR}/lib/verify-upstreams.sh" \
  "${COMPOSE_FILE}" "${SCRIPT_DIR}/fixtures/upstream-truth.json"

# shellcheck source=lib/gen-witness.sh
source "${SCRIPT_DIR}/lib/gen-witness.sh"
export AGENTHOUND_CONTEXTFORGE_TOKEN
AGENTHOUND_CONTEXTFORGE_TOKEN="$(jq -er '.contextforge.token' "${SCRIPT_DIR}/fixtures/runtime.json")"
export CONTEXTFORGE_MCP_URL CONTEXTFORGE_TOOL_ID
CONTEXTFORGE_MCP_URL="$(jq -er '.contextforge.mcp_url' "${SCRIPT_DIR}/fixtures/runtime.json")"
CONTEXTFORGE_TOOL_ID="$(jq -er '.contextforge.tool_id' "${SCRIPT_DIR}/fixtures/runtime.json")"
OPENWEBUI_TOKEN="$(jq -er '.openwebui.token' "${SCRIPT_DIR}/fixtures/runtime.json")"

RUN_PHASE=collector_validation
run_host_json
run_json scan-config scan --config --project-dir /root/projects/example --output -
run_json scan-mcp scan --mcp --url http://mcp-streamable:3001/mcp --output -
run_json scan-mcp-configured scan --mcp --output -
run_json scan-a2a scan --a2a \
  --targets http://a2a-static/,http://a2a-static/legacy,http://a2a-dynamic:9000/ \
  --no-verify-jwks --a2a-trusted-keys /root/fixtures/a2a-trusted-jwks.json \
  --output -
run_json discover discover 10.20.30.0/24 \
  --mcp-ports 3001 --a2a-ports 80,9000 \
  --network-scan-concurrency 64 --output -
run_json scan-network scan 10.20.30.0/24 \
  --network-scan-concurrency 64 --output -

# Credential-reach uses the same real catalog API token as the configured MCP
# client and the independently verified authentication gate.
run_json campaign-cred-reach campaign "${CONTEXTFORGE_MCP_URL}" \
  --scenario cred-reach --witness /root/fixtures/witness.json \
  --commit --engagement-id RTV-CRED-REACH --output -

run_json loot-ollama loot ollama:11434 --type ollama --include-embeddings \
  --engagement-id RTV-LOOT-OLLAMA --output -
run_json loot-litellm loot litellm:4000 --type litellm \
  --master-key sk-local-agenthound-master-key-not-production \
  --engagement-id RTV-LOOT-LITELLM --output -
run_json loot-mlflow loot mlflow:5000 --type mlflow \
  --engagement-id RTV-LOOT-MLFLOW --output -
run_json loot-qdrant loot qdrant:6333 --type qdrant --include-points \
  --points-per-collection 2 --max-total-resources 4 \
  --engagement-id RTV-LOOT-QDRANT --output -
run_json loot-jupyter loot jupyter:8888 --type jupyter \
  --credential token=agenthound-jupyter-token \
  --engagement-id RTV-LOOT-JUPYTER --output -
run_json loot-openwebui loot openwebui:3000 --type openwebui \
  --api-key "${OPENWEBUI_TOKEN}" \
  --engagement-id RTV-LOOT-OPENWEBUI --output -
run_json extract-embedding extract "${TEST_MODEL_ID}" --type embedding-invert \
  --artifact /root/fixtures/models/stories260K.gguf \
  --confidence-threshold 1.5 --commit --engagement-id RTV-EXTRACT --output -

refresh_contextforge_token
run_contextforge_poison
run_contextforge_roundtrip
run_instruction_poison
run_config_implant
run_smoke rules-list rules list --format json
run_smoke version version

jq -s \
  --arg run_id "${RUN_ID}" \
  --arg upstream_truth "${SCRIPT_DIR}/fixtures/upstream-truth.json" \
  --argjson failures "${COLLECTOR_FAILURES}" \
  '{
    run_id:$run_id,
    harness_status:"valid",
    upstream_truth:$upstream_truth,
    collector_status:(if $failures == 0 then "compatible" else "incompatible" end),
    collector_failures:$failures,
    results:.
  }' "${RESULTS_FILE}" >"${ARTIFACTS_DIR}/summary.json"

if ((COLLECTOR_FAILURES > 0)); then
  printf '\nHarness is valid; collector incompatibilities: %d\n' "${COLLECTOR_FAILURES}" >&2
  jq -r '.results[] | select(.status == "collector_failure") | "  - \(.name): \(.reason)"' \
    "${ARTIFACTS_DIR}/summary.json" >&2
  exit 1
fi

printf '\nAll collector scenarios match the independently verified real upstreams.\n'
