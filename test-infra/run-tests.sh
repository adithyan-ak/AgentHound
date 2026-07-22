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
SERVER_BIN="${BIN_DIR}/agenthound-server"
HOST_COLLECTOR_BIN="${BIN_DIR}/agenthound-host"
RESULTS_FILE="${ARTIFACTS_DIR}/results.ndjson"
# Keep the release-gate inventory explicit and Bash 3.2 compatible. The final
# reconciliation requires every primary exactly once; PLANNED_SCENARIOS is
# derived from this manifest so an invocation cannot silently drift from a
# separately maintained integer.
EXPECTED_PRIMARY_SCENARIOS=(
  scan-config-host
  scan-config
  scan-config-secrets
  scan-mcp
  scan-mcp-url-secrets
  scan-mcp-configured
  scan-a2a
  discover
  scan-network
  campaign-cred-reach
  loot-ollama
  loot-litellm
  cross-service-credential-chain
  loot-mlflow
  loot-qdrant
  loot-jupyter
  loot-openwebui
  extract-embedding
  poison-mcp
  campaign-mcp-roundtrip
  poison-instruction
  implant-mcp-config
  rules-list
  version
)
ALLOWED_DIAGNOSTIC_SCENARIOS=(
  campaign-cred-reach-witness-binding
  raw-secret-artifacts
)
PLANNED_SCENARIOS=${#EXPECTED_PRIMARY_SCENARIOS[@]}
# ComputeNodeID("AIModel", immutable Hugging Face repository identity,
# "tinyllamas/stories260K.gguf"). The external locator remains provenance;
# the graph endpoint uses AgentHound's canonical node-ID representation.
EXTRACTION_SOURCE_NODE_ID='sha256:4482e450f9f605ebe76de9243b6ce516c859b29e3a173b42af8425914009bef2'
A2A_CARD_OPERATOR_TOKEN='agenthound-a2a-card-operator-secret-sentinel-20260719'

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
	# Keep the array non-empty for macOS Bash 3.2 under set -u. Expanding an
	# explicitly empty local array is treated as an unbound variable there.
	local -a compose_args=(exec -T)
	if [[ -n "${AGENTHOUND_CONTEXTFORGE_TOKEN:-}" ]]; then
		compose_args+=( -e "AGENTHOUND_CONTEXTFORGE_TOKEN=${AGENTHOUND_CONTEXTFORGE_TOKEN}" )
	fi
	if [[ -n "${AGENTHOUND_CAMPAIGN_CREDENTIAL:-}" ]]; then
		compose_args+=( -e "AGENTHOUND_CAMPAIGN_CREDENTIAL=${AGENTHOUND_CAMPAIGN_CREDENTIAL}" )
	fi
	compose "${compose_args[@]}" workstation "$@"
}

cleanup() {
  local ec=$?
  if ((ec != 0)) && [[ -d "${ARTIFACTS_DIR}" ]]; then
    assert_no_raw_secrets unexpected-exit "${ARTIFACTS_DIR}"/* || true
  fi
  if ((ec != 0)) && [[ -d "${ARTIFACTS_DIR}" ]] &&
    [[ ! -f "${ARTIFACTS_DIR}/summary.json" ]]; then
    if [[ -f "${RESULTS_FILE}" ]]; then
      jq -s --arg run_id "${RUN_ID}" --arg phase "${RUN_PHASE}" \
        --argjson planned_scenarios "${PLANNED_SCENARIOS}" '
        {
          run_id:$run_id,
          harness_status:"invalid",
          failure_phase:$phase,
          planned_scenarios:$planned_scenarios,
          result_records:length,
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
    compose --profile analysis --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
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
    'agenthound-analysis-local'
    'agenthound-argv-secret-sentinel-20260719'
    'agenthound-inline-secret-sentinel-20260719'
    'agenthound-userinfo-secret-sentinel-20260719'
    'agenthound-query-secret-sentinel-20260719'
    'agenthound-fragment-secret-sentinel-20260719'
    'agenthound-a2a-card-operator-secret-sentinel-20260719'
    'agenthound-a2a-api-key-not-production'
    '4a8f2c1d9e3b7a0f5c6d8e2b1a4f7c3d'
    "${AGENTHOUND_CONTEXTFORGE_TOKEN:-}"
    "${CROSS_SERVICE_MASTER_MATERIAL:-}"
    "${CROSS_SERVICE_PROOF_MATERIAL:-}"
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

guard_scenario_secrets() {
  local name="$1"
  local -a paths=("${ARTIFACTS_DIR}/${name}"*)
  assert_no_raw_secrets "${name}" "${paths[@]}"
}

run_json() {
  local name="$1"
  shift
  local artifact="${ARTIFACTS_DIR}/${name}.json"
  local stderr_path="${ARTIFACTS_DIR}/${name}.stderr"
  local expectation="${EXPECTED_DIR}/${name}.jq"
  local ec=0
  local -a collector_command=(agenthound --quiet "$@")
  if [[ "${AGENTHOUND_SCENARIO_LOGGED:-0}" == 1 ]]; then
    collector_command=(agenthound "$@")
  fi
  if [[ -n "${AGENTHOUND_SCENARIO_HOME:-}" ]]; then
    collector_command=(env "HOME=${AGENTHOUND_SCENARIO_HOME}" "${collector_command[@]}")
  fi

  printf '\n==> %s\n' "${name}"
  set +e
  ws "${collector_command[@]}" >"${artifact}" 2>"${stderr_path}"
  ec=$?
  set -e

  if ! guard_scenario_secrets "${name}"; then
    collector_failure "${name}" 'raw credential disclosure'
    return 0
  fi
  if ((ec != 0)); then
    collector_failure "${name}" "collector exited ${ec}; see ${stderr_path}"
    return 0
  fi
  if ! jq -e . "${artifact}" >/dev/null 2>&1; then
    collector_failure "${name}" 'collector output is not valid JSON'
    return 0
  fi
  if ! jq -e '
      .meta.version == 4 and
      .meta.identity.scheme == "agenthound_collection_v1" and
      .meta.identity.version == 1 and
      (.meta.identity.collection_point_id | test("^sha256:[0-9a-f]{64}$")) and
      (.meta.identity.network_context_id | test("^sha256:[0-9a-f]{64}$")) and
      (.meta.identity.quality == "strong" or .meta.identity.quality == "weak") and
      (.meta.identity.evidence | length > 0) and
      (.meta.identity.network_evidence | length > 0)
    ' "${artifact}" >/dev/null; then
    collector_failure "${name}" 'artifact does not contain valid automatic ingest-v4 identity'
    return 0
  fi
  if [[ -n "${AGENTHOUND_SCENARIO_POSTCHECK:-}" ]] &&
    ! "${AGENTHOUND_SCENARIO_POSTCHECK}" "${name}" "${artifact}"; then
    collector_failure "${name}" 'post-collection safety oracle failed'
    return 0
  fi
  if ! assert_json "${name}" "${artifact}" "${expectation}"; then
    collector_failure "${name}" 'output disagrees with independently verified upstream truth'
    return 0
  fi
  record_result "${name}" pass
}

assert_a2a_probe_safety() {
  local name="$1"
  local artifact="$2"
  local before_path="${ARTIFACTS_DIR}/${name}-probe-state-before.json"
  local after_path="${ARTIFACTS_DIR}/${name}-probe-state-after.json"
  local proof_path="${ARTIFACTS_DIR}/${name}-probe-proof.json"
  printf '%s\n' "${A2A_PROBE_STATE_BEFORE}" >"${before_path}"
  ws curl -fsS http://a2a-dynamic:9000/probe-state >"${after_path}"
  jq -n --slurpfile before "${before_path}" --slurpfile after "${after_path}" '
    ["v1", "v0_3", "protected", "ambiguous"] as $lanes |
    {
      ok: ($lanes | all(. as $lane |
        ($after[0][$lane].protocol_requests - $before[0][$lane].protocol_requests) == 1 and
        ($after[0][$lane].get_task_requests - $before[0][$lane].get_task_requests) == 1 and
        ($after[0][$lane].non_get_task_requests - $before[0][$lane].non_get_task_requests) == 0 and
        ($after[0][$lane].credential_header_requests - $before[0][$lane].credential_header_requests) == 0 and
        ($after[0][$lane].executor_calls - $before[0][$lane].executor_calls) == 0 and
        ($after[0][$lane].task_store_saves - $before[0][$lane].task_store_saves) == 0 and
        ($after[0][$lane].task_store_deletes - $before[0][$lane].task_store_deletes) == 0
      )),
      before: $before[0],
      after: $after[0],
      expected_collector_delta: {
        protocol_requests: 1,
        get_task_requests: 1,
        non_get_task_requests: 0,
        credential_header_requests: 0,
        executor_calls: 0,
        task_store_saves: 0,
        task_store_deletes: 0
      }
    }
  ' >"${proof_path}"
  if ! jq -e '.ok == true' "${proof_path}" >/dev/null; then
    printf '%s: A2A probe counters disagreed; inspect %s\n' "${name}" "${proof_path}" >&2
    return 1
  fi
  if ! assert_no_raw_secrets "${name}-probe-proof" \
    "${before_path}" "${after_path}" "${proof_path}" "${artifact}"; then
    return 1
  fi
}

run_host_json() {
  local name=scan-config-host
  local artifact="${ARTIFACTS_DIR}/${name}.json"
  local stderr_path="${ARTIFACTS_DIR}/${name}.stderr"
  local ec=0

  printf '\n==> %s\n' "${name}"
  set +e
  HOME="${SCRIPT_DIR}/host-home" \
    "${HOST_COLLECTOR_BIN}" --quiet \
    scan --config --output - >"${artifact}" 2>"${stderr_path}"
  ec=$?
  set -e
  if ! guard_scenario_secrets "${name}"; then
    collector_failure "${name}" 'raw credential disclosure'
    return
  fi
  if ((ec != 0)); then
    collector_failure "${name}" "collector exited ${ec}; see ${stderr_path}"
    return
  fi
  if ! jq -e '
      .meta.version == 4 and
      .meta.identity.scheme == "agenthound_collection_v1" and
      (.meta.identity.collection_point_id | test("^sha256:[0-9a-f]{64}$")) and
      (.meta.identity.network_context_id | test("^sha256:[0-9a-f]{64}$"))
    ' "${artifact}" >/dev/null; then
    collector_failure "${name}" 'host-native artifact does not contain automatic ingest-v4 identity'
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
  if ! guard_scenario_secrets "${name}"; then
    collector_failure "${name}" 'raw credential disclosure'
    return
  fi
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

  if ! guard_scenario_secrets "${name}"; then
    restore_contextforge_description "${before}"
    collector_failure "${name}" 'raw credential disclosure'
    return
  fi

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
  if ! guard_scenario_secrets "${name}"; then
    restore_contextforge_description "${before}"
    collector_failure "${name}" 'raw credential disclosure'
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
  if ! guard_scenario_secrets "${name}"; then
    ws /usr/local/bin/workstation-entrypoint restore-fixtures || true
    collector_failure "${name}" 'raw credential disclosure'
    return
  fi
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
  if ! guard_scenario_secrets "${name}"; then
    ws /usr/local/bin/workstation-entrypoint restore-fixtures || true
    collector_failure "${name}" 'raw credential disclosure'
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
  if ! guard_scenario_secrets "${name}"; then
    ws /usr/local/bin/workstation-entrypoint restore-fixtures || true
    collector_failure "${name}" 'raw credential disclosure'
    return
  fi
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
  if ! guard_scenario_secrets "${name}"; then
    ws /usr/local/bin/workstation-entrypoint restore-fixtures || true
    collector_failure "${name}" 'raw credential disclosure'
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
  if ! guard_scenario_secrets "${name}"; then
    restore_contextforge_description "${before}"
    collector_failure "${name}" 'raw credential disclosure'
    return
  fi
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

run_cred_reach_campaign() {
  local name=campaign-cred-reach
  local witness="${SCRIPT_DIR}/fixtures/witness.json"
  local ec=0

  printf '\n==> Starting production projection dependencies\n'
  compose --profile analysis up -d --wait analysis-postgres analysis-neo4j

  set +e
  bash "${SCRIPT_DIR}/lib/export-witness.sh" \
    "${COMPOSE_FILE}" \
    "${ARTIFACTS_DIR}/scan-config.json" \
    "${ARTIFACTS_DIR}/scan-mcp-configured.json" \
    "${SCRIPT_DIR}/fixtures/runtime.json" \
    "${ARTIFACTS_DIR}" \
    "${witness}" \
    >"${ARTIFACTS_DIR}/${name}-projection.out" \
    2>"${ARTIFACTS_DIR}/${name}-projection.stderr"
  ec=$?
  set -e
  if ! guard_scenario_secrets "${name}"; then
    collector_failure "${name}" 'raw credential disclosure in production projection artifacts'
    return
  fi
  if ((ec != 0)); then
    collector_failure "${name}" 'actual collector projections did not produce a production-exportable CAN_REACH witness'
    return
  fi

  run_json "${name}" campaign "${CONTEXTFORGE_MCP_URL}" \
    --scenario cred-reach --witness /root/fixtures/witness.json \
    --commit --engagement-id RTV-CRED-REACH --output -

  if [[ -s "${ARTIFACTS_DIR}/${name}.json" ]] && ! jq -e \
    --slurpfile witness "${witness}" '
      .graph.edges[0].properties as $p |
      $witness[0] as $w |
      $p.agent_id == $w.agent_id and
      $p.credential_id == $w.credential_id and
      $p.credential_value_hash == $w.credential_value_hash and
      $p.credential_merge_key == $w.credential_merge_key and
      $p.server_id == $w.server_id and
      $p.resource_id == $w.resource_id and
      $p.evidence_node_ids == $w.evidence_node_ids and
      $p.evidence_node_kinds == $w.evidence_node_kinds
    ' "${ARTIFACTS_DIR}/${name}.json" >/dev/null; then
    collector_failure campaign-cred-reach-witness-binding \
      'campaign evidence does not preserve the production-exported witness'
  fi
}

run_cross_service_credential_chain() {
  local name=cross-service-credential-chain
  local ec=0

  printf '\n==> %s\n' "${name}"
  compose --profile analysis up -d --wait analysis-postgres analysis-neo4j
  set +e
  bash "${SCRIPT_DIR}/lib/assert-cross-service-chain.sh" \
    "${COMPOSE_FILE}" \
    "${ARTIFACTS_DIR}/scan-config.json" \
    "${ARTIFACTS_DIR}/scan-mcp-configured.json" \
    "${ARTIFACTS_DIR}/loot-litellm.json" \
    "${ARTIFACTS_DIR}" \
    "${ARTIFACTS_DIR}/${name}.json" \
    >"${ARTIFACTS_DIR}/${name}.out" \
    2>"${ARTIFACTS_DIR}/${name}.stderr"
  ec=$?
  set -e

  if ! guard_scenario_secrets "${name}"; then
    collector_failure "${name}" 'raw credential disclosure in cross-service projection artifacts'
    return
  fi
  if ((ec != 0)); then
    collector_failure "${name}" 'real collector outputs did not produce canonical published cross-service findings for every LiteLLM target'
    return
  fi
  if ! assert_json "${name}" "${ARTIFACTS_DIR}/${name}.json" \
    "${EXPECTED_DIR}/${name}.jq"; then
    collector_failure "${name}" 'cross-service projection status oracle failed'
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

printf '==> Deriving exact extraction truth with the official GGUF reader\n'
STACK_STARTED=1
compose --profile tools build gguf-verifier >/dev/null
compose --profile tools run --rm --no-deps gguf-verifier \
  /fixtures/models/stories260K.gguf 1.5 \
  >"${ARTIFACTS_DIR}/extraction-truth.json"
jq -e --slurpfile expected "${EXPECTED_DIR}/extraction-truth.json" \
  '. == $expected[0]' "${ARTIFACTS_DIR}/extraction-truth.json" >/dev/null ||
  fail 'official GGUF reader output drifted from the reviewed exact extraction truth'
pass upstream:gguf-extraction-truth

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
GOOS=linux GOARCH="$(go env GOARCH)" CGO_ENABLED=0 \
  go build -trimpath -ldflags='-s -w' -o "${SERVER_BIN}" ./server/cmd/agenthound-server
go build -trimpath -o "${HOST_COLLECTOR_BIN}" ./collector/cmd/agenthound

printf '==> Starting real upstream topology\n'
compose up -d --wait --build
wait_ready "${COMPOSE_FILE}" 1200

printf '==> Seeding through real upstream APIs\n'
bash "${SCRIPT_DIR}/lib/seed-services.sh" "${COMPOSE_FILE}"

printf '==> Verifying upstream truth independently of the collector\n'
bash "${SCRIPT_DIR}/lib/verify-upstreams.sh" \
  "${COMPOSE_FILE}" "${SCRIPT_DIR}/fixtures/upstream-truth.json"

# Read the shared values from the live disposable workstation. They are used
# only for authenticated controls and the real looter call, and every retained
# artifact is guarded against both raw strings below. Host-side names are
# intentionally different from the container variables, preventing accidental
# Compose interpolation or an empty host export from shadowing container state.
CROSS_SERVICE_MASTER_MATERIAL="$(ws sh -c 'printf %s "$AGENTHOUND_LITELLM_MASTER_KEY"')"
CROSS_SERVICE_PROOF_MATERIAL="$(ws sh -c 'printf %s "$AGENTHOUND_CROSS_SERVICE_PROOF"')"
[[ -n "${CROSS_SERVICE_MASTER_MATERIAL}" && -n "${CROSS_SERVICE_PROOF_MATERIAL}" ]] ||
  fail 'cross-service runtime credential fixtures are empty'

# Prove that the privacy lane's reverse proxy actually enforces both URL
# credential components before using collector completeness as wire evidence.
# An exact request is deliberately not a valid MCP JSON-RPC message, so the
# pinned Everything Server returns 406 only after the gate forwards it.
gate_missing_status="$(ws curl -s -o /dev/null -w '%{http_code}' -X POST \
  'http://mcp-credential-gate:3002/mcp?api_key=agenthound-query-secret-sentinel-20260719')"
gate_wrong_query_status="$(ws curl -s -o /dev/null -w '%{http_code}' -X POST \
  -u 'agenthound-user:agenthound-userinfo-secret-sentinel-20260719' \
  'http://mcp-credential-gate:3002/mcp?api_key=wrong')"
gate_exact_status="$(ws curl -s -o /dev/null -w '%{http_code}' -X POST \
  -u 'agenthound-user:agenthound-userinfo-secret-sentinel-20260719' \
  'http://mcp-credential-gate:3002/mcp?api_key=agenthound-query-secret-sentinel-20260719')"
[[ "${gate_missing_status}" == 401 && "${gate_wrong_query_status}" == 401 && \
  "${gate_exact_status}" == 406 ]] ||
  fail "MCP credential gate enforcement drifted (missing=${gate_missing_status}, wrong_query=${gate_wrong_query_status}, exact=${gate_exact_status})"
pass upstream:mcp-credential-gate

# Prove the cross-service gate rejects each independently incorrect control.
# The 406 exact response originates at the pinned official Everything Server,
# so it also proves the exact bearer/proof request passed through the proxy.
cross_missing_auth_status="$(ws curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "X-AgentHound-Secret: ${CROSS_SERVICE_PROOF_MATERIAL}" \
  'http://mcp-cross-service-gate:3003/mcp')"
cross_wrong_auth_status="$(ws curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H 'Authorization: Bearer wrong' \
  -H "X-AgentHound-Secret: ${CROSS_SERVICE_PROOF_MATERIAL}" \
  'http://mcp-cross-service-gate:3003/mcp')"
cross_missing_proof_status="$(ws curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${CROSS_SERVICE_MASTER_MATERIAL}" \
  'http://mcp-cross-service-gate:3003/mcp')"
cross_wrong_proof_status="$(ws curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${CROSS_SERVICE_MASTER_MATERIAL}" \
  -H 'X-AgentHound-Secret: wrong' \
  'http://mcp-cross-service-gate:3003/mcp')"
cross_exact_status="$(ws curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${CROSS_SERVICE_MASTER_MATERIAL}" \
  -H "X-AgentHound-Secret: ${CROSS_SERVICE_PROOF_MATERIAL}" \
  'http://mcp-cross-service-gate:3003/mcp')"
[[ "${cross_missing_auth_status}" == 401 && \
  "${cross_wrong_auth_status}" == 401 && \
  "${cross_missing_proof_status}" == 401 && \
  "${cross_wrong_proof_status}" == 401 && \
  "${cross_exact_status}" == 406 ]] ||
  fail "cross-service MCP gate enforcement drifted (missing_auth=${cross_missing_auth_status}, wrong_auth=${cross_wrong_auth_status}, missing_proof=${cross_missing_proof_status}, wrong_proof=${cross_wrong_proof_status}, exact=${cross_exact_status})"
pass upstream:mcp-cross-service-gate

export AGENTHOUND_CONTEXTFORGE_TOKEN
AGENTHOUND_CONTEXTFORGE_TOKEN="$(jq -er '.contextforge.token' "${SCRIPT_DIR}/fixtures/runtime.json")"
export AGENTHOUND_CAMPAIGN_CREDENTIAL
AGENTHOUND_CAMPAIGN_CREDENTIAL="${AGENTHOUND_CONTEXTFORGE_TOKEN}"
export CONTEXTFORGE_MCP_URL CONTEXTFORGE_TOOL_ID
CONTEXTFORGE_MCP_URL="$(jq -er '.contextforge.mcp_url' "${SCRIPT_DIR}/fixtures/runtime.json")"
CONTEXTFORGE_TOOL_ID="$(jq -er '.contextforge.tool_id' "${SCRIPT_DIR}/fixtures/runtime.json")"
OPENWEBUI_TOKEN="$(jq -er '.openwebui.token' "${SCRIPT_DIR}/fixtures/runtime.json")"

RUN_PHASE=collector_validation
run_host_json
run_json scan-config scan --config --project-dir /root/projects/example --output -
AGENTHOUND_SCENARIO_HOME=/root/secret-fixture-home \
  run_json scan-config-secrets scan --config \
    --project-dir /root/secret-fixture-home/project --output -
run_json scan-mcp scan --mcp --url http://mcp-streamable:3001/mcp --output -
AGENTHOUND_SCENARIO_LOGGED=1 run_json scan-mcp-url-secrets scan --mcp \
  --url 'http://agenthound-user:agenthound-userinfo-secret-sentinel-20260719@mcp-credential-gate:3002/mcp?api_key=agenthound-query-secret-sentinel-20260719#agenthound-fragment-secret-sentinel-20260719' \
  --output -
run_json scan-mcp-configured scan --mcp --output -
A2A_PROBE_STATE_BEFORE="$(ws curl -fsS http://a2a-dynamic:9000/probe-state)"
AGENTHOUND_SCENARIO_POSTCHECK=assert_a2a_probe_safety run_json scan-a2a scan --a2a \
  --targets http://a2a-static/,http://a2a-static/legacy,http://a2a-dynamic:9000/,http://a2a-dynamic:9000/legacy,http://a2a-dynamic:9000/protected,http://a2a-dynamic:9000/ambiguous \
  --auth-token "${A2A_CARD_OPERATOR_TOKEN}" \
  --no-verify-jwks --a2a-trusted-keys /root/fixtures/a2a-trusted-jwks.json \
  --output -
run_json discover discover 10.20.30.0/24 \
  --mcp-ports 3001 --a2a-ports 80,9000 \
  --network-scan-concurrency 64 --output -
run_json scan-network scan 10.20.30.0/24 \
  --network-scan-concurrency 64 --output -

# The witness is exported only after these actual collector outputs pass
# through the production ingest, processor, publication, and witness path.
run_cred_reach_campaign

run_json loot-ollama loot ollama:11434 --type ollama --include-embeddings \
  --engagement-id RTV-LOOT-OLLAMA --output -
run_json loot-litellm loot litellm:4000 --type litellm \
  --master-key "${CROSS_SERVICE_MASTER_MATERIAL}" \
  --engagement-id RTV-LOOT-LITELLM --output -
run_cross_service_credential_chain
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
run_json extract-embedding extract \
  "${EXTRACTION_SOURCE_NODE_ID}" \
  --type embedding-invert \
  --artifact /root/fixtures/models/stories260K.gguf \
  --confidence-threshold 1.5 --commit --engagement-id RTV-EXTRACT --output -

refresh_contextforge_token
run_contextforge_poison
run_contextforge_roundtrip
run_instruction_poison
run_config_implant
run_smoke rules-list rules list --format json
run_smoke version version

# Defense in depth: include every retained stdout/stderr/revert/cleanup file,
# including artifacts emitted on an unexpected shell failure path.
if ! assert_no_raw_secrets all-artifacts "${ARTIFACTS_DIR}"/*; then
  collector_failure raw-secret-artifacts 'raw credential found in retained artifacts'
fi

expected_primary_json="$(printf '%s\n' "${EXPECTED_PRIMARY_SCENARIOS[@]}" |
  jq -Rsc 'split("\n") | map(select(length > 0))')"
allowed_diagnostics_json="$(printf '%s\n' "${ALLOWED_DIAGNOSTIC_SCENARIOS[@]}" |
  jq -Rsc 'split("\n") | map(select(length > 0))')"

jq -s \
  --arg run_id "${RUN_ID}" \
  --arg upstream_truth "${SCRIPT_DIR}/fixtures/upstream-truth.json" \
  --argjson failures "${COLLECTOR_FAILURES}" \
  --argjson planned_scenarios "${PLANNED_SCENARIOS}" \
  --argjson expected_primary "${expected_primary_json}" \
  --argjson allowed_diagnostics "${allowed_diagnostics_json}" '
  . as $results |
  ([$results[] | select(type == "object")]) as $object_records |
  ($expected_primary + $allowed_diagnostics) as $allowed_names |
  ([$object_records[] |
    . as $record |
    select(($expected_primary | index($record.name)) != null)]) as $primary_records |
  ([$object_records[] |
    . as $record |
    select(($allowed_diagnostics | index($record.name)) != null)]) as $diagnostic_records |
  ([$expected_primary[] |
    . as $name |
    select(($object_records | map(select(.name == $name)) | length) == 0) |
    $name]) as $missing_primary |
  ([$object_records | group_by(.name)[] |
    select(length > 1) | .[0].name]) as $duplicate_names |
  ([$object_records[].name |
    . as $name |
    select(($allowed_names | index($name)) == null)] | unique) as $unexpected_names |
  ([$results | to_entries[] |
    select(
      if (.value | type) != "object" then true
      else
        (.value.name | type) != "string" or .value.name == "" or
        (.value.status | type) != "string" or
        (.value.reason | type) != "string"
      end
    ) | .key]) as $malformed_record_indexes |
  ([$object_records[] |
    select(.status != "pass" and .status != "collector_failure") |
    .name]) as $invalid_status_names |
  ([$diagnostic_records[] |
    select(
      .status != "collector_failure"
    ) | .name]) as $non_failure_diagnostics |
  ([$object_records[] | select(.status == "collector_failure")] | length) as $failure_rows |
  ($primary_records | all(.status == "pass")) as $all_primary_pass |
  (
    ($expected_primary | length) == $planned_scenarios and
    ($primary_records | length) == $planned_scenarios and
    ($missing_primary | length) == 0 and
    ($duplicate_names | length) == 0 and
    ($unexpected_names | length) == 0 and
    ($malformed_record_indexes | length) == 0 and
    ($invalid_status_names | length) == 0 and
    ($non_failure_diagnostics | length) == 0 and
    $failure_rows == $failures
  ) as $coverage_valid |
  (
    $coverage_valid and
    $failures == 0 and
    $failure_rows == 0 and
    ($results | length) == $planned_scenarios and
    ($primary_records | length) == $planned_scenarios and
    $all_primary_pass and
    ($diagnostic_records | length) == 0
  ) as $green_eligible |
  {
    run_id:$run_id,
    harness_status:(if $coverage_valid then "valid" else "invalid" end),
    upstream_truth:$upstream_truth,
    planned_scenarios:$planned_scenarios,
    result_records:($results | length),
    coverage:{
      valid:$coverage_valid,
      expected_primary:$expected_primary,
      allowed_diagnostics:$allowed_diagnostics,
      primary_records:($primary_records | length),
      diagnostic_records:($diagnostic_records | length),
      all_primary_pass:$all_primary_pass,
      green_eligible:$green_eligible,
      missing_primary:$missing_primary,
      duplicate_names:$duplicate_names,
      unexpected_names:$unexpected_names,
      malformed_record_indexes:$malformed_record_indexes,
      invalid_status_names:$invalid_status_names,
      non_failure_diagnostics:$non_failure_diagnostics,
      failure_counter:$failures,
      failure_rows:$failure_rows
    },
    collector_status:(
      if $coverage_valid | not then "not_evaluated"
      elif $green_eligible then "compatible"
      else "incompatible" end
    ),
    collector_failures:$failures,
    results:$results
  }' "${RESULTS_FILE}" >"${ARTIFACTS_DIR}/summary.json"

if ! jq -e '.coverage.valid == true' "${ARTIFACTS_DIR}/summary.json" >/dev/null; then
  printf '\nHarness result reconciliation is invalid:\n' >&2
  jq -r '
    def printable_names:
      map(if type == "string" then . else tojson end) | join(", ");
    "  missing primary: \(.coverage.missing_primary | printable_names)",
    "  duplicate names: \(.coverage.duplicate_names | printable_names)",
    "  unexpected names: \(.coverage.unexpected_names | printable_names)",
    "  malformed record indexes: \(.coverage.malformed_record_indexes | map(tostring) | join(", "))",
    "  invalid status names: \(.coverage.invalid_status_names | printable_names)",
    "  non-failure diagnostics: \(.coverage.non_failure_diagnostics | printable_names)",
    "  failure counter/rows: \(.coverage.failure_counter)/\(.coverage.failure_rows)"
  ' "${ARTIFACTS_DIR}/summary.json" >&2
  exit 2
fi

if ((COLLECTOR_FAILURES > 0)); then
  printf '\nHarness is valid; collector incompatibilities: %d\n' "${COLLECTOR_FAILURES}" >&2
  jq -r '.results[] | select(.status == "collector_failure") | "  - \(.name): \(.reason)"' \
    "${ARTIFACTS_DIR}/summary.json" >&2
  exit 1
fi

printf '\nAll collector scenarios match the independently verified real upstreams.\n'
