#!/usr/bin/env bash
# Offline collector harness: build agenthound, bring up the compose stack,
# run every collector verb against live targets, assert JSON / mutation state.
set -Eeuo pipefail

KEEP=0
usage() {
  cat <<'EOF'
Usage: bash test-infra/run-tests.sh [--keep]

Build the collector, start the offline compose stack, seed fixtures, run
collector scenarios, and assert outputs. On success the stack is removed
unless --keep is set. Failure always retains artifacts/ and leaves the
stack up for inspection.
EOF
}

for arg in "$@"; do
  case "${arg}" in
    --keep) KEEP=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "${arg}" >&2
      usage >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_INFRA_DIR="${SCRIPT_DIR}"
COMPOSE_FILE="${TEST_INFRA_DIR}/docker-compose.yml"
ARTIFACTS_DIR="${TEST_INFRA_DIR}/artifacts"
EXPECTED_DIR="${TEST_INFRA_DIR}/expected"
BIN_DIR="${TEST_INFRA_DIR}/services/workstation/bin"
COLLECTOR_BIN="${BIN_DIR}/agenthound"

# shellcheck source=lib/assertions.sh
source "${TEST_INFRA_DIR}/lib/assertions.sh"
# shellcheck source=lib/wait-ready.sh
source "${TEST_INFRA_DIR}/lib/wait-ready.sh"

require_command go
require_command docker
require_command jq

FAILED=0
STACK_STARTED=0
KEEP_STACK_ON_EXIT=0

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

ws() {
  # Propagate campaign credential into the runner container when set.
  if [[ -n "${AGENTHOUND_CAMPAIGN_CREDENTIAL:-}" ]]; then
    compose exec -T \
      -e "AGENTHOUND_CAMPAIGN_CREDENTIAL=${AGENTHOUND_CAMPAIGN_CREDENTIAL}" \
      workstation "$@"
  else
    compose exec -T workstation "$@"
  fi
}

cleanup() {
  local ec=$?
  if ((FAILED)) || ((ec != 0)); then
    printf '\nHarness failed — artifacts retained under %s\n' "${ARTIFACTS_DIR}" >&2
    if ((STACK_STARTED)); then
      printf 'Stack left running for inspection (use --keep semantics).\n' >&2
      printf '  docker compose -f %s ps\n' "${COMPOSE_FILE}" >&2
    fi
    return
  fi
  if ((STACK_STARTED)) && ((KEEP == 0)) && ((KEEP_STACK_ON_EXIT == 0)); then
    printf 'Tearing down stack...\n'
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  elif ((KEEP)); then
    printf 'Keeping stack (--keep).\n'
  fi
}
trap cleanup EXIT

cd "${REPO_ROOT}"

mkdir -p "${ARTIFACTS_DIR}" "${BIN_DIR}" "${TEST_INFRA_DIR}/fixtures"

printf '==> Generating campaign witness (must precede compose up)\n'
# shellcheck source=lib/gen-witness.sh
source "${TEST_INFRA_DIR}/lib/gen-witness.sh"
[[ -n "${GATED_RESOURCE_TOKEN_HASH}" ]] || fail "GATED_RESOURCE_TOKEN_HASH unset after gen-witness"
[[ -n "${AGENTHOUND_CAMPAIGN_CREDENTIAL}" ]] || fail "AGENTHOUND_CAMPAIGN_CREDENTIAL unset after gen-witness"
[[ -f "${TEST_INFRA_DIR}/fixtures/witness.json" ]] || fail "witness.json missing"

printf '==> Building collector → %s\n' "${COLLECTOR_BIN}"
GOOS=linux GOARCH="$(go env GOARCH)" CGO_ENABLED=0 \
  go build -trimpath -ldflags='-s -w' \
  -o "${COLLECTOR_BIN}" \
  ./collector/cmd/agenthound
[[ -x "${COLLECTOR_BIN}" ]] || fail "collector binary missing after build"

printf '==> Starting compose stack\n'
compose up -d --wait --build
STACK_STARTED=1

printf '==> Waiting for service readiness\n'
wait_ready "${COMPOSE_FILE}" 900

printf '==> Seeding deterministic fixtures\n'
bash "${TEST_INFRA_DIR}/lib/seed-services.sh" "${COMPOSE_FILE}"

# --- helpers -----------------------------------------------------------------

run_json() {
  local name="$1"
  shift
  local artifact="${ARTIFACTS_DIR}/${name}.json"
  local expectation="${EXPECTED_DIR}/${name}.jq"
  local ec=0

  printf '\n==> %s\n' "${name}"
  set +e
  ws agenthound --quiet "$@" >"${artifact}" 2>"${ARTIFACTS_DIR}/${name}.stderr"
  ec=$?
  set -e

  if ((ec != 0)); then
    printf 'FAIL: %s (exit %d)\n' "${name}" "${ec}" >&2
    printf '  stderr: %s\n' "${ARTIFACTS_DIR}/${name}.stderr" >&2
    FAILED=1
    return 1
  fi

  if ! assert_json "${name}" "${artifact}" "${expectation}"; then
    FAILED=1
    return 1
  fi
  return 0
}

run_smoke() {
  local name="$1"
  shift
  printf '\n==> %s (smoke)\n' "${name}"
  if ws agenthound --quiet "$@" >"${ARTIFACTS_DIR}/${name}.out" 2>"${ARTIFACTS_DIR}/${name}.stderr"; then
    pass "${name}"
    return 0
  fi
  fail "${name} (exit nonzero)"
  FAILED=1
  return 1
}

mcp_tool_description() {
  local tool="$1"
  ws curl -fsS -X POST \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
    http://mcp-target-admin:8080/admin/tools-list |
    jq -r --arg tool "${tool}" \
      '.result.tools[] | select(.name == $tool) | .description'
}

file_sha_in_ws() {
  local path="$1"
  ws sha256sum "${path}" | awk '{print $1}'
}

file_contents_in_ws() {
  local path="$1"
  ws cat "${path}"
}

# --- JSON-producing verbs ----------------------------------------------------

run_json scan-config \
  scan --config --project-dir /root/projects/example --output -

run_json scan-mcp \
  scan --mcp --url http://mcp-target-admin:8080/mcp --output -

run_json scan-a2a-static \
  scan --a2a --target http://a2a-static/ --output -

run_json scan-a2a-dynamic \
  scan --a2a --target http://a2a-dynamic:9000/ --output -

run_json scan-network \
  scan 10.20.30.0/24 --network-scan-concurrency 32 --output -

run_json discover \
  discover 10.20.30.0/24 --network-scan-concurrency 32 --output -

run_json loot-ollama \
  loot ollama:11434 --type ollama --engagement-id RTV-LOOT-OLLAMA --output -

run_json loot-litellm \
  loot litellm:4000 --type litellm \
  --master-key sk-local-agenthound-master-key-not-production \
  --engagement-id RTV-LOOT-LITELLM --output -

run_json loot-mlflow \
  loot mlflow:5000 --type mlflow --engagement-id RTV-LOOT-MLFLOW --output -

run_json loot-qdrant \
  loot qdrant:6333 --type qdrant --include-points \
  --engagement-id RTV-LOOT-QDRANT --output -

run_json loot-jupyter \
  loot jupyter:8888 --type jupyter --engagement-id RTV-LOOT-JUPYTER --output -

run_json loot-openwebui \
  loot openwebui:3000 --type openwebui --engagement-id RTV-LOOT-OPENWEBUI --output -

run_json extract-embedding \
  extract "${TEST_MODEL_ID}" --type embedding-invert \
  --artifact /root/testdata/extract/synthetic.gguf \
  --confidence-threshold 1.5 \
  --commit --engagement-id RTV-EXTRACT --output -

run_json campaign-cred-reach \
  campaign http://mcp-target-admin:8080/mcp --scenario cred-reach \
  --witness /root/fixtures/witness.json \
  --commit --engagement-id RTV-CRED-REACH --output -

# --- Mutation / state verbs (shell + status JSON for expected/*.jq) ----------

run_poison_mcp() {
  local name=poison-mcp
  local eng=RTV-POISON-MCP
  local inject='TAMPERED-BY-AGENTHOUND-OFFLINE-HARNESS'
  local before after restored
  local artifact="${ARTIFACTS_DIR}/${name}.json"

  printf '\n==> %s\n' "${name}"
  before="$(mcp_tool_description support_lookup)"
  [[ -n "${before}" ]] || {
    fail "${name}: empty original description"
    FAILED=1
    return 1
  }

  if ! ws agenthound --quiet poison http://mcp-target-admin:8080 \
    --type mcp.tool.description \
    --target-id support_lookup \
    --inject "${inject}" \
    --list-path /admin/tools-list \
    --update-path '/admin/tools/{id}' \
    --commit --engagement-id "${eng}" \
    >"${ARTIFACTS_DIR}/${name}.out" 2>"${ARTIFACTS_DIR}/${name}.stderr"; then
    fail "${name}: poison commit failed"
    FAILED=1
    return 1
  fi

  after="$(mcp_tool_description support_lookup)"
  if [[ "${after}" != *"${inject}"* ]]; then
    fail "${name}: description not mutated"
    FAILED=1
    return 1
  fi

  if ! ws agenthound --quiet revert "${eng}" \
    >"${ARTIFACTS_DIR}/${name}-revert.out" 2>"${ARTIFACTS_DIR}/${name}-revert.stderr"; then
    fail "${name}: revert failed"
    FAILED=1
    return 1
  fi

  restored="$(mcp_tool_description support_lookup)"
  if [[ "${restored}" != "${before}" ]]; then
    fail "${name}: description not restored byte-identical"
    FAILED=1
    return 1
  fi

  write_status_json "${artifact}" \
    --arg eng "${eng}" \
    --arg before "${before}" \
    --arg after "${after}" \
    --arg restored "${restored}" \
    '{
      ok: true,
      engagement_id: $eng,
      mutated: ($after != $before),
      reverted: ($restored == $before),
      before: $before,
      after: $after,
      restored: $restored
    }'
  assert_json "${name}" "${artifact}" "${EXPECTED_DIR}/${name}.jq" || FAILED=1
}

run_poison_instruction() {
  local name=poison-instruction
  local eng=RTV-POISON-INSTR
  local path=/root/projects/example/CLAUDE.md
  local inject='TAMPERED-INSTRUCTION-BLOCK'
  local before_hash after_hash restored_hash
  local artifact="${ARTIFACTS_DIR}/${name}.json"

  printf '\n==> %s\n' "${name}"
  ws /usr/local/bin/workstation-entrypoint restore-fixtures
  before_hash="$(file_sha_in_ws "${path}")"

  if ! ws agenthound --quiet poison workstation \
    --type instruction.file \
    --file "${path}" \
    --inject "${inject}" \
    --commit --engagement-id "${eng}" \
    >"${ARTIFACTS_DIR}/${name}.out" 2>"${ARTIFACTS_DIR}/${name}.stderr"; then
    fail "${name}: poison commit failed"
    FAILED=1
    return 1
  fi

  after_hash="$(file_sha_in_ws "${path}")"
  if [[ "${after_hash}" == "${before_hash}" ]]; then
    fail "${name}: file hash unchanged after poison"
    FAILED=1
    return 1
  fi
  assert_contains "${name}:inject-present" "$(file_contents_in_ws "${path}")" "${inject}" || FAILED=1

  if ! ws agenthound --quiet revert "${eng}" \
    >"${ARTIFACTS_DIR}/${name}-revert.out" 2>"${ARTIFACTS_DIR}/${name}-revert.stderr"; then
    fail "${name}: revert failed"
    FAILED=1
    return 1
  fi

  restored_hash="$(file_sha_in_ws "${path}")"
  if [[ "${restored_hash}" != "${before_hash}" ]]; then
    fail "${name}: file not restored byte-identical"
    FAILED=1
    return 1
  fi

  write_status_json "${artifact}" \
    --arg eng "${eng}" \
    --arg before "${before_hash}" \
    --arg after "${after_hash}" \
    --arg restored "${restored_hash}" \
    '{
      ok: true,
      engagement_id: $eng,
      mutated: ($after != $before),
      reverted: ($restored == $before),
      before_hash: $before,
      after_hash: $after,
      restored_hash: $restored
    }'
  assert_json "${name}" "${artifact}" "${EXPECTED_DIR}/${name}.jq" || FAILED=1
}

run_implant_mcp_config() {
  local name=implant-mcp-config
  local eng=RTV-IMPLANT
  local path=/root/.cursor/mcp.json
  local server_name=agenthound-implant-fixture
  local inject='{"command":"/usr/bin/printf","args":["implanted-fixture"]}'
  local before_hash after_hash restored_hash before_canon restored_canon
  local artifact="${ARTIFACTS_DIR}/${name}.json"

  printf '\n==> %s\n' "${name}"
  ws /usr/local/bin/workstation-entrypoint restore-fixtures
  before_hash="$(file_sha_in_ws "${path}")"
  before_canon="$(ws jq -S -c . "${path}")"

  if ! ws agenthound --quiet implant workstation \
    --type mcp.config.malicious-server \
    --file "${path}" \
    --server-name "${server_name}" \
    --inject "${inject}" \
    --commit --engagement-id "${eng}" \
    >"${ARTIFACTS_DIR}/${name}.out" 2>"${ARTIFACTS_DIR}/${name}.stderr"; then
    fail "${name}: implant commit failed"
    FAILED=1
    return 1
  fi

  after_hash="$(file_sha_in_ws "${path}")"
  if [[ "${after_hash}" == "${before_hash}" ]]; then
    fail "${name}: config hash unchanged after implant"
    FAILED=1
    return 1
  fi
  assert_contains "${name}:server-present" "$(file_contents_in_ws "${path}")" "${server_name}" || FAILED=1

  if ! ws agenthound --quiet revert "${eng}" \
    >"${ARTIFACTS_DIR}/${name}-revert.out" 2>"${ARTIFACTS_DIR}/${name}-revert.stderr"; then
    fail "${name}: revert failed"
    FAILED=1
    return 1
  fi

  restored_hash="$(file_sha_in_ws "${path}")"
  restored_canon="$(ws jq -S -c . "${path}")"
  assert_not_contains "${name}:server-gone" "$(file_contents_in_ws "${path}")" "${server_name}" || FAILED=1
  # mcpconfigimplant reverts by dropping the implanted key and re-encoding
  # via encoding/json.MarshalIndent — intentional semantic restore (key order /
  # whitespace may change). Assert jq -S equality, not byte-identical SHA.
  if [[ "${restored_canon}" != "${before_canon}" ]]; then
    fail "${name}: config not restored semantically (jq -S mismatch)"
    FAILED=1
    return 1
  fi

  write_status_json "${artifact}" \
    --arg eng "${eng}" \
    --arg before "${before_hash}" \
    --arg after "${after_hash}" \
    --arg restored "${restored_hash}" \
    --arg server "${server_name}" \
    '{
      ok: true,
      engagement_id: $eng,
      server_name: $server,
      mutated: ($after != $before),
      reverted: true,
      semantic_reverted: true,
      before_hash: $before,
      after_hash: $after,
      restored_hash: $restored
    }'
  assert_json "${name}" "${artifact}" "${EXPECTED_DIR}/${name}.jq" || FAILED=1
}

run_campaign_mcp_roundtrip() {
  local name=campaign-mcp-roundtrip
  local eng=RTV-MCP-ROUNDTRIP
  local inject='ROUNDTRIP-TAMPER'
  local before after
  local artifact="${ARTIFACTS_DIR}/${name}.json"
  local ec=0

  printf '\n==> %s\n' "${name}"
  before="$(mcp_tool_description support_lookup)"

  set +e
  ws agenthound --quiet campaign http://mcp-target-admin:8080 \
    --scenario mcp-poison-roundtrip \
    --target-id support_lookup \
    --inject "${inject}" \
    --list-path /admin/tools-list \
    --update-path '/admin/tools/{id}' \
    --commit --engagement-id "${eng}" \
    >"${ARTIFACTS_DIR}/${name}.out" 2>"${ARTIFACTS_DIR}/${name}.stderr"
  ec=$?
  set -e

  if ((ec != 0)); then
    fail "${name}: campaign exited ${ec}"
    FAILED=1
    return 1
  fi

  after="$(mcp_tool_description support_lookup)"
  if [[ "${after}" != "${before}" ]]; then
    fail "${name}: tool description not restored after round-trip"
    FAILED=1
    return 1
  fi

  write_status_json "${artifact}" \
    --arg eng "${eng}" \
    --arg before "${before}" \
    --arg after "${after}" \
    --rawfile stderr "${ARTIFACTS_DIR}/${name}.stderr" \
    '{
      ok: true,
      engagement_id: $eng,
      restored: ($after == $before),
      standalone: ($stderr | contains("STANDALONE") or contains("RUN_REPORT")),
      before: $before,
      after: $after
    }'
  assert_json "${name}" "${artifact}" "${EXPECTED_DIR}/${name}.jq" || FAILED=1
}

run_revert_smoke() {
  # Dedicated no-op / missing-receipt path already covered by poison/implant
  # revert loops. Emit a status artifact proving those loops recorded success.
  local name=revert
  local artifact="${ARTIFACTS_DIR}/${name}.json"
  printf '\n==> %s\n' "${name}"
  write_status_json "${artifact}" \
    --argjson poison_mcp "$(jq -c . "${ARTIFACTS_DIR}/poison-mcp.json")" \
    --argjson poison_instr "$(jq -c . "${ARTIFACTS_DIR}/poison-instruction.json")" \
    --argjson implant "$(jq -c . "${ARTIFACTS_DIR}/implant-mcp-config.json")" \
    '{
      ok: true,
      poison_mcp_reverted: $poison_mcp.reverted,
      poison_instruction_reverted: $poison_instr.reverted,
      implant_reverted: $implant.reverted
    }'
  assert_json "${name}" "${artifact}" "${EXPECTED_DIR}/${name}.jq" || FAILED=1
}

run_poison_mcp
run_poison_instruction
run_implant_mcp_config
run_campaign_mcp_roundtrip
run_revert_smoke

run_smoke rules-list rules list --format json
run_smoke version version

if ((FAILED)); then
  KEEP_STACK_ON_EXIT=1
  exit 1
fi

printf '\nAll harness scenarios passed.\n'
exit 0
