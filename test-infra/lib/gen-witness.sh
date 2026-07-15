#!/usr/bin/env bash
set -Eeuo pipefail

# Source this file from run-tests.sh so both exports remain in the parent
# environment before `docker compose up` performs environment interpolation.
# Prefer BASH_SOURCE (bash); fall back to $0 for other hosts that may source us.
_src="${BASH_SOURCE[0]:-}"
if [[ -z "${_src}" || "${_src}" == "bash" || "${_src}" == "-bash" ]]; then
  _src="${0:-.}"
fi
SCRIPT_DIR="$(cd "$(dirname "${_src}")" && pwd)"
TEST_INFRA_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WITNESS_PATH="${TEST_INFRA_DIR}/fixtures/witness.json"
unset _src

sha256_text() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | awk '{print $1}'
  else
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  fi
}

node_id() {
  printf 'sha256:%s' "$(sha256_text "$1")"
}

export AGENTHOUND_CAMPAIGN_CREDENTIAL='sk-agenthound-offline-campaign-not-real'
export GATED_RESOURCE_TOKEN_HASH
GATED_RESOURCE_TOKEN_HASH="$(sha256_text "${AGENTHOUND_CAMPAIGN_CREDENTIAL}")"

export WITNESS_AGENT_ID WITNESS_CREDENTIAL_ID WITNESS_SERVER_ID
export WITNESS_RESOURCE_ID TEST_MODEL_ID
WITNESS_AGENT_ID="$(node_id 'AgentInstance:agenthound-offline-fixture')"
WITNESS_CREDENTIAL_ID="$(node_id 'Credential:agenthound-offline-fixture:campaign')"
WITNESS_SERVER_ID="$(node_id 'MCPServer:http:http://mcp-target-admin:8080/mcp')"
WITNESS_RESOURCE_ID="$(node_id "MCPResource:${WITNESS_SERVER_ID}:file:///data/support-cases/case-001.json")"
TEST_MODEL_ID="$(node_id 'AIModel:agenthound-synthetic-embedding-fixture')"

mkdir -p "$(dirname "${WITNESS_PATH}")"
tmp="${WITNESS_PATH}.tmp"
jq -n \
  --arg credential_hash "${GATED_RESOURCE_TOKEN_HASH}" \
  --arg agent_id "${WITNESS_AGENT_ID}" \
  --arg credential_id "${WITNESS_CREDENTIAL_ID}" \
  --arg server_id "${WITNESS_SERVER_ID}" \
  --arg resource_id "${WITNESS_RESOURCE_ID}" \
  '{
    schema_version: 2,
    topology_normalization_version: 1,
    publication_revision: 1,
    predicted_edge_kind: "CAN_REACH",
    agent_id: $agent_id,
    agent_kind: "AgentInstance",
    credential_id: $credential_id,
    credential_kind: "Credential",
    credential_value_hash: $credential_hash,
    credential_merge_key: "value_hash",
    server_id: $server_id,
    server_kind: "MCPServer",
    resource_id: $resource_id,
    resource_kind: "MCPResource",
    resource_identity_input: "file:///data/support-cases/case-001.json",
    evidence_node_ids: [$agent_id, $credential_id, $server_id, $resource_id],
    evidence_node_kinds: ["AgentInstance", "Credential", "MCPServer", "MCPResource"]
  }' >"${tmp}"
mv "${tmp}" "${WITNESS_PATH}"

jq -e \
  --arg credential_hash "${GATED_RESOURCE_TOKEN_HASH}" \
  --arg agent_id "${WITNESS_AGENT_ID}" \
  --arg credential_id "${WITNESS_CREDENTIAL_ID}" \
  --arg server_id "${WITNESS_SERVER_ID}" \
  --arg resource_id "${WITNESS_RESOURCE_ID}" \
  '
    .credential_value_hash == $credential_hash and
    (.credential_value_hash | test("^[0-9a-f]{64}$")) and
    ([.agent_id, .credential_id, .server_id, .resource_id]
      | all(test("^sha256:[0-9a-f]{64}$"))) and
    .agent_id == $agent_id and
    .credential_id == $credential_id and
    .server_id == $server_id and
    .resource_id == $resource_id and
    .resource_identity_input == "file:///data/support-cases/case-001.json" and
    .evidence_node_ids == [$agent_id, $credential_id, $server_id, $resource_id] and
    .evidence_node_kinds == ["AgentInstance", "Credential", "MCPServer", "MCPResource"]
  ' "${WITNESS_PATH}" >/dev/null
