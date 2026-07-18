#!/usr/bin/env bash
set -Eeuo pipefail

WITNESS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WITNESS_TEST_INFRA_DIR="$(cd "${WITNESS_SCRIPT_DIR}/.." && pwd)"
RUNTIME_PATH="${WITNESS_TEST_INFRA_DIR}/fixtures/runtime.json"
WITNESS_PATH="${WITNESS_TEST_INFRA_DIR}/fixtures/witness.json"

[[ -f "${RUNTIME_PATH}" ]] || fail 'runtime.json missing; seed real services first'

export AGENTHOUND_CAMPAIGN_CREDENTIAL
AGENTHOUND_CAMPAIGN_CREDENTIAL="$(jq -er '.contextforge.token' "${RUNTIME_PATH}")"
mcp_url="$(jq -er '.contextforge.mcp_url' "${RUNTIME_PATH}")"

node_id() {
  printf 'sha256:%s' "$(sha256_text "$1")"
}

export WITNESS_AGENT_ID WITNESS_CREDENTIAL_ID WITNESS_SERVER_ID
export WITNESS_RESOURCE_ID TEST_MODEL_ID

# Construct the exact identities that the real config and MCP projections
# produce. This is the credential-gated path the server would place in a
# campaign witness; no placeholder graph identities are introduced.
config_path=/root/.cursor/mcp.json
config_id="$(node_id "ConfigFile:${config_path}")"
WITNESS_AGENT_ID="$(node_id "AgentInstance:${config_id}:cursor")"
entry_server_id="$(node_id 'MCPServer:http:http://mcp-streamable:3001/mcp')"
entry_tool_id="$(node_id "MCPTool:${entry_server_id}:get-env")"
WITNESS_SERVER_ID="$(node_id "MCPServer:http:${mcp_url}")"
WITNESS_CREDENTIAL_ID="$(node_id 'Credential:contextforge-real:Authorization')"
identity_id="$(node_id "Identity:${WITNESS_SERVER_ID}:bearer")"
resource_tool_id="$(node_id "MCPTool:${WITNESS_SERVER_ID}:support-lookup")"
WITNESS_RESOURCE_ID="$(node_id "MCPResource:${WITNESS_SERVER_ID}:file:///data/support-cases/case-001.json")"
TEST_MODEL_ID="$(node_id 'AIModel:ggml-org/models:499bc882:tinyllamas/stories260K.gguf')"
credential_hash="$(sha256_text "${AGENTHOUND_CAMPAIGN_CREDENTIAL}")"

jq -n \
  --arg credential_hash "${credential_hash}" \
  --arg agent_id "${WITNESS_AGENT_ID}" \
  --arg credential_id "${WITNESS_CREDENTIAL_ID}" \
  --arg entry_server_id "${entry_server_id}" \
  --arg entry_tool_id "${entry_tool_id}" \
  --arg server_id "${WITNESS_SERVER_ID}" \
  --arg identity_id "${identity_id}" \
  --arg resource_tool_id "${resource_tool_id}" \
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
    evidence_node_ids: [
      $agent_id,
      $entry_server_id,
      $entry_tool_id,
      $server_id,
      $credential_id,
      $identity_id,
      $resource_tool_id,
      $resource_id
    ],
    evidence_node_kinds: [
      "AgentInstance",
      "MCPServer",
      "MCPTool",
      "MCPServer",
      "Credential",
      "Identity",
      "MCPTool",
      "MCPResource"
    ]
  }' >"${WITNESS_PATH}.tmp"
mv "${WITNESS_PATH}.tmp" "${WITNESS_PATH}"

jq -e '
  (.credential_value_hash | test("^[0-9a-f]{64}$")) and
  ([.agent_id, .credential_id, .server_id, .resource_id]
    | all(test("^sha256:[0-9a-f]{64}$"))) and
  (.evidence_node_ids | length) == 8 and
  (.evidence_node_kinds | length) == 8 and
  .credential_merge_key == "value_hash" and
  .resource_identity_input == "file:///data/support-cases/case-001.json"
' "${WITNESS_PATH}" >/dev/null

printf 'Generated witness from the real ContextForge server identity.\n'
