#!/usr/bin/env bash
# Export a campaign witness through AgentHound's production ingest, analysis,
# publication, and guarded witness path. No graph IDs or topology are computed
# by this harness.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=assertions.sh
source "${SCRIPT_DIR}/assertions.sh"

COMPOSE_FILE="$1"
CONFIG_OUTPUT="$2"
MCP_OUTPUT="$3"
RUNTIME_PATH="$4"
ARTIFACTS_DIR="$5"
WITNESS_PATH="$6"

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

ws() {
  compose exec -T workstation "$@"
}

for collected in "${CONFIG_OUTPUT}" "${MCP_OUTPUT}"; do
  jq -e '.meta.collection.state == "complete"' "${collected}" >/dev/null ||
    fail "production witness input is not a complete collector projection: ${collected}"
done

ws agenthound-server --log-level error ingest - <"${CONFIG_OUTPUT}" \
  >"${ARTIFACTS_DIR}/campaign-cred-reach-ingest-config.out" \
  2>"${ARTIFACTS_DIR}/campaign-cred-reach-ingest-config.stderr"
ws agenthound-server --log-level error ingest - <"${MCP_OUTPUT}" \
  >"${ARTIFACTS_DIR}/campaign-cred-reach-ingest-mcp.out" \
  2>"${ARTIFACTS_DIR}/campaign-cred-reach-ingest-mcp.stderr"

ws agenthound-server --log-level error query --findings --all-findings --format json \
  >"${ARTIFACTS_DIR}/campaign-cred-reach-findings.json" \
  2>"${ARTIFACTS_DIR}/campaign-cred-reach-findings.stderr"

resource_id="$(jq -er '
  [.graph.nodes[] | select(
    (.kinds | index("MCPResource")) and
    .properties.uri == "file:///data/support-cases/case-001.json"
  )] | if length == 1 then .[0].id else error("exact ContextForge resource not collected") end
' "${MCP_OUTPUT}")"
server_id="$(jq -er --arg url "$(jq -er '.contextforge.mcp_url' "${RUNTIME_PATH}")" '
  [.graph.nodes[] | select(
    (.kinds | index("MCPServer")) and .properties.endpoint == $url
  )] | if length == 1 then .[0].id else error("exact ContextForge server not collected") end
' "${MCP_OUTPUT}")"
finding_id="$(jq -er --arg resource "${resource_id}" '
  [.findings[] | select(
    .edge_kind == "CAN_REACH" and
    .target_kind == "MCPResource" and
    .target_id == $resource
  )] | if length >= 1 then .[0].id else error("published CAN_REACH finding absent") end
' "${ARTIFACTS_DIR}/campaign-cred-reach-findings.json")"

ws agenthound-server --log-level error witness --finding "${finding_id}" --output - \
  >"${WITNESS_PATH}.tmp" \
  2>"${ARTIFACTS_DIR}/campaign-cred-reach-witness.stderr"

credential_hash="$(sha256_text "$(jq -er '.contextforge.token' "${RUNTIME_PATH}")")"
jq -e \
  --arg resource_id "${resource_id}" \
  --arg server_id "${server_id}" \
  --arg credential_hash "${credential_hash}" \
  --argjson revision "$(jq -er '.scope.revision' "${ARTIFACTS_DIR}/campaign-cred-reach-findings.json")" '
  .agent_id as $agent_id |
  .credential_id as $credential_id |
  .server_id as $witness_server_id |
  .resource_id as $witness_resource_id |
  .schema_version == 2 and
  .topology_normalization_version == 1 and
  .publication_revision == $revision and
  .predicted_edge_kind == "CAN_REACH" and
  .agent_kind == "AgentInstance" and
  .credential_kind == "Credential" and
  .credential_merge_key == "value_hash" and
  .credential_value_hash == $credential_hash and
  .server_kind == "MCPServer" and .server_id == $server_id and
  .resource_kind == "MCPResource" and .resource_id == $resource_id and
  .resource_identity_input == "file:///data/support-cases/case-001.json" and
  (.evidence_node_ids | length) == (.evidence_node_kinds | length) and
  (.evidence_node_ids | index($agent_id)) != null and
  (.evidence_node_ids | index($credential_id)) != null and
  (.evidence_node_ids | index($witness_server_id)) != null and
  (.evidence_node_ids | index($witness_resource_id)) != null
' "${WITNESS_PATH}.tmp" >/dev/null
mv "${WITNESS_PATH}.tmp" "${WITNESS_PATH}"

printf 'Exported production witness for published finding %s.\n' "${finding_id}"
