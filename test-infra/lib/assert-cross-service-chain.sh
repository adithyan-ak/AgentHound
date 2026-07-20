#!/usr/bin/env bash
# Prove cross_service_credential_chain from three real collector outputs
# through production ingest, analysis, publication, and persisted evidence.
# Raw credential material is neither accepted as an argument nor written.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=assertions.sh
source "${SCRIPT_DIR}/assertions.sh"

COMPOSE_FILE="$1"
CONFIG_OUTPUT="$2"
MCP_OUTPUT="$3"
LITELLM_OUTPUT="$4"
ARTIFACTS_DIR="$5"
RESULT_PATH="$6"
GATE_URL=http://mcp-cross-service-gate:3003/mcp

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

ws() {
  compose exec -T workstation "$@"
}

for collected in "${CONFIG_OUTPUT}" "${MCP_OUTPUT}" "${LITELLM_OUTPUT}"; do
  jq -e '.meta.collection.state == "complete"' "${collected}" >/dev/null ||
    fail "cross-service input is not a complete collector projection: ${collected}"
done

# Derive the correlation from the actual LiteLLM looter output. The harness
# never recomputes or hard-codes this hash as a substitute for collector data.
master_hash="$(jq -er '
  [.graph.nodes[] | select(
    (.kinds | index("Credential")) and
    .properties.type == "master_key" and
    .properties.merge_key == "value_hash" and
    .properties.identity_basis == "value_hash" and
    .properties.material_status == "observed" and
    .properties.exposure_status == "exposed"
  )] |
  if length == 1 then .[0].properties.value_hash
  else error("expected exactly one observed LiteLLM master credential") end
' "${LITELLM_OUTPUT}")"
[[ "${master_hash}" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'LiteLLM master credential has no canonical nonempty value_hash'

config_server_id="$(jq -er --arg endpoint "${GATE_URL}" '
  [.graph.nodes[] | select(
    (.kinds | index("MCPServer")) and
    .properties.transport == "http" and
    .properties.endpoint == $endpoint
  )] | if length == 1 then .[0].id
      else error("exact cross-service MCP server absent from config output") end
' "${CONFIG_OUTPUT}")"
config_credential_id="$(jq -er --arg hash "${master_hash}" '
  [.graph.nodes[] | select(
    (.kinds | index("Credential")) and
    .properties.name == "Authorization" and
    .properties.location == "header" and
    .properties.value_hash == $hash and
    .properties.merge_key == "value_hash" and
    .properties.identity_basis == "value_hash" and
    .properties.material_status == "observed" and
    .properties.exposure_status == "exposed" and
    (.properties | has("value") | not)
  )] | if length == 1 then .[0].id
      else error("exact header-backed master credential absent from config output") end
' "${CONFIG_OUTPUT}")"

# The second required gate header gives the real corpus one positive
# high-entropy, non-env Credential without changing the value_hash join.
proof_credential_id="$(jq -er '
  [.graph.nodes[] | select(
    (.kinds | index("Credential")) and
    .properties.name == "X-AgentHound-Secret" and
    .properties.location == "header" and
    .properties.high_entropy == true and
    .properties.merge_key == "value_hash" and
    .properties.material_status == "observed" and
    .properties.exposure_status == "exposed" and
    (.properties.value_hash | test("^[0-9a-f]{64}$")) and
    (.properties | has("value") | not)
  )] | if length == 1 then .[0].id
      else error("enforced high-entropy proof header is not unique") end
' "${CONFIG_OUTPUT}")"
proof_identity_id="$(jq -er --arg proof "${proof_credential_id}" '
  [.graph.edges[] | select(
    .kind == "USES_CREDENTIAL" and .target == $proof
  )] | if length == 1 then .[0].source
      else error("high-entropy proof credential identity is not unique") end
' "${CONFIG_OUTPUT}")"
jq -e --arg server "${config_server_id}" --arg identity "${proof_identity_id}" '
  [.graph.edges[] | select(
    .kind == "AUTHENTICATES_WITH" and
    .source == $server and .target == $identity
  )] | length == 1
' "${CONFIG_OUTPUT}" >/dev/null ||
  fail 'enforced high-entropy proof header lacks canonical server attribution'

identity_id="$(jq -er --arg credential "${config_credential_id}" '
  [.graph.edges[] | select(
    .kind == "USES_CREDENTIAL" and .target == $credential
  )] | if length == 1 then .[0].source
      else error("master credential does not have exactly one canonical identity") end
' "${CONFIG_OUTPUT}")"
jq -e --arg server "${config_server_id}" --arg identity "${identity_id}" '
  [.graph.edges[] | select(
    .kind == "AUTHENTICATES_WITH" and
    .source == $server and .target == $identity
  )] | length == 1
' "${CONFIG_OUTPUT}" >/dev/null ||
  fail 'configured master credential is not on MCPServer -> Identity -> Credential topology'
agent_id="$(jq -er --arg server "${config_server_id}" '
  [.graph.edges[] | select(
    .kind == "TRUSTS_SERVER" and .target == $server
  )] | if length == 1 then .[0].source
      else error("cross-service MCP server does not have exactly one trusting agent") end
' "${CONFIG_OUTPUT}")"

master_credential_id="$(jq -er --arg hash "${master_hash}" '
  [.graph.nodes[] | select(
    (.kinds | index("Credential")) and
    .properties.type == "master_key" and
    .properties.value_hash == $hash
  )] | if length == 1 then .[0].id
      else error("LiteLLM master ID cannot be resolved") end
' "${LITELLM_OUTPUT}")"
gateway_id="$(jq -er --arg master "${master_credential_id}" '
  [.graph.edges[] | select(
    .kind == "EXPOSES_CREDENTIAL" and .target == $master
  )] | if length == 1 then .[0].source
      else error("LiteLLM gateway -> master evidence is not unique") end
' "${LITELLM_OUTPUT}")"
target_descriptors="$(jq -cer \
  --arg gateway "${gateway_id}" \
  --arg master "${master_credential_id}" '
  . as $document |
  ([$document.graph.edges[] | select(
    .kind == "EXPOSES_CREDENTIAL" and
    .source == $gateway and
    .target != $master
  ) | .target] | unique) as $exposed |
  ([$document.graph.nodes[] | select(
    (.kinds | index("Credential")) and
    (.id as $id | ($exposed | index($id)) != null) and
    (.properties.type == "apiKey" or .properties.type == "virtual_key") and
    (.properties | has("value") | not)
  ) | {
    id,
    name:.properties.name,
    type:.properties.type,
    source:.properties.source,
    provider:(.properties.provider // null),
    merge_key:.properties.merge_key,
    identity_basis:.properties.identity_basis,
    material_status:.properties.material_status,
    exposure_status:.properties.exposure_status
  }] | sort_by(.id)) as $targets |
  if
    ($targets | length) == 3 and
    ([$targets[] | select(
      .type == "apiKey" and
      .source == "litellm" and
      .merge_key == "identity" and
      .identity_basis == "provider_name" and
      .material_status == "masked" and
      .exposure_status == "not_observed"
    ) | .provider] | sort) == ["anthropic","openai"] and
    ([$targets[] | select(
      .type == "virtual_key" and
      .source == "litellm" and
      .provider == null and
      .merge_key == "value_hash" and
      .identity_basis == "value_hash" and
      .material_status == "hashed" and
      .exposure_status == "not_observed"
    )] | length) == 1
  then $targets
  else error("real LiteLLM processor target set is not the pinned two apiKey plus one virtual_key corpus") end
' "${LITELLM_OUTPUT}")"
target_ids="$(printf '%s' "${target_descriptors}" | jq -c 'map(.id) | sort')"

# Re-ingestion is deliberate: same-ID production retries are supported, and
# this makes the lane independent of the earlier credential-reach campaign's
# success while preserving the required config -> MCP -> looter order.
ws agenthound-server --log-level error ingest - <"${CONFIG_OUTPUT}" \
  >"${ARTIFACTS_DIR}/cross-service-credential-chain-ingest-config.out" \
  2>"${ARTIFACTS_DIR}/cross-service-credential-chain-ingest-config.stderr"
ws agenthound-server --log-level error ingest - <"${MCP_OUTPUT}" \
  >"${ARTIFACTS_DIR}/cross-service-credential-chain-ingest-mcp.out" \
  2>"${ARTIFACTS_DIR}/cross-service-credential-chain-ingest-mcp.stderr"
ws agenthound-server --log-level error ingest - <"${LITELLM_OUTPUT}" \
  >"${ARTIFACTS_DIR}/cross-service-credential-chain-ingest-litellm.out" \
  2>"${ARTIFACTS_DIR}/cross-service-credential-chain-ingest-litellm.stderr"

ws agenthound-server --log-level error query --findings --all-findings --format json \
  >"${ARTIFACTS_DIR}/cross-service-credential-chain-findings.json" \
  2>"${ARTIFACTS_DIR}/cross-service-credential-chain-findings.stderr"
ws agenthound-server --log-level error query --prebuilt high-entropy-secrets --format json \
  >"${ARTIFACTS_DIR}/cross-service-credential-chain-high-entropy.json" \
  2>"${ARTIFACTS_DIR}/cross-service-credential-chain-high-entropy.stderr"

# Public findings intentionally omit the larger exact-evidence object. Verify
# both public publication and the production-persisted exact evidence below.
public_matches="$(jq -cer \
  --arg source "${agent_id}" \
  --argjson targets "${target_descriptors}" '
  ($targets | map(.id) | sort) as $target_ids |
  ([.findings[] | select(
    .source_id == $source and
    .evidence.detector == "cross_service_credential_chain"
  )] | sort_by(.target_id)) as $matches |
  if
  .scope.available == true and
  .scope.stale == false and
  (.scope.revision | type == "number" and . > 0) and
  ($matches | map(.target_id) | sort) == $target_ids and
  ($matches | length) == ($targets | length) and
  ($matches | all(
    . as $finding |
    ($targets[] | select(.id == $finding.target_id)) as $target |
    $finding.edge_kind == "CAN_REACH" and
    $finding.source_kind == "AgentInstance" and
    $finding.target_kind == "Credential" and
    $finding.confidence == 0.95 and
    $finding.variant == "credential_chain_reference" and
    $finding.evidence.state == "reference_only" and
    $finding.evidence.detector == "cross_service_credential_chain" and
    $finding.evidence.material_status == $target.material_status and
    $finding.evidence.exposure_status == $target.exposure_status
  ))
  then $matches
  else error("published cross-service finding target set or evidence is incomplete") end
' "${ARTIFACTS_DIR}/cross-service-credential-chain-findings.json")" ||
  fail 'published cross-service findings do not exactly cover every real LiteLLM processor target'
jq -e \
  --arg credential "${proof_credential_id}" \
  --arg server "${config_server_id}" \
  --argjson revision "$(jq -er '.scope.revision' "${ARTIFACTS_DIR}/cross-service-credential-chain-findings.json")" '
  .projection.revision == $revision and
  ([.rows[] | select(
    .credential_id == $credential and
    .credential_name == "X-AgentHound-Secret" and
    .credential_type == "hardcoded" and
    .server_id == $server and
    .server_name == "http://mcp-cross-service-gate:3003/mcp" and
    .source == "litellm-master-gated-everything"
  )] | length) == 1
' "${ARTIFACTS_DIR}/cross-service-credential-chain-high-entropy.json" >/dev/null ||
  fail 'published high-entropy query did not attribute the enforced header to its MCP server'

graph_query='MATCH (a:AgentInstance)-[e:CAN_REACH]->(target:Credential)
WHERE e.source_collector = "cross_service_credential_chain"
WITH a, e, target
MATCH (gateway:LiteLLMGateway)
WHERE gateway.objectid = e.evidence_node_ids[5]
RETURN a.objectid AS source_id,
       target.objectid AS target_id,
       e.hops AS hops,
       e.merge_value_hash AS merge_value_hash,
       e.via_gateway AS via_gateway,
       coalesce(gateway.name, gateway.endpoint, gateway.objectid) AS expected_via_gateway,
       e.evidence_node_ids AS evidence_node_ids,
       size(e.evidence_relationship_ids) AS evidence_relationship_count,
       e.evidence_synthetic_edge AS evidence_synthetic_edge
ORDER BY source_id, target_id'
ws agenthound-server --log-level error query "${graph_query}" --format json \
  >"${ARTIFACTS_DIR}/cross-service-credential-chain-graph.json" \
  2>"${ARTIFACTS_DIR}/cross-service-credential-chain-graph.stderr"

expected_synthetic="$(jq -nc \
  --arg configured "${config_credential_id}" \
  --arg master "${master_credential_id}" '
  [$configured,$master,"VALUE_HASH_MATCH","identity_correlation","value_hash","cross_service_credential_chain"]
')"
graph_matches="$(jq -cer \
  --arg source "${agent_id}" \
  --argjson target_ids "${target_ids}" '
  ([.[] | select(.source_id == $source)] | sort_by(.target_id)) as $matches |
  if
    ($matches | length) == ($target_ids | length) and
    ($matches | map(.target_id) | sort) == $target_ids
  then $matches
  else error("current cross-service graph target set is incomplete or contains extras") end
' "${ARTIFACTS_DIR}/cross-service-credential-chain-graph.json")"
printf '%s' "${graph_matches}" | jq -e \
  --arg hash "${master_hash}" \
  --arg agent "${agent_id}" \
  --arg server "${config_server_id}" \
  --arg identity "${identity_id}" \
  --arg configured "${config_credential_id}" \
  --arg master "${master_credential_id}" \
  --arg gateway "${gateway_id}" \
  --argjson target_ids "${target_ids}" \
  --argjson synthetic "${expected_synthetic}" '
  ($hash | test("^[0-9a-f]{64}$")) and
  (map(.target_id) | sort) == $target_ids and
  all(
    .hops == 6 and
    .merge_value_hash == $hash and
    (.via_gateway | type == "string" and length > 0) and
    .via_gateway == .expected_via_gateway and
    .evidence_node_ids == [
      $agent,$server,$identity,$configured,$master,$gateway,.target_id
    ] and
    .evidence_relationship_count == 5 and
    .evidence_synthetic_edge == $synthetic
  )
' >/dev/null ||
  fail 'current graph edges do not preserve canonical topology metadata for every LiteLLM target'
via_gateway="$(printf '%s' "${graph_matches}" | jq -er '
  (map(.via_gateway) | unique) as $identifiers |
  if ($identifiers | length) == 1 then $identifiers[0]
  else error("cross-service edges disagree on the LiteLLM gateway identifier") end
')"

# Read the exact evidence frozen by production publication, rather than
# reconstructing a similar path in the harness. Each output line is one JSON
# finding and contains public hashes/IDs only.
compose exec -T analysis-postgres \
  psql -X -v ON_ERROR_STOP=1 -U agenthound -d agenthound -At -c \
  "SELECT jsonb_build_object(
     'finding_id', btrim(f.fingerprint),
     'source_id', f.source_id,
     'target_id', f.target_id,
     'exact_evidence', f.exact_evidence
   )::text
   FROM findings f
   JOIN posture_state p ON p.published_scan_id = f.scan_id
   WHERE f.evidence->>'detector' = 'cross_service_credential_chain'
   ORDER BY f.source_id, f.target_id" \
  >"${ARTIFACTS_DIR}/cross-service-credential-chain-persisted-evidence.ndjson"
jq -s '.' "${ARTIFACTS_DIR}/cross-service-credential-chain-persisted-evidence.ndjson" \
  >"${ARTIFACTS_DIR}/cross-service-credential-chain-persisted-evidence.json"

persisted_matches="$(jq -cer \
  --arg source "${agent_id}" \
  --argjson target_ids "${target_ids}" '
  ([.[] | select(.source_id == $source)] | sort_by(.target_id)) as $matches |
  if
    ($matches | length) == ($target_ids | length) and
    ($matches | map(.target_id) | sort) == $target_ids
  then $matches
  else error("persisted cross-service finding target set is incomplete or contains extras") end
' "${ARTIFACTS_DIR}/cross-service-credential-chain-persisted-evidence.json")"
printf '%s' "${persisted_matches}" | jq -e \
  --arg hash "${master_hash}" \
  --arg agent "${agent_id}" \
  --arg server "${config_server_id}" \
  --arg identity "${identity_id}" \
  --arg configured "${config_credential_id}" \
  --arg master "${master_credential_id}" \
  --arg gateway "${gateway_id}" \
  --argjson targets "${target_descriptors}" \
  --argjson public_matches "${public_matches}" '
  (map(.target_id) | sort) == ($targets | map(.id) | sort) and
  all(
    . as $persisted |
    ($targets[] | select(.id == $persisted.target_id)) as $target |
    ($public_matches[] | select(.target_id == $persisted.target_id)) as $public |
    $persisted.finding_id == $public.id and
    ($persisted.finding_id | test("^[0-9a-f]{16}$")) and
    $persisted.exact_evidence.version == 1 and
    $persisted.exact_evidence.complete == true and
    $persisted.exact_evidence.reasons == [] and
    [$persisted.exact_evidence.nodes[].id] == [
      $agent,$server,$identity,$configured,$master,$gateway,$target.id
    ] and
    ($persisted.exact_evidence.nodes[0].kinds | index("AgentInstance")) != null and
    ($persisted.exact_evidence.nodes[1].kinds | index("MCPServer")) != null and
    ($persisted.exact_evidence.nodes[2].kinds | index("Identity")) != null and
    ($persisted.exact_evidence.nodes[3].kinds | index("Credential")) != null and
    $persisted.exact_evidence.nodes[3].properties.value_hash == $hash and
    ($persisted.exact_evidence.nodes[4].kinds | index("Credential")) != null and
    $persisted.exact_evidence.nodes[4].properties.value_hash == $hash and
    ($persisted.exact_evidence.nodes[5].kinds | index("LiteLLMGateway")) != null and
    ($persisted.exact_evidence.nodes[6].kinds | index("Credential")) != null and
    $persisted.exact_evidence.nodes[6].properties.name == $target.name and
    $persisted.exact_evidence.nodes[6].properties.type == $target.type and
    $persisted.exact_evidence.nodes[6].properties.source == $target.source and
    ($persisted.exact_evidence.nodes[6].properties.provider // null) == $target.provider and
    $persisted.exact_evidence.nodes[6].properties.merge_key == $target.merge_key and
    $persisted.exact_evidence.nodes[6].properties.identity_basis == $target.identity_basis and
    $persisted.exact_evidence.nodes[6].properties.material_status == $target.material_status and
    $persisted.exact_evidence.nodes[6].properties.exposure_status == $target.exposure_status and
    ([$persisted.exact_evidence.edges[] | select(.synthetic == false) |
      {source,target,kind}]) == [
      {source:$agent,target:$server,kind:"TRUSTS_SERVER"},
      {source:$server,target:$identity,kind:"AUTHENTICATES_WITH"},
      {source:$identity,target:$configured,kind:"USES_CREDENTIAL"},
      {source:$gateway,target:$master,kind:"EXPOSES_CREDENTIAL"},
      {source:$gateway,target:$target.id,kind:"EXPOSES_CREDENTIAL"}
    ] and
    ([$persisted.exact_evidence.edges[] | select(.synthetic == true)] | length) == 1 and
    ([$persisted.exact_evidence.edges[] | select(.synthetic == true)][0] |
      .source == $configured and
      .target == $master and
      .kind == "VALUE_HASH_MATCH" and
      .provenance.type == "identity_correlation" and
      .provenance.basis == "value_hash" and
      .provenance.source_collector == "cross_service_credential_chain")
  )
' >/dev/null ||
  fail 'persisted findings do not preserve the canonical witness for every LiteLLM target'

publication_revision="$(jq -er '.scope.revision' "${ARTIFACTS_DIR}/cross-service-credential-chain-findings.json")"
status_targets="$(jq -nc \
  --argjson targets "${target_descriptors}" \
  --argjson public_matches "${public_matches}" \
  --argjson persisted_matches "${persisted_matches}" '
  $targets | map(
    . as $target |
    ($public_matches[] | select(.target_id == $target.id)) as $public |
    ($persisted_matches[] | select(.target_id == $target.id)) as $persisted |
    $target + {
      finding_id:$public.id,
      persisted_finding_id:$persisted.finding_id
    }
  )
')"
topology_witnesses="$(jq -nc \
  --arg agent "${agent_id}" \
  --arg server "${config_server_id}" \
  --arg identity "${identity_id}" \
  --arg configured "${config_credential_id}" \
  --arg master "${master_credential_id}" \
  --arg gateway "${gateway_id}" \
  --argjson targets "${target_descriptors}" '
  $targets | map(
    .id as $target |
    {
      target_id:$target,
      node_ids:[$agent,$server,$identity,$configured,$master,$gateway,$target],
      raw_relationships:[
        {source:$agent,target:$server,kind:"TRUSTS_SERVER"},
        {source:$server,target:$identity,kind:"AUTHENTICATES_WITH"},
        {source:$identity,target:$configured,kind:"USES_CREDENTIAL"},
        {source:$gateway,target:$master,kind:"EXPOSES_CREDENTIAL"},
        {source:$gateway,target:$target,kind:"EXPOSES_CREDENTIAL"}
      ]
    }
  )
')"

write_status_json "${RESULT_PATH}" \
  --arg hash "${master_hash}" \
  --arg configured_credential_id "${config_credential_id}" \
  --arg master_credential_id "${master_credential_id}" \
  --arg proof_credential_id "${proof_credential_id}" \
  --arg via_gateway "${via_gateway}" \
  --argjson publication_revision "${publication_revision}" \
  --argjson targets "${status_targets}" \
  --argjson witnesses "${topology_witnesses}" '
  {
    ok:true,
    scenario:"cross-service-credential-chain",
    inputs:{config:"complete",mcp:"complete",litellm_loot:"complete"},
    correlation:{
      basis:"value_hash",
      value_hash:$hash,
      config_location:"header",
      configured_credential_id:$configured_credential_id,
      master_credential_id:$master_credential_id,
      proof_credential_id:$proof_credential_id,
      target_count:($targets | length),
      high_entropy_server_attribution:true
    },
    targets:$targets,
    findings:{
      count:($targets | length),
      ids:($targets | map(.finding_id) | sort),
      detector:"cross_service_credential_chain",
      publication_revision:$publication_revision
    },
    topology:{
      hops:6,
      via_gateway:$via_gateway,
      target_count:($targets | length),
      witnesses:$witnesses,
      raw_relationship_kinds:[
        "TRUSTS_SERVER","AUTHENTICATES_WITH","USES_CREDENTIAL",
        "EXPOSES_CREDENTIAL","EXPOSES_CREDENTIAL"
      ],
      synthetic_relationship:"VALUE_HASH_MATCH"
    }
  }
'

pass 'production cross-service credential-chain projection and evidence'
