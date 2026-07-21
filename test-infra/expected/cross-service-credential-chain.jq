.ok == true
and .scenario == "cross-service-credential-chain"
and .inputs == {config:"complete",mcp:"complete",litellm_loot:"complete"}
and .correlation.basis == "value_hash"
and (.correlation.value_hash | test("^[0-9a-f]{64}$"))
and .correlation.config_location == "header"
and (.correlation.configured_credential_id | test("^sha256:[0-9a-f]{64}$"))
and (.correlation.master_credential_id | test("^sha256:[0-9a-f]{64}$"))
and .correlation.configured_credential_id != .correlation.master_credential_id
and (.correlation.proof_credential_id | test("^sha256:[0-9a-f]{64}$"))
and .correlation.target_count == 3
and .correlation.high_entropy_server_attribution == true
and (.targets | length) == 3
and ([.targets[].id] | unique | length) == 3
and ([.targets[].finding_id] | unique | length) == 3
and (.targets | all(
  (.id | test("^sha256:[0-9a-f]{64}$")) and
  (.finding_id | test("^[0-9a-f]{16}$")) and
  .persisted_finding_id == .finding_id and
  .source == "litellm" and
  .exposure_status == "not_observed"
))
and ([.targets[] | select(.type == "apiKey") | {
  name,provider,merge_key,identity_basis,material_status,exposure_status
}] | sort_by(.provider)) == [
  {
    name:"upstream-agenthound-anthropic-placeholder",
    provider:"anthropic",
    merge_key:"identity",
    identity_basis:"provider_name",
    material_status:"masked",
    exposure_status:"not_observed"
  },
  {
    name:"upstream-agenthound-openai-placeholder",
    provider:"openai",
    merge_key:"identity",
    identity_basis:"provider_name",
    material_status:"masked",
    exposure_status:"not_observed"
  }
]
and ([.targets[] | select(
  .type == "virtual_key" and
  (.name | test("^virtual-[0-9a-f]{64}$")) and
  .provider == null and
  .merge_key == "value_hash" and
  .identity_basis == "value_hash" and
  .material_status == "hashed" and
  .exposure_status == "not_observed"
)] | length) == 1
and .findings.count == 3
and .findings.detector == "cross_service_credential_chain"
and (.findings.publication_revision | type == "number" and . > 0)
and .findings.ids == ([.targets[].finding_id] | sort)
and .topology.hops == 6
and (.topology.via_gateway | type == "string" and length > 0)
and .topology.target_count == 3
and (.topology.witnesses | length) == 3
and ([.topology.witnesses[].target_id] | sort) == ([.targets[].id] | sort)
and (.topology.witnesses | all(
  . as $witness |
  ($witness.node_ids | length) == 7 and
  ($witness.node_ids | all(test("^sha256:[0-9a-f]{64}$"))) and
  $witness.node_ids[6] == $witness.target_id and
  $witness.raw_relationships == [
    {source:$witness.node_ids[0],target:$witness.node_ids[1],kind:"TRUSTS_SERVER"},
    {source:$witness.node_ids[1],target:$witness.node_ids[2],kind:"AUTHENTICATES_WITH"},
    {source:$witness.node_ids[2],target:$witness.node_ids[3],kind:"USES_CREDENTIAL"},
    {source:$witness.node_ids[5],target:$witness.node_ids[4],kind:"EXPOSES_CREDENTIAL"},
    {source:$witness.node_ids[5],target:$witness.node_ids[6],kind:"EXPOSES_CREDENTIAL"}
  ]
))
and .topology.raw_relationship_kinds
  == ["TRUSTS_SERVER","AUTHENTICATES_WITH","USES_CREDENTIAL","EXPOSES_CREDENTIAL","EXPOSES_CREDENTIAL"]
and .topology.synthetic_relationship == "VALUE_HASH_MATCH"
