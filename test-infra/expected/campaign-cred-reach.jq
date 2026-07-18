.meta.collection.state == "complete"
and (.graph.nodes | length) == 2
and ([.graph.nodes[].kinds[0]] | sort) == ["AgentInstance","MCPResource"]
and (.graph.edges | length) == 1
and (.graph.edges[0] | .kind == "CREDENTIAL_REACH_VERIFIED"
  and .source_kind == "AgentInstance"
  and .target_kind == "MCPResource"
  and .properties.oracle_type == "differential_credential_reach"
  and .properties.outcome == "credential_gated_reach_verified"
  and .properties.control_stage == "initialize"
  and .properties.control_status == "denied"
  and .properties.control_resource_addressed == false
  and .properties.authed_stage == "resource_read"
  and .properties.authed_status == "allowed"
  and .properties.authed_resource_addressed == true
  and .properties.credential_merge_key == "value_hash"
  and (.properties.credential_value_hash | test("^[0-9a-f]{64}$"))
  and .properties.evidence_node_kinds == [
    "AgentInstance",
    "MCPServer",
    "MCPTool",
    "MCPServer",
    "Credential",
    "Identity",
    "MCPTool",
    "MCPResource"
  ]
  and (.properties.evidence_node_ids | length) == 8
  and .properties.server_id == .properties.evidence_node_ids[3]
  and .properties.credential_id == .properties.evidence_node_ids[4]
  and .properties.resource_id == .properties.evidence_node_ids[7]
  and .source == .properties.agent_id
  and .target == .properties.resource_id)
