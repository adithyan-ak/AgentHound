.meta.collection.state == "complete"
and ([.graph.nodes[] | select(.kinds | index("A2AAgent")) | .properties.name] | sort)
  == ["ClaimsTriageAgent","LegacyArchiveAgent","PayrollAgent"]
and ([.graph.nodes[] | select(.kinds | index("A2ASkill")) | .properties.name] | sort)
  == ["ArchivePayslip","RunPayroll","TriageClaim"]
and ([.graph.nodes[] | select(
  (.kinds | index("A2AAgent")) and .properties.name == "PayrollAgent"
) | .properties.signature_verification_status]) == ["valid_trusted"]
and ([.graph.nodes[] | select(
  (.kinds | index("A2AAgent")) and .properties.name == "LegacyArchiveAgent"
) | .properties.signature_verification_status]) == ["unsigned"]
and ([.graph.nodes[] | select(.kinds | index("A2AAgent")) | .properties.card_conformant] | unique) == [true]
and ([.graph.edges[] | select(.kind == "ADVERTISES_SKILL")] | length) == 3
and ([.graph.edges[] | select(.kind == "DELEGATES_TO")] | length) == 1
and (.graph.edges | any(
  .kind == "DELEGATES_TO" and
  .properties.evidence_state == "hypothesis" and
  .properties.match_type == "lexical_name" and
  .properties.matched_reference == "payrollagent"
))
