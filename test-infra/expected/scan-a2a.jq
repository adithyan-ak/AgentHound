.meta.collection.state == "complete"
and ([.graph.nodes[] | select(.kinds | index("A2AAgent")) | .properties.name] | sort)
  == [
    "ClaimsTriageAgent",
    "LegacyArchiveAgent",
    "LegacySDKAgent",
    "PayrollAgent",
    "ProtectedPaymentsAgent",
    "VersionAmbiguousAgent"
  ]
and ([.graph.nodes[] | select(.kinds | index("A2ASkill")) | .properties.name] | sort)
  == [
    "AmbiguousControl",
    "ArchivePayslip",
    "LegacySDKLookup",
    "ProtectedPaymentLookup",
    "RunPayroll",
    "TriageClaim"
  ]
and ([.graph.nodes[] | select(
  (.kinds | index("A2AAgent")) and .properties.name == "PayrollAgent"
) | .properties.signature_verification_status]) == ["valid_trusted"]
and ([.graph.nodes[] | select(
  (.kinds | index("A2AAgent")) and .properties.name == "LegacyArchiveAgent"
) | .properties.signature_verification_status]) == ["unsigned"]
and ([.graph.nodes[] | select(.kinds | index("A2AAgent")) | .properties.card_conformant] | unique) == [true]
and ([.graph.edges[] | select(.kind == "ADVERTISES_SKILL")] | length) == 6
and ([.graph.edges[] | select(.kind == "DELEGATES_TO")] | length) == 1
and (.graph.edges | any(
  .kind == "DELEGATES_TO" and
  .properties.evidence_state == "hypothesis" and
  .properties.match_type == "lexical_name" and
  .properties.matched_reference == "payrollagent"
))
and ([.graph.nodes[] | select(
  (.kinds | index("A2AAgent")) and .properties.name == "ClaimsTriageAgent"
) | .properties] | length) == 1
and ([.graph.nodes[] | select(
  (.kinds | index("A2AAgent")) and .properties.name == "ClaimsTriageAgent"
) | .properties][0] as $v1 |
  $v1.auth_method == "unknown" and
  $v1.auth_assurance == "unknown" and
  $v1.auth_evidence == "declared_security_scheme" and
  $v1.auth_probe_method == "get_task_nonexistent" and
  $v1.auth_probe_status == "anonymous_protocol_access" and
  $v1.auth_probe_detail == "task_not_found_v1" and
  $v1.observed_auth_method == "none" and
  $v1.observed_auth_assurance == "unauthenticated" and
  $v1.observed_auth_evidence == "anonymous_probe_succeeded"
)
and ([.graph.nodes[] | select(
  (.kinds | index("A2AAgent")) and .properties.name == "LegacySDKAgent"
) | .properties][0] as $v03 |
  $v03.card_schema_version == "v0.3.0" and
  $v03.auth_probe_method == "get_task_nonexistent" and
  $v03.auth_probe_status == "anonymous_protocol_access" and
  $v03.auth_probe_detail == "task_not_found_v0_3" and
  $v03.observed_auth_method == "none" and
  $v03.observed_auth_assurance == "unauthenticated" and
  $v03.observed_auth_evidence == "anonymous_probe_succeeded"
)
and ([.graph.nodes[] | select(
  (.kinds | index("A2AAgent")) and .properties.name == "ProtectedPaymentsAgent"
) | .properties][0] as $protected |
  $protected.auth_method == "apiKey" and
  $protected.auth_assurance == "weak" and
  $protected.auth_evidence == "declared_security_scheme" and
  $protected.auth_probe_method == "get_task_nonexistent" and
  $protected.auth_probe_status == "authentication_required" and
  $protected.auth_probe_detail == "http_unauthorized" and
  ($protected | has("observed_auth_method") | not) and
  ($protected | has("observed_auth_assurance") | not) and
  ($protected | has("observed_auth_evidence") | not)
)
and ([.graph.nodes[] | select(
  (.kinds | index("A2AAgent")) and .properties.name == "VersionAmbiguousAgent"
) | .properties][0] as $ambiguous |
  $ambiguous.auth_probe_method == "get_task_nonexistent" and
  $ambiguous.auth_probe_status == "unknown" and
  $ambiguous.auth_probe_detail == "non_task_not_found_error" and
  ($ambiguous | has("observed_auth_method") | not) and
  ($ambiguous | has("observed_auth_assurance") | not) and
  ($ambiguous | has("observed_auth_evidence") | not)
)
and ([.graph.nodes[] | select(
  (.kinds | index("A2AAgent")) and
  (.properties.name == "PayrollAgent" or .properties.name == "LegacyArchiveAgent")
) | .properties] | all(
  .auth_probe_method == "get_task_nonexistent" and
  .auth_probe_status == "unknown" and
  .auth_probe_detail == "unexpected_http_status" and
  (has("observed_auth_method") | not) and
  (has("observed_auth_assurance") | not) and
  (has("observed_auth_evidence") | not)
))
