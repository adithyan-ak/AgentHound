.meta.collection.state == "complete"
and (.meta.extra.partial_errors | length) == 0
and (.graph.nodes | any(
  (.kinds | index("OpenWebUIInstance")) and
  .properties.endpoint == "http://openwebui:3000" and
  .properties.loot_observed == true and
  (.properties | has("discovered_via") | not) and
  .properties.auth_required == true and
  .properties.signup_enabled == false and
  .properties.probe_status == "verified"
))
and (.graph.nodes | any(
  (.kinds | index("OllamaInstance")) and
  .properties.endpoint == "http://ollama:11434" and
  .properties.configuration_observed == true and
  .properties.configured_via == "openwebui" and
  .properties.configured_auth_method == "unknown" and
  (.properties | has("loot_observed") | not) and
  (.properties | has("probe_status") | not) and
  (.properties | has("discovered_via") | not)
))
and ([.graph.nodes[] | select(.kinds | index("Credential"))] | length) == 1
and (.graph.nodes | any(
  (.kinds | index("Credential")) and
  .properties.name == "upstream-openai-0" and
  .properties.provider_endpoint == "http://litellm:4000/v1" and
  .properties.value_hash == "e3361aa8c1da8e9a7fe5828991ff97ea3b3d08a8adb60b95b80cf7b4331a2230" and
  (has("value") | not)
))
and ([.graph.edges[] | select(.kind == "EXPOSES_CREDENTIAL")] | length) == 1
