.meta.collection.state == "complete"
and (.meta.extra.partial_errors | length) == 0
and ([.graph.nodes[] | select(.kinds | index("LiteLLMGateway"))] | length) == 1
and ([.graph.nodes[] | select(.kinds | index("Credential"))] | length) == 4
and ([.graph.nodes[] | select(.kinds | index("Credential")) | .properties.type] | sort)
  == (["apiKey","apiKey","master_key","virtual_key"] | sort)
and (.graph.nodes | any(
  (.kinds | index("Credential")) and
  .properties.type == "master_key" and
  .properties.value_hash == "18d8fb72d7e03d68e47afbf4e571b96829f265d3dbb86c558f018eb6de3fd10f" and
  .properties.merge_key == "value_hash" and
  (has("value") | not)
))
and ([.graph.nodes[] | select(
  (.kinds | index("Credential")) and .properties.type == "apiKey"
) | .properties.merge_key] | unique) == ["identity"]
and ([.graph.edges[] | select(.kind == "EXPOSES_CREDENTIAL")] | length) == 4
