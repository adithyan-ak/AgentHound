(.graph.nodes | any(.kinds | index("LiteLLMGateway")))
and
(.graph.nodes | map(select(.kinds | index("Credential"))) | length) >= 2
and
(.graph.nodes | any(
  (.kinds | index("Credential"))
  and (.properties.type == "master_key")
  and (.properties.merge_key == "value_hash")
  and (.properties.value_hash | type == "string")
  and (.properties.value_hash | test("^[0-9a-f]{64}$"))
))
and
(.graph.edges | any(.kind == "EXPOSES_CREDENTIAL"))
and
((.meta.collection.state == "complete") or (.meta.collection.state == "partial"))
