.meta.collection.state == "complete"
and ([.graph.nodes[] | select(.kinds | index("MCPServer"))] | length) == 2
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  .properties.command == "/usr/local/bin/mcp-server-everything" and
  .properties.arg_count == 3 and
  .properties.arg_hashes == [
    "sha256:342f9b6c4dabc590c516e5638f81b375bbade098820d303b2a230f569b98b245",
    "sha256:bd8eaffdde2f965204bc8812a3091470fd8be91f57661579a8f76aeb27ae8487",
    "sha256:bba059dd0b1eeb66a3d8705c6cae4858b5f7f184724a0a3ad04566240bcc4cae"
  ] and
  (.properties | has("args") | not) and
  (.properties | has("endpoint") | not)
))
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  .properties.endpoint == "http://mcp-streamable:3001/mcp" and
  .properties.endpoint_userinfo_redacted == true and
  .properties.endpoint_query_redacted == true and
  .properties.endpoint_fragment_redacted == true
))
and ([
  .graph.nodes[]
  | select(.kinds | index("Credential"))
  | .properties.value_hash
] | contains([
  "dedf77915f1b29091ae7bbf5f1becbd2414a96feaf9c48e0d044947112158198",
  "6f1b26e03a049facd13689d2273d6ef6fd0b1c339c9506fb44b130810af1eba0",
  "9d3f3ee4788e5f48854af36eae6531969b601ca25979a3bcd35ad350736b69f0",
  "b8a8f4f722f431168c837a0aa2b2d3c3bb6bf02f4e9e9e26a893e0b29f8f3442"
]))
and ([.graph.edges[] | select(.kind == "HAS_ENV_VAR")] | length) == 0
