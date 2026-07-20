.meta.collection.state == "complete"
and ([.graph.nodes[] | select(.kinds | index("ConfigFile")) | .properties.client])
  == ["claude-desktop"]
and ([.graph.nodes[] | select(.kinds | index("ConfigFile")) | .properties.path]
  | length) == 1
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  .properties.command == "npx" and
  .properties.arg_count == 3 and
  .properties.arg_hashes == [
    "sha256:628791a90247f934c52bfb2d4b63a223581a47959deb206b6a51c75f7d4474e5",
    "sha256:650ddd3756346f9b9163e3a4279468546b1e8afcd4abcb54146bed8141873c70",
    "sha256:d5badea36b03778fde56dec07b4f21674bab535d716f0be1250f0ce6daf1b075"
  ] and
  (.properties | has("args") | not) and
  (.properties | has("endpoint") | not) and
  .properties.pinning_status == "pinned"
))
