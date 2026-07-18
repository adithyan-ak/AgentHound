.meta.collection.state == "complete"
and ([.graph.nodes[] | select(.kinds | index("ConfigFile")) | .properties.client])
  == ["claude-desktop"]
and ([.graph.nodes[] | select(.kinds | index("ConfigFile")) | .properties.path]
  | length) == 1
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  .properties.command == "npx" and
  .properties.args == ["--yes","@modelcontextprotocol/server-everything@2026.7.4","stdio"] and
  .properties.pinning_status == "pinned"
))
