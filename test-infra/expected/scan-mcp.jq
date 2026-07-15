(.graph.nodes | map(select(.kinds | index("MCPServer"))) | length) == 1
and
(.graph.nodes | any(.properties.name == "mcp-target-admin"))
and
(.graph.nodes | map(select(.kinds | index("MCPTool"))) | length) >= 5
and
(.graph.nodes | any(.kinds | index("MCPResource")))
and
(.graph.edges | any(.kind == "PROVIDES_TOOL"))
and
(.meta.collection.state == "complete")
