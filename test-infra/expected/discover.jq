(.graph.nodes | any(.kinds | index("MCPServer")))
and
(.graph.nodes | any(.kinds | index("A2AAgent")))
and
(.meta.collection.state == "complete")
