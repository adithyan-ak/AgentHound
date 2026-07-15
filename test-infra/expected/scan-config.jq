(.graph.nodes | any(.kinds | index("MCPServer")))
and
(.graph.nodes | any(.kinds | index("InstructionFile")))
and
(.graph.nodes | any(.kinds | index("ConfigFile")))
and
(.meta.collection.state == "complete")
