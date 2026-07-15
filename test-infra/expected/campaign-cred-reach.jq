(.graph.edges | any(.kind == "CREDENTIAL_REACH_VERIFIED"))
and
(.graph.nodes | any(.kinds | index("AgentInstance")))
and
(.graph.nodes | any(.kinds | index("MCPResource")))
and
(.meta.collection.state == "complete")
