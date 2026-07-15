(.graph.nodes | any(.kinds | index("MLflowServer")))
and
(.graph.nodes | any(.kinds | index("MCPResource")))
and
(.graph.edges | any(.kind == "PROVIDES_RESOURCE"))
and
((.meta.collection.state == "complete") or (.meta.collection.state == "partial"))
