(.graph.nodes | any(.kinds | index("JupyterServer")))
and
(.graph.nodes | any(
  (.kinds | index("MCPResource"))
  and ((.properties.uri // .properties.name // "") | tostring | test("agenthound-fixture\\.ipynb"))
))
and
(.graph.edges | any(.kind == "PROVIDES_RESOURCE"))
and
((.meta.collection.state == "complete") or (.meta.collection.state == "partial"))
