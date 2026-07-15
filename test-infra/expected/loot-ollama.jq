(.graph.nodes | any(.kinds | index("OllamaInstance")))
and
(.graph.nodes | any(.kinds | index("AIModel")))
and
(.graph.edges | any(.kind == "PROVIDES_MODEL"))
and
((.meta.collection.state == "complete") or (.meta.collection.state == "partial"))
