(.graph.nodes | any(.kinds | index("OpenWebUIInstance")))
and
(.graph.nodes | any(
  (.kinds | index("OpenWebUIInstance"))
  and (.properties.probe_status == "verified")
))
and
((.meta.collection.state == "complete") or (.meta.collection.state == "partial"))
