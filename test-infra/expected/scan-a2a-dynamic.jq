(.graph.nodes | any(
  (.kinds | index("A2AAgent"))
  and (.properties.name == "ClaimsTriageAgent")
))
and
(.meta.collection.state == "complete")
