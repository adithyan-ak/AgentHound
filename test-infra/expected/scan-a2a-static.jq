(.graph.nodes | any(
  (.kinds | index("A2AAgent"))
  and (.properties.name == "PayrollAgent")
))
and
(.graph.nodes | any(.properties.signature_verification_status == "verified"))
and
(.graph.edges | any(.kind == "ADVERTISES_SKILL"))
and
(.meta.collection.state == "complete")
