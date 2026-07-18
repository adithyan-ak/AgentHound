.meta.collection.state == "complete"
and (.meta.extra.partial_errors | length) == 0
and (.graph.nodes | any(
  (.kinds | index("JupyterServer")) and
  .properties.endpoint == "http://jupyter:8888" and
  .properties.auth_required == true and
  .properties.auth_evidence == "configured_credential"
))
and ([.graph.nodes[] | select(.kinds | index("MCPResource")) | .properties.name] | sort)
  == ["agenthound-fixture.ipynb","support-context.md"]
and ([.graph.edges[] | select(.kind == "PROVIDES_RESOURCE")] | length) == 2
