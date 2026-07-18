.meta.collection.state == "complete"
and (.meta.extra.partial_errors | length) == 0
and (.graph.nodes | any(
  (.kinds | index("MLflowServer")) and
  .properties.endpoint == "http://mlflow:5000" and
  .properties.experiment_count == 2 and
  .properties.total_runs == 1 and
  .properties.registered_model_count == 1 and
  .properties.registered_models == ["agenthound-fixture-model"] and
  .properties.model_version_count == 1
))
and ([.graph.nodes[] | select(.kinds | index("MCPResource")) | .properties.name])
  == ["agenthound-fixture-model:1"]
and ([.graph.edges[] | select(.kind == "PROVIDES_RESOURCE")] | length) == 1
