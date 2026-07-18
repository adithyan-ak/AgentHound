.meta.collection.state == "complete"
and (.meta.extra.partial_errors | length) == 0
and ([.graph.nodes[] | select(.kinds | index("OllamaInstance")) | .properties.endpoint])
  == ["http://ollama:11434"]
and ([.graph.nodes[] | select(.kinds | index("OllamaInstance")) | .properties.embedding_capability_confirmed])
  == [true]
and ([.graph.nodes[] | select(.kinds | index("AIModel")) | .properties.name])
  == ["qwen2:0.5b"]
and ([.graph.edges[] | select(.kind == "PROVIDES_MODEL")] | length) == 1
and ([.graph.nodes[] | select(has("properties")) | .properties | select(has("modelfile") or has("value"))] | length) == 0
