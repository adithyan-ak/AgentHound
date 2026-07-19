.meta.collection.state == "complete"
and ([.graph.nodes[] | select(.kinds | index("AIService"))] | length) == 9
and ([.graph.nodes[] | select(.kinds | index("OllamaInstance")) | .properties.endpoint])
  == ["http://10.20.30.10:11434"]
and ([.graph.nodes[] | select(.kinds | index("VLLMInstance")) | .properties.endpoint])
  == ["http://10.20.30.11:8000"]
and ([.graph.nodes[] | select(.kinds | index("LangServeApp")) | .properties.endpoint])
  == ["http://10.20.30.12:8000"]
and ([.graph.nodes[] | select(.kinds | index("QdrantInstance")) | .properties.endpoint])
  == ["http://10.20.30.13:6333"]
and ([.graph.nodes[] | select(.kinds | index("MLflowServer")) | .properties.endpoint])
  == ["http://10.20.30.14:5000"]
and ([.graph.nodes[] | select(.kinds | index("LiteLLMGateway")) | .properties.endpoint] | sort)
  == ["http://10.20.30.15:4000","http://10.20.30.18:8000"]
and ([.graph.nodes[] | select(.kinds | index("JupyterServer")) | .properties.endpoint])
  == ["http://10.20.30.16:8888"]
and ([.graph.nodes[] | select(.kinds | index("OpenWebUIInstance")) | .properties.endpoint])
  == ["http://10.20.30.17:3000"]
and ([.graph.nodes[] | select(
  (.kinds | index("VLLMInstance")) and
  .properties.endpoint == "http://10.20.30.18:8000"
)] | length) == 0
