(.graph.nodes | any(.kinds | index("OllamaInstance")))
and
(.graph.nodes | any(.kinds | index("VLLMInstance")))
and
(.graph.nodes | any(.kinds | index("LangServeApp")))
and
(.graph.nodes | any(.kinds | index("QdrantInstance")))
and
(.graph.nodes | any(.kinds | index("MLflowServer")))
and
(.graph.nodes | any(.kinds | index("LiteLLMGateway")))
and
(.graph.nodes | any(.kinds | index("JupyterServer")))
and
(.graph.nodes | any(.kinds | index("OpenWebUIInstance")))
and
(.meta.collection.state == "complete")
