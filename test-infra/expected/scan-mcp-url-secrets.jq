.meta.collection.state == "complete"
and ([.meta.collection.outcomes[].state] | unique) == ["complete"]
and ([.meta.collection.outcomes[] | select(.collector == "mcp" and .target != "mcp") | .target] | unique)
  == ["http://mcp-credential-gate:3002/mcp"]
and ([.graph.nodes[] | select(.kinds | index("MCPServer"))] | length) == 1
and ([.graph.nodes[] | select(.kinds | index("MCPServer"))][0].properties | (
  .server_name == "mcp-servers/everything" and
  .endpoint == "http://mcp-credential-gate:3002/mcp" and
  .endpoint_userinfo_redacted == true and
  .endpoint_query_redacted == true and
  .endpoint_fragment_redacted == true and
  .auth_method == "basic" and
  .auth_evidence == "configured_credential" and
  .observed_auth_method == "basic" and
  .observed_auth_evidence == "configured_credential" and
  .has_tasks_capability == true and
  (.capabilities | index("tasks")) != null
))
and ([.graph.nodes[] | select(.kinds | index("MCPTool")) | .properties.name] | sort)
  == ([
    "echo",
    "get-annotated-message",
    "get-env",
    "get-resource-links",
    "get-resource-reference",
    "get-roots-list",
    "get-structured-content",
    "get-sum",
    "get-tiny-image",
    "gzip-file-as-resource",
    "simulate-research-query",
    "toggle-simulated-logging",
    "toggle-subscriber-updates",
    "trigger-long-running-operation"
  ] | sort)
and ([.graph.nodes[] | select(.kinds | index("MCPResource"))] | length) == 9
and ([.graph.nodes[] | select(.kinds | index("MCPResource"))] | all(
  .properties | has("size") | not
))
and ([.graph.nodes[] | select(.kinds | index("MCPPrompt")) | .properties.name] | sort)
  == (["args-prompt","completable-prompt","resource-prompt","simple-prompt"] | sort)
and ([.graph.edges[] | select(.kind == "PROVIDES_TOOL")] | length) == 14
and ([.graph.edges[] | select(.kind == "PROVIDES_RESOURCE")] | length) == 9
and ([.graph.edges[] | select(.kind == "PROVIDES_PROMPT")] | length) == 4
