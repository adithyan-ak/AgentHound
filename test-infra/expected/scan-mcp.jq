.meta.collection.state == "complete"
and ([.meta.collection.outcomes[].state] | unique) == ["complete"]
and ([.graph.nodes[] | select(.kinds | index("MCPServer")) | .properties.name]
  == ["mcp-servers/everything"])
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
and ([.graph.nodes[] | select(.kinds | index("MCPPrompt")) | .properties.name] | sort)
  == (["args-prompt","completable-prompt","resource-prompt","simple-prompt"] | sort)
and ([.graph.edges[] | select(.kind == "PROVIDES_TOOL")] | length) == 14
and ([.graph.edges[] | select(.kind == "PROVIDES_RESOURCE")] | length) == 9
and ([.graph.edges[] | select(.kind == "PROVIDES_PROMPT")] | length) == 4
