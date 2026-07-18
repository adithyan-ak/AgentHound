.meta.collection.state == "complete"
and ([.meta.collection.outcomes[] | select(.state != "complete")] | length) == 0
and ([.graph.nodes[] | select(.kinds | index("MCPServer")) | .properties.transport] | unique | sort)
  == ["http","stdio"]
and ([.graph.nodes[] | select(.kinds | index("MCPServer")) | .properties.endpoint] | unique | length) == 4
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  .properties.endpoint == "/usr/local/bin/mcp-server-everything"
))
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  .properties.endpoint == "http://mcp-streamable:3001/mcp"
))
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  .properties.endpoint == "http://mcp-sse:3001/sse"
))
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  (.properties.endpoint | test("^http://contextforge:4444/servers/[0-9a-f-]+/mcp$"))
))
and ([.graph.nodes[] | select(.kinds | index("MCPTool"))] | length) == 43
and ([.graph.nodes[] | select(.kinds | index("MCPResource"))] | length) == 28
and ([.graph.nodes[] | select(.kinds | index("MCPPrompt"))] | length) == 12
and ([.graph.nodes[] | select(.kinds | index("MCPTool")) | .properties.name]
  | group_by(.) | map({name:.[0],count:length}) | sort_by(.name))
  == ([
    {name:"echo",count:3},
    {name:"get-annotated-message",count:3},
    {name:"get-env",count:3},
    {name:"get-resource-links",count:3},
    {name:"get-resource-reference",count:3},
    {name:"get-roots-list",count:3},
    {name:"get-structured-content",count:3},
    {name:"get-sum",count:3},
    {name:"get-tiny-image",count:3},
    {name:"gzip-file-as-resource",count:3},
    {name:"simulate-research-query",count:3},
    {name:"support-lookup",count:1},
    {name:"toggle-simulated-logging",count:3},
    {name:"toggle-subscriber-updates",count:3},
    {name:"trigger-long-running-operation",count:3}
  ] | sort_by(.name))
and ([.graph.edges[] | select(.kind == "PROVIDES_TOOL")] | length) == 43
and ([.graph.edges[] | select(.kind == "PROVIDES_RESOURCE")] | length) == 28
and ([.graph.edges[] | select(.kind == "PROVIDES_PROMPT")] | length) == 12
