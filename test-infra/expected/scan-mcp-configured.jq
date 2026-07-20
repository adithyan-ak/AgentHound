.meta.collection.state == "complete"
and ([.meta.collection.outcomes[] | select(.state != "complete")] | length) == 0
and ([.graph.nodes[] | select(.kinds | index("MCPServer")) | .properties.transport] | unique | sort)
  == ["http","stdio"]
and ([.graph.nodes[] | select(
  (.kinds | index("MCPServer")) and .properties.transport == "http"
) | .properties.endpoint] | unique | length) == 4
and ([.graph.nodes[] | select(
  (.kinds | index("MCPServer")) and
  (.properties.command == "/usr/local/bin/mcp-server-everything" or
   .properties.endpoint == "http://mcp-streamable:3001/mcp" or
   .properties.endpoint == "http://mcp-sse:3001/sse" or
   .properties.endpoint == "http://mcp-cross-service-gate:3003/mcp")
)] | all(
  .properties.has_tasks_capability == true and
  (.properties.capabilities | index("tasks")) != null
))
and ([.graph.nodes[] | select(
  (.kinds | index("MCPServer")) and
  .properties.transport == "http" and
  (.properties.endpoint | test("^http://contextforge:4444/servers/[0-9a-f-]+/mcp$"))
)] | all(
  .properties.has_tasks_capability == false and
  (.properties.capabilities | index("tasks")) == null
))
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  .properties.transport == "stdio" and
  .properties.command == "/usr/local/bin/mcp-server-everything" and
  (.properties | has("endpoint") | not)
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
  .properties.endpoint == "http://mcp-cross-service-gate:3003/mcp"
))
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  .properties.transport == "http" and
  (.properties.endpoint | test("^http://contextforge:4444/servers/[0-9a-f-]+/mcp$"))
))
and ([.graph.nodes[] | select(.kinds | index("MCPTool"))] | length) == 57
and ([.graph.nodes[] | select(.kinds | index("MCPResource"))] | length) == 37
and ([.graph.nodes[] | select(.kinds | index("MCPResource"))] | all(
  .properties | has("size") | not
))
and ([.graph.nodes[] | select(.kinds | index("MCPPrompt"))] | length) == 16
and ([.graph.nodes[] | select(.kinds | index("MCPTool")) | .properties.name]
  | group_by(.) | map({name:.[0],count:length}) | sort_by(.name))
  == ([
    {name:"echo",count:4},
    {name:"get-annotated-message",count:4},
    {name:"get-env",count:4},
    {name:"get-resource-links",count:4},
    {name:"get-resource-reference",count:4},
    {name:"get-roots-list",count:4},
    {name:"get-structured-content",count:4},
    {name:"get-sum",count:4},
    {name:"get-tiny-image",count:4},
    {name:"gzip-file-as-resource",count:4},
    {name:"simulate-research-query",count:4},
    {name:"support-lookup",count:1},
    {name:"toggle-simulated-logging",count:4},
    {name:"toggle-subscriber-updates",count:4},
    {name:"trigger-long-running-operation",count:4}
  ] | sort_by(.name))
and ([.graph.edges[] | select(.kind == "PROVIDES_TOOL")] | length) == 57
and ([.graph.edges[] | select(.kind == "PROVIDES_RESOURCE")] | length) == 37
and ([.graph.edges[] | select(.kind == "PROVIDES_PROMPT")] | length) == 16
