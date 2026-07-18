.meta.collection.state == "complete"
and ([.graph.nodes[] | select(.kinds | index("ConfigFile")) | .properties.path] | sort)
  == ([
    "/root/.augment/settings.json",
    "/root/.aws/amazonq/default.json",
    "/root/.claude.json",
    "/root/.codeium/windsurf/mcp_config.json",
    "/root/.config/Code/User/mcp.json",
    "/root/.config/zed/settings.json",
    "/root/.continue/config.yaml",
    "/root/.cursor/mcp.json",
    "/root/.junie/mcp/mcp.json",
    "/root/.kiro/settings/mcp.json",
    "/root/projects/example/.amazonq/default.json",
    "/root/projects/example/.cline/mcp.json",
    "/root/projects/example/.cursor/mcp.json",
    "/root/projects/example/.junie/mcp/mcp.json",
    "/root/projects/example/.kiro/settings/mcp.json",
    "/root/projects/example/.mcp.json",
    "/root/projects/example/.vscode/mcp.json"
  ] | sort)
and ([.graph.nodes[] | select(.kinds | index("InstructionFile")) | .properties.path] | sort)
  == ([
    "/root/.claude/CLAUDE.md",
    "/root/projects/example/.cursor/rules/agenthound-harness.mdc",
    "/root/projects/example/.github/copilot-instructions.md",
    "/root/projects/example/AGENTS.md",
    "/root/projects/example/CLAUDE.md"
  ] | sort)
and ([.graph.nodes[] | select(.kinds | index("MCPServer")) | .properties.endpoint] | unique | length) == 4
and ([.graph.nodes[] | select(.kinds | index("MCPServer")) | .properties.endpoint]
  | index("/usr/local/bin/mcp-server-everything") != null)
and ([.graph.nodes[] | select(.kinds | index("MCPServer")) | .properties.endpoint]
  | index("http://mcp-sse:3001/sse") != null)
and ([.graph.nodes[] | select(.kinds | index("MCPServer")) | .properties.endpoint]
  | index("http://mcp-streamable:3001/mcp") != null)
and (.graph.nodes | any(
  (.kinds | index("MCPServer")) and
  (.properties.endpoint | test("^http://contextforge:4444/servers/[0-9a-f-]+/mcp$"))
))
and (.graph.nodes | any(
  (.kinds | index("Credential")) and
  .properties.merge_key == "value_hash" and
  (.properties.value_hash | test("^[0-9a-f]{64}$")) and
  (has("value") | not)
))
and ([.graph.nodes[] | select(.kinds | index("Credential"))] | length) == 1
and ([.graph.edges[] | select(.kind == "CONFIGURED_IN")] | length) == 19
