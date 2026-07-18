.meta.collection.state == "complete"
and .meta.collection.outcomes == [{
  collector:"scan",
  coverage_key:.meta.collection.outcomes[0].coverage_key,
  target:"10.20.30.0/24",
  method:"protocol_discovery",
  state:"complete",
  items:3
}]
and ([.graph.nodes[] | select(.kinds | index("MCPServer")) | .properties.endpoint])
  == ["http://10.20.30.20:3001/mcp"]
and ([.graph.nodes[] | select(.kinds | index("A2AAgent")) | .properties.agent_card_url] | sort)
  == ([
    "http://10.20.30.21:80/.well-known/agent-card.json",
    "http://10.20.30.22:9000/.well-known/agent-card.json"
  ] | sort)
and ([.graph.nodes[]] | length) == 3
