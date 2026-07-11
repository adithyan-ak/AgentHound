# CAN_EXFILTRATE_VIA

**Type:** Composite (post-processor generated)  
**Direction:** `AgentInstance → MCPTool`  
**Depends on:** CAN_REACH  
**Severity:** Critical  
**OWASP:** MCP04 (Tool Misuse), ASI03 (Data Exfiltration)

## What it means

An agent can reach sensitive data (via CAN_REACH to a high-sensitivity MCPResource) AND has access to a tool with an outbound-exfiltration capability (`email_send`, `network_outbound`, `file_write`, `auto_fetch_render`, or `allowlisted_proxy`). The combination means the agent can read secrets and send them out — directly (network, email), by writing them to a file another actor can pull, by triggering a link fetch that leaks them in the URL, or by tunnelling through a proxy the agent already trusts.

## How it's computed

The `can_exfiltrate` post-processor runs after CAN_REACH and checks:

1. Does the agent have a CAN_REACH path to a resource with `sensitivity` in {critical, high}?
2. Does the same agent (via TRUSTS_SERVER → PROVIDES_TOOL) have access to a tool whose `capability_surface` intersects `{email_send, network_outbound, file_write, auto_fetch_render, allowlisted_proxy}`?

If both conditions hold, emit: `(agent)-[:CAN_EXFILTRATE_VIA]->(tool)`

## Cypher example

```cypher
MATCH (a:AgentInstance)-[:CAN_EXFILTRATE_VIA]->(t:MCPTool)
WHERE ANY(cap IN t.capability_surface WHERE cap IN
  ['email_send', 'network_outbound', 'file_write', 'auto_fetch_render', 'allowlisted_proxy'])
RETURN a.name AS agent, t.name AS exfil_tool,
       t.capability_surface AS capabilities
ORDER BY a.name
```

## What an operator does with it

This is the "game over" edge — the agent can steal data autonomously. Prioritize:
1. Remove the outbound tool from the agent's trusted servers
2. If the tool must stay, restrict its scope (input validation, allowlisted destinations)
3. Monitor: any invocation of the exfil tool by this agent is an incident

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `confidence` | float | Fixed `0.8`. |
| `risk_weight` | float | Fixed `0.1` (high exploitability — attacker prefers this edge). |
| `sensitive_resource` | string | `uri` of the reachable resource that triggered the match. |
| `resource_sensitivity` | string | Sensitivity bucket of that resource (`critical` or `high`). |
| `is_composite` | bool | `true`. |
| `source_collector` | string | `mcp`. |
| `scan_id`, `last_seen` | string | Standard edge provenance. |
