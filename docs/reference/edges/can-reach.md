# CAN_REACH Edge

The `CAN_REACH` composite edge is AgentHound's primary finding: it proves that an agent (or external A2A caller) can transitively access a resource through the trust graph. This is the edge operators triage first.

---

## Semantics

```
(AgentInstance)-[:CAN_REACH]->(MCPResource)
```

Meaning: the source agent has a viable path through trusted servers and their tools to reach the target resource. The agent does not need direct configuration for that resource — the path may traverse credential chains, multiple servers, or even cross-protocol boundaries.

---

## Computation

The `can_reach` post-processor runs after `has_access_to` (its only dependency) and produces two variants:

### Direct Path (3 hops)

```cypher
MATCH (a:AgentInstance)-[ts:TRUSTS_SERVER]->(s:MCPServer)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE NOT EXISTS((a)-[:CAN_REACH]->(r))
MERGE (a)-[e:CAN_REACH]->(r)
SET e.hops = 3,
    e.via_server = s.name,
    e.via_tool = t.name,
    e.confidence = CASE WHEN ts.risk_weight <= 0.1 THEN 1.0
                        WHEN ts.risk_weight <= 0.3 THEN 0.8
                        ELSE 0.5 END
```

Confidence decreases as the trust edge auth strengthens — a server behind mTLS is harder to abuse than one with no auth.

### Credential Chain (6 hops)

```cypher
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s1:MCPServer)-[:PROVIDES_TOOL]->(t1:MCPTool)
WHERE ANY(cap IN t1.capability_surface WHERE cap IN ['file_read', 'credential_access'])
MATCH (s2:MCPServer)-[:HAS_ENV_VAR]->(c:Credential)
MATCH (c)<-[:USES_CREDENTIAL]-(i:Identity)<-[:AUTHENTICATES_WITH]-(s2)
MATCH (s2)-[:PROVIDES_TOOL]->(t2:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE s1 <> s2
      AND (s1.auth_method IS NULL OR s1.auth_method IN ['none', 'apiKey'])
```

This variant models: "agent has a tool that can read credentials, and those credentials authenticate to a second server with access to additional resources." Fixed confidence: 0.6.

---

## Cross-Protocol Variant

The `cross_protocol` post-processor emits a separate `CAN_REACH` edge with `cross_protocol = true`:

```cypher
MATCH (ext:A2AAgent)-[:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[:RUNS_ON]->(h:Host)<-[:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE (ext.auth_method = 'none' OR ext.auth_method IS NULL)
```

This models an unauthenticated A2A agent delegating through a chain that lands on the same host as an MCP server — host correlation bridges the protocol boundary. This is the path class that no single-protocol scanner can find.

---

## Edge Properties

| Property | Type | Description |
|----------|------|-------------|
| `scan_id` | string | Scan that created this edge |
| `last_seen` | datetime | Timestamp of last computation |
| `is_composite` | bool | Always `true` |
| `source_collector` | string | `mcp` or `a2a` (scopes stale-edge cleanup) |
| `hops` | int | Path length: 3 (direct) or 6 (credential chain) |
| `via_server` | string | MCP server name in the path |
| `via_tool` | string | Tool name in the path |
| `via_credential` | string | Credential name (chain variant only) |
| `cross_protocol` | bool | True for A2A-to-MCP paths |
| `confidence` | float | 0.5-1.0 based on auth strength |
| `risk_weight` | float | 0.1 (constant, used by Dijkstra) |

---

## Operator Guidance

1. Sort CAN_REACH findings by target resource sensitivity (critical > high > medium).
2. Prioritize paths where the agent's trust edge has `risk_weight <= 0.1` (no auth).
3. Cross-protocol paths (`cross_protocol = true`) represent novel attack surface — review host co-location.
4. Credential chain paths indicate lateral movement potential — rotate exposed credentials.

---

## OWASP Mapping

| ID | Name |
|----|------|
| MCP04 | Tool Poisoning / Privilege Escalation |
| MCP09 | Improper Access Control |
| ASI02 | Excessive Agency |
| ASI05 | Improper Access Control |
