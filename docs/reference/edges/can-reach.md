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

The `can_reach` post-processor runs after `auth_strength` and `has_access_to`
and produces two variants:

### Direct Path (3 hops)

```cypher
MATCH (a:AgentInstance)-[ts:TRUSTS_SERVER]->(s:MCPServer)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
MERGE (a)-[e:CAN_REACH]->(r)
SET e.hops = 3,
    e.via_server = s.name,
    e.via_tool = t.name,
    e.confidence = CASE WHEN ts.effective_risk_weight <= 0.1 THEN 1.0
                        WHEN ts.effective_risk_weight <= 0.3 THEN 0.8
                        ELSE 0.5 END
```

Confidence decreases as the trust edge auth strengthens — a server behind mTLS is harder to abuse than one with no auth.

### Credential Chain (6 hops)

```cypher
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s1:MCPServer)-[:PROVIDES_TOOL]->(t1:MCPTool)
WHERE ANY(cap IN t1.capability_surface WHERE cap IN ['file_read', 'credential_access'])
MATCH (s2:MCPServer)-[:AUTHENTICATES_WITH]->(i:Identity)-[:USES_CREDENTIAL]->(c:Credential)
MATCH (s2)-[:PROVIDES_TOOL]->(t2:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE s1 <> s2
  AND (
    (s1.effective_auth_assurance = 'unauthenticated'
      AND s1.effective_auth_source = 'observed')
    OR s1.effective_auth_assurance = 'weak'
  )
  AND c.value_hash IS NOT NULL AND c.value_hash <> ''
  AND c.merge_key = 'value_hash'
  AND c.identity_basis = 'value_hash'
  AND c.material_status = 'observed'
  AND c.exposure_status = 'exposed'
```

This variant models: "agent has a tool that can read credentials, and observed,
exposed credential material authenticates to a second server with access to
additional resources." The canonical identity topology applies to every config
location; `HAS_ENV_VAR` is only optional location evidence and is not required.
An unauthenticated first server is eligible only when its effective auth source
is an accepted runtime observation. Configured weak authentication remains
eligible, while a configured no-auth claim without runtime proof does not.
Fixed confidence: 0.6.

---

## Cross-Protocol Variant

The `cross_protocol` post-processor emits a separate `CAN_REACH` edge with `cross_protocol = true`:

```cypher
MATCH (ext:A2AAgent)-[:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[:RUNS_ON]->(h:Host)<-[:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE ext.effective_auth_assurance = 'unauthenticated'
  AND ext.effective_auth_source = 'observed'
  AND ext.effective_auth_evidence = 'anonymous_probe_succeeded'
```

This models a runtime-confirmed anonymous A2A agent delegating through a chain
that lands on the same host as an MCP server — host correlation bridges the
protocol boundary. A missing auth tuple or configured no-auth claim alone does
not satisfy the correlation. This is the path class that no single-protocol
scanner can find.

---

## Edge Properties

| Property | Type | Description |
|----------|------|-------------|
| `scan_id` | string | Scan that created this edge |
| `last_seen` | datetime | Timestamp of last computation |
| `is_composite` | bool | Always `true` |
| `source_collector` | string | Detector provenance: `mcp`, `a2a`, or a processor-owned source such as `cross_service_credential_chain` |
| `hops` | int | Path length: 3 (direct) or 6 (credential chain) |
| `via_server` | string | MCP server name in the path |
| `via_tool` | string | Tool name in the path |
| `via_credential` | string | Credential name (chain variant only) |
| `cross_protocol` | bool | True for A2A-to-MCP paths |
| `confidence` | float | 0.5-1.0 based on auth strength |
| `risk_weight` | float | 0.1 (constant, used by weighted traversal) |

---

## Operator Guidance

1. Sort CAN_REACH findings by target resource sensitivity (critical > high > medium).
2. Prioritize paths where the agent's trust edge has
   `effective_risk_weight <= 0.1` (runtime-confirmed no auth).
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
