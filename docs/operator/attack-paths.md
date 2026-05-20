# Attack Path Analysis

AgentHound's core contribution is surfacing attack paths that span protocol boundaries -- paths no single-protocol scanner can see. The graph combines MCP trust relationships, A2A delegation chains, network-discovered AI services, and looted credentials into a unified directed graph where Cypher queries reveal multi-hop exploitation routes.

## 1. Credential chains via value_hash

The `value_hash` property on `Credential` nodes is the cross-collector merge primitive. When two collectors independently discover the same secret value, they emit `Credential` nodes with identical `value_hash` (SHA-256 of the raw value). The `cross_service_credential_chain` post-processor joins these into transitive access paths.

### How it works

1. **Config Collector** parses an MCP client config and finds `LITELLM_MASTER_KEY=sk-...` as an env var on an MCPServer. Emits:
   ```
   (:MCPServer)-[:HAS_ENV_VAR]->(:Credential {type: "envVar", value_hash: H1})
   ```

2. **LiteLLM Looter** authenticates with the same master key and discovers upstream provider keys. Emits:
   ```
   (:LiteLLMGateway)-[:EXPOSES_CREDENTIAL]->(:Credential {type: "master_key", value_hash: H1})
   (:LiteLLMGateway)-[:EXPOSES_CREDENTIAL]->(:Credential {type: "apiKey", provider: "openai", value_hash: H2})
   (:LiteLLMGateway)-[:EXPOSES_CREDENTIAL]->(:Credential {type: "apiKey", provider: "anthropic", value_hash: H3})
   ```

3. **Post-processor** matches `H1 == H1` across collectors, then walks the full path:
   ```
   (:AgentInstance)-[:TRUSTS_SERVER]->(:MCPServer)-[:HAS_ENV_VAR]->(c1)-[value_hash join]->
   (:LiteLLMGateway)-[:EXPOSES_CREDENTIAL]->(upstream_cred)
   ```
   Emits: `(:AgentInstance)-[:CAN_REACH {type: "credential_chain"}]->(upstream_cred)`

### Query: surface all credential chains

```cypher
MATCH path = (a:AgentInstance)-[:CAN_REACH {evidence_type: "credential_chain"}]->(c:Credential)
WHERE c.type = 'apiKey'
RETURN a.name AS agent, c.provider AS provider, c.value_hash AS hash,
       length(path) AS hops
ORDER BY hops ASC
```

### Pre-built query

```bash
agenthound-server query --prebuilt credential-chain
```

## 2. Cross-protocol CAN_REACH (A2A to MCP)

When an A2A agent delegates to another agent that runs on the same host as an MCP server, the graph reveals transitive access from the A2A protocol boundary into MCP resources -- a path invisible to tools that only analyze one protocol.

### How it works

1. A2A Collector emits: `(:A2AAgent)-[:DELEGATES_TO]->(:A2AAgent)-[:RUNS_ON]->(:Host)`
2. Config/MCP Collector emits: `(:MCPServer)-[:RUNS_ON]->(:Host)` and `(:MCPServer)-[:PROVIDES_TOOL]->(:MCPTool)-[:HAS_ACCESS_TO]->(:MCPResource)`
3. The `cross_protocol` post-processor correlates via shared Host nodes and emits:
   ```
   (:A2AAgent)-[:CAN_REACH {type: "cross_protocol"}]->(:MCPResource)
   ```

### Query: all cross-protocol paths

```cypher
MATCH path = (a:A2AAgent)-[:DELEGATES_TO*1..3]->(delegate:A2AAgent)-[:RUNS_ON]->(h:Host)<-[:RUNS_ON]-(s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
RETURN a.name AS source_agent, delegate.name AS pivot_agent,
       h.hostname AS shared_host, s.name AS mcp_server,
       t.name AS tool, r.uri AS resource
```

### Pre-built query

```bash
agenthound-server query --prebuilt cross-protocol-paths
```

## 3. Tool poisoning paths

Two post-processors detect tool-level manipulation that can redirect agent behavior:

### SHADOWS

A tool on Server B references Server A's tool by name or description fragment, enabling tool confusion attacks where an agent calls the shadow instead of the original.

```cypher
MATCH (shadow:MCPTool)-[:SHADOWS]->(original:MCPTool)
MATCH (shadow)<-[:PROVIDES_TOOL]-(shadow_server:MCPServer)
MATCH (original)<-[:PROVIDES_TOOL]-(original_server:MCPServer)
WHERE shadow_server <> original_server
RETURN shadow.name AS shadow_tool, shadow_server.name AS shadow_on,
       original.name AS original_tool, original_server.name AS original_on
```

### POISONED_DESCRIPTION

A tool's description contains injection patterns (imperative overrides, exfiltration URLs, instruction hijacking). Self-referencing edge on the MCPTool node.

```cypher
MATCH (t:MCPTool)-[p:POISONED_DESCRIPTION]->(t)
MATCH (t)<-[:PROVIDES_TOOL]-(s:MCPServer)<-[:TRUSTS_SERVER]-(a:AgentInstance)
RETURN a.name AS exposed_agent, s.name AS server, t.name AS tool,
       p.evidence AS injection_evidence
```

### Pre-built queries

```bash
agenthound-server query --prebuilt tool-shadowing
agenthound-server query --prebuilt poisoned-tools
```

## 4. Exfiltration routes (CAN_EXFILTRATE_VIA)

The `CAN_EXFILTRATE_VIA` edge connects an agent to a tool that provides BOTH access to sensitive data (via `CAN_REACH` to a sensitive resource) AND an outbound channel (network_outbound or email_send capability).

### How it works

1. `CAN_REACH` post-processor establishes agent-to-resource reachability
2. Tool capability classification identifies outbound channels (`capability_surface` includes `network_outbound` or `email_send`)
3. Post-processor joins: agent can reach sensitive data AND has a tool to send it somewhere

### Query: all exfiltration routes

```cypher
MATCH (a:AgentInstance)-[e:CAN_EXFILTRATE_VIA]->(t:MCPTool)
MATCH (a)-[:CAN_REACH]->(r:MCPResource)
WHERE r.sensitivity IN ['critical', 'high']
RETURN a.name AS agent, t.name AS exfil_tool,
       collect(r.uri) AS sensitive_resources,
       t.capability_surface AS capabilities
ORDER BY size(collect(r.uri)) DESC
```

### Pre-built query

```bash
agenthound-server query --prebuilt exfiltration-routes
```

## Combining findings

The real power is in composition. An operator running the full chain (config scan + network scan + discover + loot + ingest) gets all four attack-path types computed automatically by the post-processor pipeline. The Findings API returns them ranked by severity:

```bash
# All critical and high findings
agenthound-server query --findings --severity critical,high

# Specific finding detail with full path
curl -s localhost:8080/api/v1/analysis/findings | \
    jq '.[] | select(.processor == "cross_service_credential_chain")'
```

The UI's Findings panel renders each path as an interactive graph with the attack narrative annotated on edges. The Graph Explorer allows click-through from any node to its blast radius (N-hop reachable subgraph).

## Post-processor execution order

Attack-path edges depend on lower-level edges being computed first:

1. HAS_ACCESS_TO
2. CAN_EXECUTE
3. SHADOWS
4. POISONED_DESCRIPTION
5. POISONED_INSTRUCTIONS
6. CAN_REACH (depends on 1)
7. cross_service_credential_chain (depends on 1, 6)
8. CAN_EXFILTRATE_VIA (depends on 6)
9. CAN_IMPERSONATE
10. Cross-protocol CAN_REACH (depends on 1)
11. RiskScore (depends on all above)

Each post-processor is idempotent. Re-ingesting the same scan re-runs the pipeline and updates composite edges in place (MERGE by source+target+kind).
