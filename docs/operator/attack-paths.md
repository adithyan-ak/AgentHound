# Attack Path Analysis

Once the offensive lifecycle has collected configs, MCP/A2A enumeration, AI-service posture, looted credentials, and model artifacts, AgentHound's analysis layer turns those facts into attack paths. The graph combines MCP trust relationships, A2A delegation chains, network-discovered AI services, instruction files, untrusted-input signals, and credential reuse into one directed graph where composite edges and Cypher queries reveal multi-hop exploitation routes.

The canonical graph schema is in [Graph Model](../reference/graph-model.md). The canonical processor details and cleanup semantics are in [Post-Processors](../architecture/post-processors.md).

## Path Families

AgentHound computes 12 composite edge types. Operators usually reason about them in these path families:

| Family | Composite edges | What it answers |
|---|---|---|
| Reachability | `HAS_ACCESS_TO`, `CAN_REACH` | What can an agent, tool, or A2A boundary reach if trust edges are followed? |
| Credential chains | `CAN_REACH` with `via_credential` or `source_collector='cross_service_credential_chain'` | Where does credential reuse create implicit access? |
| Execution and exfiltration | `CAN_EXECUTE`, `CAN_EXFILTRATE_VIA` | Which paths lead to command/code execution or sensitive-data egress? |
| Poisoning and context manipulation | `SHADOWS`, `POISONED_DESCRIPTION`, `POISONED_INSTRUCTIONS`, `POISONS_CONTEXT` | Which tools or instruction files can steer model behavior? |
| Untrusted-input data flow | `TAINTS`, `IFC_VIOLATION` | Can attacker-controlled input flow into compatible tools or high-impact sinks? |
| A2A identity and delegation | `CAN_IMPERSONATE`, `CONFUSED_DEPUTY`, cross-protocol `CAN_REACH` | Can an A2A agent mimic, delegate into, or pivot across trust boundaries? |

Not every composite edge has a named pre-built query. Pre-built queries live under `agenthound-server query --prebuilt <id>`; composite-edge findings are always available through `agenthound-server query --findings` and `GET /api/v1/analysis/findings`.

## 1. Reachability (`HAS_ACCESS_TO`, `CAN_REACH`)

`HAS_ACCESS_TO` links tools to resources when capability surface and resource URI scheme line up, or when a tool description references a resource. `CAN_REACH` then folds agent trust into transitive access:

```text
(:AgentInstance)-[:TRUSTS_SERVER]->(:MCPServer)
  -[:PROVIDES_TOOL]->(:MCPTool)
  -[:HAS_ACCESS_TO]->(:MCPResource)
```

The `can_reach` processor emits:

```text
(:AgentInstance)-[:CAN_REACH {hops: 3, via_server, via_tool}]->(:MCPResource)
```

Credential-mediated reachability is also a `CAN_REACH` variant. If an agent can reach a tool that can read credentials, and another MCP server authenticates with one of those credentials, AgentHound emits a longer `CAN_REACH` path with `via_credential` and `hops: 6`.

### Pre-built queries

```bash
agenthound-server query --prebuilt credential-chain
agenthound-server query --prebuilt shortest-to-database
agenthound-server query --prebuilt agents-shell-access
```

## 2. Cross-Service Credential Chains (`value_hash`)

`Credential.value_hash` is the cross-collector merge primitive. Every collector and looter that emits a `Credential` must populate it with `SHA-256(raw credential value)`. When two independently discovered credentials share the same `value_hash`, AgentHound can prove that they represent the same secret without storing the raw value by default.

Example: a local MCP config exposes a LiteLLM master key, and the LiteLLM looter uses that same key to enumerate upstream provider keys.

```text
(:AgentInstance)-[:TRUSTS_SERVER]->(:MCPServer)
  -[:HAS_ENV_VAR]->(:Credential {value_hash: H1})

(:LiteLLMGateway)-[:EXPOSES_CREDENTIAL]->(:Credential {value_hash: H1})
(:LiteLLMGateway)-[:EXPOSES_CREDENTIAL]->(:Credential {type: "apiKey"})
```

The `cross_service_credential_chain` processor joins on `value_hash` and emits:

```text
(:AgentInstance)-[:CAN_REACH {
  source_collector: "cross_service_credential_chain",
  via_gateway,
  merge_value_hash,
  upstream_provider,
  hops: 5
}]->(:Credential)
```

It also records `blast_radius` on the emitted `CAN_REACH_CREDENTIAL_CHAIN` edge (not on the raw credential nodes, which are immutable prior observations): the number of distinct agents that can reach the merged secret.

### Pre-built query

```bash
agenthound-server query --prebuilt litellm-credential-leak
```

## 3. Cross-Protocol Pivots (`CAN_REACH`)

When an external A2A agent delegates to another A2A agent running on the same host as an MCP server, AgentHound can emit a cross-protocol `CAN_REACH` path from the A2A boundary into MCP resources.

```text
(:A2AAgent)-[:DELEGATES_TO*1..3]->(:A2AAgent)
  -[:RUNS_ON]->(:Host)<-[:RUNS_ON]-(:MCPServer)
  -[:PROVIDES_TOOL]->(:MCPTool)
  -[:HAS_ACCESS_TO]->(:MCPResource)
```

The emitted edge is:

```text
(:A2AAgent)-[:CAN_REACH {
  cross_protocol: true,
  source_collector: "a2a",
  via_host,
  via_mcp_server,
  via_mcp_tool
}]->(:MCPResource)
```

The current processor requires the external A2A agent to have no authentication (`auth_method IS NULL` or `auth_method = 'none'`).

### Pre-built query

```bash
agenthound-server query --prebuilt cross-protocol-paths
```

## 4. Execution and Exfiltration

`CAN_EXECUTE` links an MCP tool to its host when the tool has `shell_access` or `code_execution` in `capability_surface`.

```text
(:MCPTool)-[:CAN_EXECUTE]->(:Host)
```

`CAN_EXFILTRATE_VIA` links an agent to an outbound-capable tool when both conditions are true:

1. The agent can reach a `critical` or `high` sensitivity `MCPResource`.
2. The agent trusts a server with an outbound-capable tool.

Outbound-capable means the tool has one of:

```text
email_send, network_outbound, file_write, auto_fetch_render, allowlisted_proxy
```

### Pre-built query

```bash
agenthound-server query --prebuilt exfiltration-routes
```

## 5. Poisoning and Context Manipulation

AgentHound models both direct poisoning indicators and graph-level paths where poisoned context can influence high-impact tools.

### `SHADOWS`

A tool on one server references a tool on another server by name in its description. This can support tool-confusion attacks where the agent calls the shadowing tool instead of the intended capability.

```cypher
MATCH (shadow:MCPTool)-[r:SHADOWS]->(original:MCPTool)
MATCH (shadow)<-[:PROVIDES_TOOL]-(shadow_server:MCPServer)
MATCH (original)<-[:PROVIDES_TOOL]-(original_server:MCPServer)
WHERE shadow_server.objectid <> original_server.objectid
RETURN shadow.name AS shadowing_tool,
       shadow_server.name AS shadowing_server,
       original.name AS shadowed_tool,
       original_server.name AS shadowed_server,
       r.confidence AS confidence
ORDER BY r.confidence DESC
```

### `POISONED_DESCRIPTION`

A tool description contains injection patterns detected by the rules engine. This is a self-edge on the tool:

```text
(:MCPTool)-[:POISONED_DESCRIPTION]->(:MCPTool)
```

### `POISONED_INSTRUCTIONS`

An instruction file loaded by an agent contains suspicious patterns such as imperative overrides, exfiltration commands, or hidden Unicode:

```text
(:InstructionFile)-[:POISONED_INSTRUCTIONS]->(:InstructionFile)
```

### `POISONS_CONTEXT`

The `shadows` processor also emits `POISONS_CONTEXT` when an injection-bearing tool can poison the same agent context that drives a high-capability sibling tool:

```text
(:MCPTool)-[:POISONS_CONTEXT]->(:MCPTool)
```

The sink tool must carry one of:

```text
shell_access, code_execution, credential_access, email_send
```

Fan-out is capped to 20 sinks per `(agent, source tool)` pair to avoid cartesian blowups while still surfacing high-risk sources.

### Pre-built queries

```bash
agenthound-server query --prebuilt tool-shadowing
agenthound-server query --prebuilt poisoned-tools
agenthound-server query --prebuilt instruction-poisoning
```

## 6. Untrusted-Input Data Flow (`TAINTS`, `IFC_VIOLATION`)

The MCP collector emits raw `INGESTS_UNTRUSTED` edges for tools tagged by rules such as untrusted web, email, or fileshare input.

```text
(:MCPTool)-[:INGESTS_UNTRUSTED]->(:MCPResource)
```

The `taints` processor emits `TAINTS` when an untrusted-input tool shares at least two input-schema keys with a tool on another server:

```text
(:MCPTool)-[:TAINTS]->(:MCPTool)
```

The `ifc_violation` processor emits `IFC_VIOLATION` when an untrusted-input tool shares a resource path, within three `HAS_ACCESS_TO` hops, with a high-impact sink:

```text
(:MCPTool)-[:IFC_VIOLATION]->(:MCPTool)
```

High-impact sink capabilities are:

```text
credential_access, file_write, email_send
```

These edges surface through findings rather than dedicated pre-built query IDs.

## 7. A2A Identity and Delegation

### `CAN_IMPERSONATE`

The `can_impersonate` processor computes TF-IDF cosine similarity over A2A skill descriptions and emits bidirectional `CAN_IMPERSONATE` edges for cross-provider agent pairs with similarity greater than `0.8`.

```text
(:A2AAgent)-[:CAN_IMPERSONATE]->(:A2AAgent)
```

### `CONFUSED_DEPUTY`

The `auth_strength` pre-pass writes numeric auth weakness scores onto `MCPServer` and `A2AAgent` nodes. Higher is weaker (`none=100`, `apiKey=70`, `bearer=50`, `oauth=25`, `mtls=10`).

The `confused_deputy` processor emits `CONFUSED_DEPUTY` when a weakly authenticated A2A agent delegates to a strongly authenticated one:

```text
(:A2AAgent {auth_strength >= 80})
  -[:CONFUSED_DEPUTY]->
(:A2AAgent {auth_strength <= 30})
```

This models a low-trust caller borrowing the privileges of a higher-trust callee.

## Findings and Path Details

The Findings API returns composite-edge findings ranked by severity. The response shape uses `edge_kind`, not a processor name.

```bash
# All critical and high findings
agenthound-server query --findings --severity critical,high

# All CAN_REACH findings
curl -s localhost:8080/api/v1/analysis/findings | \
    jq '.[] | select(.edge_kind == "CAN_REACH")'

# Fetch one finding detail, including composite edge properties and reconstructed path
finding_id=$(curl -s localhost:8080/api/v1/analysis/findings | jq -r '.[0].id')
curl -s "localhost:8080/api/v1/analysis/findings/${finding_id}" | jq .
```

The finding detail response includes `composite_props`, which is where processor-specific properties such as `source_collector`, `via_gateway`, `merge_value_hash`, and `cross_protocol` appear.

The UI's Findings panel renders each path as an interactive graph with the attack narrative annotated on edges. The Graph Explorer allows click-through from any node to its blast radius.

## Post-Processor Execution Order

Processors run in dependency order. A processor may only read edges or properties produced by earlier processors.

| # | Processor | Produces | Dependencies |
|---|-----------|----------|--------------|
| 1 | `auth_strength` | `auth_strength` node property | None |
| 2 | `has_access_to` | `HAS_ACCESS_TO` | Raw edges |
| 3 | `can_execute` | `CAN_EXECUTE` | Raw edges |
| 4 | `shadows` | `SHADOWS`, `POISONS_CONTEXT` | Raw edges |
| 5 | `poisoned_description` | `POISONED_DESCRIPTION` | Raw edges |
| 6 | `poisoned_instructions` | `POISONED_INSTRUCTIONS` | Raw edges |
| 7 | `taints` | `TAINTS` | `INGESTS_UNTRUSTED`, `schema_keys` |
| 8 | `can_reach` | `CAN_REACH` | `HAS_ACCESS_TO` |
| 9 | `cross_service_credential_chain` | `CAN_REACH_CREDENTIAL_CHAIN` to upstream credentials, `CAN_REACH_CREDENTIAL_CHAIN.blast_radius` | `HAS_ACCESS_TO`, `CAN_REACH`, `value_hash` |
| 10 | `ifc_violation` | `IFC_VIOLATION` | `HAS_ACCESS_TO`, `INGESTS_UNTRUSTED` |
| 11 | `can_exfiltrate` | `CAN_EXFILTRATE_VIA` | `CAN_REACH` |
| 12 | `can_impersonate` | `CAN_IMPERSONATE` | Raw edges |
| 13 | `confused_deputy` | `CONFUSED_DEPUTY` | `auth_strength`, `CAN_REACH` |
| 14 | `cross_protocol` | Cross-protocol `CAN_REACH` | `HAS_ACCESS_TO`, `DELEGATES_TO` |
| 15 | `risk_score` | `risk_score` node property | Prior processors |

Each post-processor is idempotent. Re-ingesting a scan re-runs the pipeline and updates composite edges in place with `MERGE` by source, target, and edge kind. Stale composite-edge cleanup is scoped by `source_collector`, so partial scans refresh only the composite findings derived from collectors that ran in the current scan.
