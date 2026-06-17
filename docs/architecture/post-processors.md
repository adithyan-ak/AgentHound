# Post-Processors

Post-processors compute composite edges and risk scores from raw graph state after the batch write phase. They run in `server/internal/analysis/processors/` and are orchestrated by `analysis.RunPostProcessors()`.

All composite edges carry: `scan_id`, `last_seen`, `confidence` (0.0-1.0), `risk_weight`, `is_composite=true`, `source_collector`.

## Dependency DAG

```
has_access_to ─────┬─── can_reach ────┬── cross_service_credential_chain
                   │                  └── can_exfiltrate
                   └─── cross_protocol
can_execute
shadows
poisoned_description
poisoned_instructions
can_impersonate
                            ALL ───── risk_score
```

## Execution Order

| # | Processor | Dependencies |
|---|-----------|--------------|
| 1 | has_access_to | none |
| 2 | can_execute | none |
| 3 | shadows | none |
| 4 | poisoned_description | none |
| 5 | poisoned_instructions | none |
| 6 | can_reach | has_access_to |
| 7 | cross_service_credential_chain | has_access_to, can_reach |
| 8 | can_exfiltrate | can_reach |
| 9 | can_impersonate | none |
| 10 | cross_protocol | has_access_to |
| 11 | risk_score | all of 1-10 |

## Processor Interface

```go
type PostProcessor interface {
    Name() string
    Dependencies() []string
    Process(ctx context.Context, db graph.GraphDB, scanID string) (ProcessingStats, error)
}
```

`ProcessingStats` returns: `ProcessorName`, `EdgesCreated`, `NodesUpdated`, `Duration`, `Error`.

---

## 1. has_access_to

**Computes:** `MCPTool -[HAS_ACCESS_TO]-> MCPResource`

Links tools to resources on the same server when capability or description indicates access.

Three Cypher passes:
- **Capability-DB:** Tool has `database_access` capability AND resource URI scheme is postgres/mysql/mongodb/redis. Confidence: 0.7.
- **Capability-File:** Tool has `file_read` or `file_write` AND resource URI scheme is `file`. Confidence: 0.7.
- **Description match:** Tool description contains the resource name (case-insensitive substring). Confidence: 0.9.

All edges: `risk_weight=0.2`, `match_type` recorded for evidence.

## 2. can_execute

**Computes:** `MCPTool -[CAN_EXECUTE]-> Host`

Links tools to their server's host when the tool has `shell_access` or `code_execution` in `capability_surface`.

Pattern:
```cypher
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool), (s)-[:RUNS_ON]->(h:Host)
WHERE ANY(cap IN t.capability_surface WHERE cap IN ['shell_access', 'code_execution'])
MERGE (t)-[e:CAN_EXECUTE]->(h)
```

Confidence: 1.0, risk_weight: 0.1.

## 3. shadows

**Computes:** `MCPTool -[SHADOWS]-> MCPTool` (cross-server)

Detects tool shadowing: a tool on one server names another server's tool in its description (`toLower(t1.description) CONTAINS toLower(t2.name)`), which lets it impersonate or override that tool.

Pattern requires `s1 <> s2` and `t1 <> t2`. The match is intentionally target-specific — `t1`'s description must reference `t2` by name. It does **not** branch on the `has_cross_references` node flag: that flag is target-blind (true if `t1` references *any* sibling tool, see `modules/mcp/signals.go`), so OR-ing it in made one flagged tool shadow every tool on every other server (a cartesian fan-out of false positives). `has_cross_references` still feeds tool risk scoring as a node property (`server/internal/analysis/riskscore/tool.go`).

Confidence scales with injection patterns: 0.9 when `has_injection_patterns=true`, 0.6 otherwise. Risk weight: 0.4.

## 4. poisoned_description

**Computes:** `MCPTool -[POISONED_DESCRIPTION]-> MCPTool` (self-loop)

Flags tools whose descriptions contain injection patterns (detected by the rules engine during collection and stored as `has_injection_patterns=true`).

Confidence: 1.0, risk_weight: 0.8. Self-loop edge -- the finding is about the tool itself.

## 5. poisoned_instructions

**Computes:** `InstructionFile -[POISONED_INSTRUCTIONS]-> InstructionFile` (self-loop)

Flags instruction files marked `is_suspicious=true` by the Config Collector (imperative overrides, exfiltration commands, hidden Unicode).

Confidence: 1.0, risk_weight: 0.7, source_collector: `config`.

## 6. can_reach

**Computes:** `AgentInstance -[CAN_REACH]-> MCPResource`

The critical transitive-access edge. Two passes:

**Direct path (3 hops):**
```
AgentInstance -[TRUSTS_SERVER]-> MCPServer -[PROVIDES_TOOL]-> MCPTool -[HAS_ACCESS_TO]-> MCPResource
```
Confidence scales inversely with trust edge risk_weight (no-auth trust = 1.0, static-key = 0.8, OAuth = 0.5).

**Credential chain (6 hops):**
```
AgentInstance -> MCPServer(s1) -> MCPTool(file_read|credential_access)
MCPServer(s2) -[HAS_ENV_VAR]-> Credential -> Identity -> MCPServer(s2) -> MCPTool -> MCPResource
```
Requires s1 has no/weak auth so creds are accessible. Confidence: 0.6.

## 7. cross_service_credential_chain

**Computes:** `AgentInstance -[CAN_REACH]-> Credential` (upstream provider keys)

Joins Config Collector and LiteLLM Looter emissions on `Credential.value_hash`:

```
AgentInstance -> MCPServer -[HAS_ENV_VAR]-> Credential(c1)
    where c1.value_hash matches...
LiteLLMGateway -[EXPOSES_CREDENTIAL]-> Credential(c1master)
LiteLLMGateway -[EXPOSES_CREDENTIAL]-> Credential(c2, type IN [apiKey, virtual_key])
```

Emits: `(AgentInstance)-[:CAN_REACH]->(c2)` with evidence including `merge_value_hash`, `via_gateway`, `upstream_provider`. Confidence: 0.95, hops: 5.

The `value_hash` is the cross-collector merge primitive -- same secret value regardless of how each collector derives its objectid.

## 8. can_exfiltrate

**Computes:** `AgentInstance -[CAN_EXFILTRATE_VIA]-> MCPTool`

Requires both conditions:
1. Agent CAN_REACH a resource with sensitivity `critical` or `high`
2. Agent trusts a server with a tool having `email_send`, `network_outbound`, or `file_write` capability

Pattern ensures the agent has both the data access AND an outbound channel. Confidence: 0.8.

## 9. can_impersonate

**Computes:** `A2AAgent -[CAN_IMPERSONATE]-> A2AAgent` (bidirectional)

Uses TF-IDF cosine similarity on skill descriptions. For each pair of A2A agents (from different providers):
1. Loads all agents from Neo4j
2. Builds per-agent document from concatenated skill descriptions
3. Computes TF-IDF vectors via `similarity.NewCorpus`
4. Emits bidirectional CAN_IMPERSONATE edges where cosine similarity > 0.8

Writes edges via `db.WriteEdges()` (batch) rather than Cypher MERGE. Risk weight: 0.6.

Agents from the same provider are excluded (impersonation assumes cross-provider).

## 10. cross_protocol

**Computes:** `A2AAgent -[CAN_REACH]-> MCPResource`

The cross-protocol attack path that single-protocol scanners cannot detect:

```cypher
MATCH (ext:A2AAgent)-[:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[:RUNS_ON]->(h:Host)<-[:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s)-[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE ext.auth_method IS NULL OR ext.auth_method = 'none'
```

Requires the external A2A agent has no authentication. The pivot point is host co-location: an A2A agent that delegates to another agent running on the same host as an MCP server. Edge properties include `cross_protocol=true`. Confidence: 0.5.

## 11. risk_score

**Computes:** `risk_score` property on AgentInstance, MCPServer, MCPTool nodes (0-100)

Depends on ALL prior processors (uses their edges for scoring). Iterates all nodes of each scored kind and invokes per-kind scoring functions from `analysis/riskscore/`.

**Agent score (0-100):**
- 0.30 x credential exposure
- 0.25 x blast radius (reachable resources)
- 0.20 x auth posture
- 0.15 x tool surface
- 0.10 x poisoning exposure

**Server score (0-100):**
- 0.35 x auth strength
- 0.25 x tool risk
- 0.20 x exposure
- 0.20 x credential handling

**Tool score (0-100):**
- 0.30 x capability class
- 0.25 x poisoning indicators
- 0.25 x access sensitivity
- 0.20 x input validation signals

---

## Stale-Edge Cleanup

Before processors run, `cleanStaleCompositeEdges()` deletes composite edges from previous scans scoped by the current scan's collector(s):

```cypher
MATCH ()-[r]->()
WHERE r.is_composite = true
  AND r.scan_id <> $current_scan_id
  AND r.source_collector IN $collectors
DELETE r
```

This prevents stale findings from accumulating while preserving composite edges from other collectors. An MCP-only re-scan deletes old MCP composite edges but leaves A2A edges untouched.
