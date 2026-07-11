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
| 1 | auth_strength | none (pre-pass) |
| 2 | has_access_to | none |
| 3 | can_execute | none |
| 4 | shadows (+ POISONS_CONTEXT) | none |
| 5 | poisoned_description | none |
| 6 | poisoned_instructions | none |
| 7 | taints | none (reads INGESTS_UNTRUSTED + schema_keys) |
| 8 | can_reach | has_access_to |
| 9 | cross_service_credential_chain | has_access_to, can_reach |
| 10 | ifc_violation | has_access_to (reads INGESTS_UNTRUSTED) |
| 11 | can_exfiltrate | can_reach |
| 12 | can_impersonate | none |
| 13 | confused_deputy | auth_strength, can_reach |
| 14 | cross_protocol | has_access_to |
| 15 | risk_score | all of 1-14 |

## Processor Interface

```go
type PostProcessor interface {
    Name() string
    Dependencies() []string
    Process(ctx context.Context, db graph.GraphDB, scanID string) (ProcessingStats, error)
}
```

`ProcessingStats` returns: `ProcessorName`, `EdgesCreated`, `NodesUpdated`, `Duration`, `Error`.

> The Execution Order table above is the canonical sequence. The numbered
> section headings below predate later additions; new processors
> (`auth_strength`, `taints`, `ifc_violation`, `confused_deputy`) and the
> `POISONS_CONTEXT` pass are documented under their own headings.

---

## auth_strength (pre-pass)

**Computes:** canonical `auth_assurance` on every assessed node and numeric `auth_strength` only for known methods (`MCPServer`, `A2AAgent`).

A pre-pass with no dependencies that materializes the shared SDK auth policy:
none=100/unauthenticated, basic=85/weak, apiKey=70/weak,
bearer=50/moderate, oauth=25/strong, oidc=20/strong, and mtls=10/strong.
Unknown/custom methods receive `auth_assurance=unknown` and a null numeric
property, removing any stale score. It writes only node properties — no
composite edges — so it needs no `source_collector` and is untouched by
stale-edge cleanup.

---

## 1. has_access_to

**Computes:** `MCPTool -[HAS_ACCESS_TO]-> MCPResource`

Links tools to resources on the same server when capability or description indicates access.

Three Cypher passes:
- **Capability-DB:** Tool has `database_access` capability AND resource URI scheme is postgres/mysql/mongodb/redis. Confidence: 0.7.
- **Capability-File:** Tool has `file_read` or `file_write` AND resource URI scheme is `file`. Confidence: 0.7.
- **Description match:** Tool description contains the resource name (case-insensitive substring). Confidence: 0.9.

All edges: `risk_weight=0.2`, `match_type` recorded for evidence. Confidence,
match type, weight, collector, and scan metadata are refreshed on MERGE so a
prior inference cannot retain stale evidence.

## 2. can_execute

**Computes:** `MCPTool -[CAN_EXECUTE]-> Host`

Links tools to their server's host when the tool has `shell_access` or
`code_execution` in `capability_surface`. The YAML classifiers require
execution-specific terms; database-only names such as `execute_query` do not
produce either capability.

Pattern:
```cypher
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool), (s)-[:RUNS_ON]->(h:Host)
WHERE ANY(cap IN t.capability_surface WHERE cap IN ['shell_access', 'code_execution'])
MERGE (t)-[e:CAN_EXECUTE]->(h)
```

Confidence: 0.8, risk_weight: 0.1. Both values refresh on MERGE. This is a
metadata-derived execution candidate, not observed command execution.

## 3. shadows

**Computes:** `MCPTool -[SHADOWS]-> MCPTool` (cross-server)

Detects tool shadowing: a tool on one server names another server's tool in its description (`toLower(t1.description) CONTAINS toLower(t2.name)`), which lets it impersonate or override that tool.

Pattern requires `s1 <> s2` and `t1 <> t2`. The match is intentionally target-specific — `t1`'s description must reference `t2` by name. It does **not** branch on the `has_cross_references` node flag: that flag is target-blind (true if `t1` references *any* sibling tool, see `modules/mcp/signals.go`), so OR-ing it in made one flagged tool shadow every tool on every other server (a cartesian fan-out of false positives). `has_cross_references` still feeds tool risk scoring as a node property (`server/internal/analysis/riskscore/tool.go`).

Confidence scales with injection patterns: 0.9 when `has_injection_patterns=true`, 0.6 otherwise. Risk weight: 0.4.

**POISONS_CONTEXT (second pass):** the shadows processor runs a second Cypher pass that emits `MCPTool -[POISONS_CONTEXT]-> MCPTool` when the source has `has_injection_patterns=true` and the sink carries a high-blast capability (`shell_access`, `code_execution`, `credential_access`, `email_send`), **scoped to a single agent**: both tools must be co-resident under one `AgentInstance` via `(:AgentInstance)-[:TRUSTS_SERVER]->(:MCPServer)-[:PROVIDES_TOOL]->(:MCPTool)`. This deliberately widens the narrow SHADOWS guard (no description-naming requirement) to model context poisoning while the agent scope prevents a cross-tenant cross product. Fan-out is **truncated to 20 sinks per (agent, source) pair** to prevent a cartesian blow-up — the query groups on `WITH a, src` so the cap is genuinely per-agent-per-source, not a single global bucket, and keeps the first 20 sinks by `objectid` (`collect(DISTINCT snk)[..20]`, deterministic via `ORDER BY`) rather than dropping the over-cap group entirely. Truncation, not suppression, is deliberate: silently emitting zero edges for a source with >20 sinks would blind the detector in its highest-risk case and let an attacker evade it by registering a 21st sink. The cap is regression-gated by a Go integration test (`poisons_context_perf_integration_test.go`) that runs in the `test-integration` CI job; `scripts/perf-check.sh` remains the operator-facing runtime heuristic, enforcing a ≤200 poisoned-pair-per-agent ceiling (10 source tools × 20 sinks). Confidence: 0.6, risk_weight: 0.4, `source_collector='mcp'`.

## 4. poisoned_description

**Computes:** `MCPTool -[POISONED_DESCRIPTION]-> MCPTool` (self-loop)

Flags tools whose descriptions contain injection patterns (detected by the rules engine during collection and stored as `has_injection_patterns=true`).

Confidence: 1.0, risk_weight: 0.8. Self-loop edge -- the finding is about the tool itself.

## 5. poisoned_instructions

**Computes:** `InstructionFile -[POISONED_INSTRUCTIONS]-> InstructionFile` (self-loop)

Flags instruction files marked `is_suspicious=true` by the Config Collector (imperative overrides, exfiltration commands, hidden Unicode).

Confidence: 1.0, risk_weight: 0.7, source_collector: `config`.

## taints

**Computes:** `MCPTool -[TAINTS]-> MCPTool` (cross-server)

Emits a `TAINTS` edge when a tool that ingests untrusted input (it has an `INGESTS_UNTRUSTED` edge, or `source_trust='private'`) shares **≥2 input-schema keys** with a tool on another server. The schema overlap is computed in pure Cypher against the `schema_keys` node property (emitted collector-side — no APOC dependency). The ≥2 threshold avoids matching every `{type, name}` pair. No processor dependencies (reads raw `INGESTS_UNTRUSTED` edges + node properties), but registered before `can_reach` so its edges can influence the reachability walk. Confidence: 0.7, risk_weight: 0.3, `source_collector='mcp'`.

## 6. can_reach

**Computes:** `AgentInstance -[CAN_REACH]-> MCPResource`

The inferred transitive-access compatibility edge. Two passes:

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
Requires explicit unauthenticated/weak evidence for s1; missing auth evidence
does not match. Confidence: 0.6.

## 7. cross_service_credential_chain

**Computes:** `AgentInstance -[CAN_REACH]-> Credential` (upstream provider
credential material or references)

Joins Config Collector and LiteLLM Looter emissions on `Credential.value_hash`:

```
AgentInstance -> MCPServer -[HAS_ENV_VAR]-> Credential(c1)
    where c1.value_hash matches...
LiteLLMGateway -[EXPOSES_CREDENTIAL]-> Credential(c1master)
LiteLLMGateway -[EXPOSES_CREDENTIAL]-> Credential(c2, type IN [apiKey, virtual_key])
```

Emits: `(AgentInstance)-[:CAN_REACH]->(c2)` with evidence including
`merge_value_hash`, `via_gateway`, `upstream_provider`. The resulting finding
variant is `credential_chain_observed_material` only when c2 explicitly carries
observed, exposed, non-identity material; masked/hashed targets are
`credential_chain_reference`. Confidence: 0.95, hops metadata: 5.

The same single query also computes **credential blast radius**: `count(DISTINCT agent)` reaching the merged secret, written as `blast_radius` on both `c1` (the env-var credential) and `c1master` (its value_hash twin). The agents are collected for the count and re-UNWOUND so the CAN_REACH MERGE stays one edge per (agent, upstream-credential). `blast_radius` then amplifies the server credential-handling risk term (see risk-scoring.md).

The `value_hash` is the cross-collector merge primitive -- same secret value regardless of how each collector derives its objectid.

## ifc_violation

**Computes:** `MCPTool -[IFC_VIOLATION]-> MCPTool`

Emits an information-flow-control violation edge when an untrusted-input tool (`INGESTS_UNTRUSTED -> MCPResource`) shares a resource within **3 `HAS_ACCESS_TO` hops** with a sink tool carrying a high-impact capability (`credential_access`, `file_write`, `email_send`). The 1..3 hop cap is the false-positive / performance guard. Depends on `has_access_to`. Confidence: 0.6, risk_weight: 0.3, `source_collector='mcp'`.

> **Cleanup semantics:** `IFC_VIOLATION` carries `source_collector='mcp'`, so it is only swept by stale-edge cleanup when the `mcp` collector re-runs. If an operator runs only `a2a` / `config` scans afterward, IFC edges from a prior `mcp` scan persist (the underlying tools were not re-enumerated). This is acceptable.

## 8. can_exfiltrate

**Computes:** `AgentInstance -[CAN_EXFILTRATE_VIA]-> MCPTool`

Requires both conditions:
1. Agent CAN_REACH a resource with sensitivity `critical` or `high`
2. Agent trusts a server with a tool having an outbound capability: `email_send`, `network_outbound`, `file_write`, `auto_fetch_render`, or `allowlisted_proxy`

Pattern correlates inferred data access with a matched output-channel
capability. It does not observe data transfer or prove runtime invocability.
The `auto_fetch_render` / `allowlisted_proxy` classes broaden the set of
candidate channels (see detection-rules.md for the `auto_fetch_render`
host-side caveat). Confidence: 0.8.

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

The cross-protocol shared-host correlation that single-protocol scanners
cannot express:

```cypher
MATCH (ext:A2AAgent)-[:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[:RUNS_ON]->(h:Host)<-[:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s)-[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE ext.auth_assurance = 'unauthenticated'
  AND ext.auth_evidence = 'anonymous_probe_succeeded'
```

Requires explicit unauthenticated evidence for the external A2A agent; missing
auth is unknown and does not match. The pivot is host co-location: an A2A
agent delegates to another agent recorded on the same host as an MCP server.
The edge carries `cross_protocol=true` and confidence 0.5. Finding and pre-built
query output label it a `shared_host` hypothesis, not proven A2A-to-MCP
invocation.

## confused_deputy

**Computes:** `A2AAgent -[CONFUSED_DEPUTY]-> A2AAgent`

Flags a confused-deputy escalation when an unauthenticated/weak A2A agent
`DELEGATES_TO` a strong one. Unknown/custom methods are excluded. The low-trust
caller effectively borrows the callee's privileges. Depends on the
`auth_strength` pre-pass and `can_reach` (ordering).
`source_collector='a2a'`; confidence 0.8, risk weight 0.3.

## 11. risk_score

**Computes:** `risk_score`, `risk_score_min`, `risk_score_max`,
`risk_assessment_complete`, and `risk_unknown_factors` on AgentInstance,
A2AAgent, MCPServer, and MCPTool nodes.

Depends on ALL prior processors (uses their edges for scoring). It reads every
page of each scored kind under one graph revision before writing any scores;
an incomplete page, revision/total change, or count mismatch aborts the
processor rather than publishing scores for a partial node set. Per-kind
scoring functions live in `analysis/riskscore/`.

**Agent score (0-100):**
- 0.30 x credential exposure
- 0.25 x blast radius (reachable resources)
- 0.20 x auth posture
- 0.15 x tool surface
- 0.10 x poisoning exposure

**A2A agent score (0-100):**
- 0.30 x auth strength
- 0.30 x cross-protocol blast radius
- 0.25 x delegation surface
- 0.15 x impersonation exposure

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

## Post-success stale-edge cleanup

`cleanStaleCompositeEdges()` runs only after every registered processor
successfully recomputes its candidate output. A processor failure leaves the
prior composite epoch available and marks the live projection incomplete.

```cypher
MATCH ()-[r]->()
WHERE r.is_composite = true
  AND r.scan_id <> $current_scan_id
  AND r.source_collector IN $collectors
DELETE r
```

Cleanup is enabled only when at least one explicit complete raw-coverage domain
was promoted. Collector names are dependency-expanded (for example MCP/config
also refresh `cross_service_credential_chain`), but unrelated collector-owned
composites are preserved. Unknown/partial legacy coverage does not enable
cleanup.

### INGESTS_UNTRUSTED raw-edge accumulation

`INGESTS_UNTRUSTED` is a **raw** edge (`is_composite=false`), so composite
cleanup never touches it. It participates in the same observation-owner
reconciliation as every other new raw edge: a complete MCP domain removes the
prior MCP token, while partial/unknown coverage retains it.

---

## Findings Snapshot Stage (pipeline)

After post-processing and graph-total capture, the ingest pipeline materializes
a candidate **findings snapshot**. PostgreSQL finalization deletes and replaces
all rows for that scan in one transaction, including an empty retry.

Every finding-producing processor records the exact witness node object IDs and
Neo4j relationship IDs selected by its detector on the composite edge. During
the same ingest, `QueryFindings` dereferences those IDs once and migration
`007_exact_finding_evidence.sql` stores the resulting node/edge snapshots as
JSONB with the finding row. Finding detail serves that frozen witness graph; it
does not re-run detector-like `LIMIT 1` queries against the mutable projection.
Legacy rows disclose that no exact witness was retained.

When all required stages and complete coverage succeed, the same transaction
inserts an immutable `posture_publications` revision, persists its export, and
advances `posture_state`. Otherwise the snapshot can remain historical but the
published pointer does not move. A degraded retry using the currently
published scan ID preserves the prior published rows and export until a new
complete revision commits.

## Integration-test isolation

Post-processors operate on the **whole graph**, not a scan-scoped subgraph: `risk_score` lists every node of a kind, `shadows`/`taints`/`can_reach` MATCH across all servers, etc. That is correct for production (one scan, one graph) but it means two integration-test binaries cannot safely share one Neo4j concurrently — a `DETACH DELETE` in one binary can vanish a node mid-traversal in another, surfacing as `Neo.ClientError.Statement.EntityNotFound` or phantom zero-count assertions. Because `go test ./...` runs package test binaries in parallel, every DB-touching package (`analysis`, `analysis/processors`, `graph`) holds an exclusive advisory file lock (`server/internal/dbtest`) for its run via `TestMain`. The lock is a no-op when `AGENTHOUND_NEO4J_URI` is unset, so unit-only (`-short`) runs keep full parallelism. New packages that run post-processors against a live DB **must** add the same `TestMain` guard.
