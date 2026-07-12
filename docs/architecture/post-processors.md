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

**Computes:** `auth_strength` numeric property on every node with an `auth_method` (`MCPServer`, `A2AAgent`).

A pre-pass with no dependencies that materializes the runtime weakness score map (`riskscore.AuthStrengthScores`: none=100, apiKey=70, bearer=50, oauth=25, mtls=10) onto nodes as a Cypher `CASE`, so downstream processors (notably `confused_deputy`) can compare auth gradients directly in Cypher. It writes only node properties — no composite edges — so it needs no `source_collector` and is untouched by stale-edge cleanup.

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

**Computes:** `AgentInstance -[CAN_REACH_CREDENTIAL_CHAIN]-> Credential` (upstream provider keys)

Joins Config Collector and LiteLLM Looter emissions on `Credential.value_hash`:

```
AgentInstance -> MCPServer -[HAS_ENV_VAR]-> Credential(c1)
    where c1.value_hash matches...
LiteLLMGateway -[EXPOSES_CREDENTIAL]-> Credential(c1master)
LiteLLMGateway -[EXPOSES_CREDENTIAL]-> Credential(c2, type IN [apiKey, virtual_key])
```

Emits a **dedicated** `(AgentInstance)-[:CAN_REACH_CREDENTIAL_CHAIN]->(c2)` edge (not the proven `CAN_REACH`) with evidence including `merge_value_hash`, `via_gateway`, `upstream_provider`. The join that binds `c1` to `c1master` is synthetic (a `value_hash` equality, not a graph edge), so it uses a distinct edge kind rather than overloading proven transitive reach. Confidence: 0.95, hops: 5.

The edge also persists the **full evidence chain** so the finding's DAG/detail/impact are complete and self-contained: the per-endpoint generations (`source_generation`, `target_generation`) and every intermediate node's id + generation (`via_server_id`/`via_server_generation`, `via_credential_id`/`via_credential_generation`, `master_credential_id`/`master_credential_name`/`master_credential_generation`, `via_gateway_id`/`via_gateway_generation`). Because a cross-artifact chain spans generations, the finding detail reconstructs the six-node path (agent → server → env-var credential ==value_hash== master key → gateway → upstream credential) from these persisted properties rather than a single-generation re-traversal that would otherwise return nothing.

**Cross-generation join.** The Config Collector and a Looter ship as **separate artifacts in different generations**, so the in-ingest, single-`scan_id` processor can never see both. The pipeline therefore also runs a cross-generation pass (`analysis.CrossGenerationCredentialChain`) after generation tagging, scoped by `generations`-set membership to an **owner-specific, immutable selection**: the current generations of *other* scopes that are eligible participants, plus the generation being ingested (the owner). Emitted edges are attributed to (and scoped by) the owner generation.

- **Superseded same-scope exclusion.** The owner's own scope is excluded from the selection, so a superseded prior generation of the same scope is never mixed with the new owner generation.
- **Participation gating.** Only eligible artifacts join: loot generations (`loot:<type>`) always, and config-bearing generations (the `config` collector or the merged `scan:local` bundle) only with **explicit** coverage (`complete`/`partial`). An unknown-coverage config artifact makes no positive claim and is excluded. Delete-lifecycle generations are already excluded by the current-generation read.
- **Owner must contribute.** The join only emits (and attributes) an owner-generation edge when the owner generation actually observed one of the matched path nodes, so a generation is never credited with a chain it did not produce.
- **Selection errors fail the stage.** If the current-generation selection cannot be read, the **post-processing** stage is degraded to `failed` (the chain would join against an unknown set), blocking promotion.
- **Failures fail the stage.** A cross-generation-chain error degrades the **post-processing** stage to `failed`, which blocks promotion — a generation whose credential-chain findings are missing/incomplete never becomes current.
- **Owner gating.** The artifact currently being ingested runs the chain only when it is itself an eligible anchor (config-bearing with explicit coverage, or a complete/partial loot), so an mcp/a2a/network re-ingest or a failed/unknown-coverage artifact never re-runs it.

This makes a normal `config` + `loot` (e.g. LiteLLM) deployment produce the chain: `c1` (config generation) and `c1master`/`c2` (loot generation) both qualify by membership and join on `value_hash`. A loot artifact occupies its own scope (`loot:<type>`), so it never demotes the config generation while remaining membership-compatible with the join.

The same single query also computes **credential blast radius**: `count(DISTINCT agent)` reaching the merged secret, written as `blast_radius` on the emitted `CAN_REACH_CREDENTIAL_CHAIN` composite edge (keyed to the env-var credential via `via_credential_id`) — **not** written back onto the raw `Credential` observations (`c1`/`c1master`), which are immutable prior-generation facts. The agents are collected for the count and re-UNWOUND so the MERGE stays one edge per (agent, upstream-credential). `blast_radius` then amplifies the server credential-handling risk term (see risk-scoring.md).

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

Pattern ensures the agent has both the data access AND an outbound channel. The `auto_fetch_render` / `allowlisted_proxy` classes broaden the set of covert exfiltration channels (see detection-rules.md for the `auto_fetch_render` host-side caveat). Confidence: 0.8.

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

## confused_deputy

**Computes:** `A2AAgent -[CONFUSED_DEPUTY]-> A2AAgent`

Flags a confused-deputy escalation: a weakly-authenticated agent (`auth_strength >= 80`, i.e. none/apiKey-class) that `DELEGATES_TO` a strongly-authenticated one (`auth_strength <= 30`, i.e. oauth/mtls-class). The low-trust caller effectively borrows the callee's privileges. Depends on the `auth_strength` pre-pass and `can_reach` (ordering). `source_collector='a2a'` — a real collector, so it participates in stale-edge cleanup directly. Confidence: 0.8, risk_weight: 0.3.

## 11. risk_score

**Computes:** `risk_score` property on AgentInstance, A2AAgent, MCPServer, MCPTool nodes (0-100)

Depends on ALL prior processors (uses their edges for scoring). Iterates all nodes of each scored kind and invokes per-kind scoring functions from `analysis/riskscore/`.

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

## Stale-Edge Cleanup

Before processors run, `cleanStaleCompositeEdges()` deletes composite edges from previous scans scoped by the current scan's collector(s). Collector names are expanded to include processor-owned derived sources when needed, such as `cross_service_credential_chain` for config or network-scan inputs:

```cypher
MATCH ()-[r]->()
WHERE r.is_composite = true
  AND r.scan_id <> $current_scan_id
  AND r.source_collector IN $collectors
DELETE r
```

This prevents stale findings from accumulating while preserving composite edges from other collectors. An MCP-only re-scan deletes old MCP composite edges but leaves A2A and credential-chain edges untouched; a config or network re-scan also cleans credential-chain edges because those findings depend on the refreshed credential inputs.

### INGESTS_UNTRUSTED raw-edge accumulation

`INGESTS_UNTRUSTED` is a **raw** edge (`is_composite=false`), so it is *not* swept by `cleanStaleCompositeEdges` (which gates on `is_composite=true`). It is MERGE-keyed on (source, target), so re-scans rewrite `scan_id` for tools that stay around. The trade-off: a renamed or removed tool whose `INGESTS_UNTRUSTED` edge was emitted in a prior scan will linger, because the old (tool, resource) key is never re-MERGEd. Mitigation is to gate emission on stable, rule-derived `source_trust` (which does not flap for the same tool). A dedicated raw-edge sweeper is intentionally out of scope; if false-positive linger becomes load-bearing, the fix is a separate processor that DELETEs `INGESTS_UNTRUSTED` edges whose source tool no longer carries `source_trust`.

---

## Findings Snapshot Stage (pipeline)

After post-processing completes and before the scan-completion record is written, the ingest pipeline persists a **findings snapshot** to Postgres (`appdb.FindingStore.InsertFindings`). Sequencing matters: `cleanStaleCompositeEdges` runs first, so the Neo4j graph already reflects only the current scan's composite-edge set when the snapshot is taken.

This snapshot is the diffable record of "what was found when". The Neo4j graph itself is **not** diffable across scans — the stale-edge cleanup deletes prior-scan composite edges — so every triage (`/findings/triage`) and diff (`query --diff`) read comes from the Postgres snapshot, which is invariant under the next scan's cleanup. The snapshot write is non-fatal: a Postgres hiccup logs a warning but does not fail the ingest.

## Integration-test isolation

Post-processors operate on the **whole graph**, not a scan-scoped subgraph: `risk_score` lists every node of a kind, `shadows`/`taints`/`can_reach` MATCH across all servers, etc. That is correct for production (one scan, one graph) but it means two integration-test binaries cannot safely share one Neo4j concurrently — a `DETACH DELETE` in one binary can vanish a node mid-traversal in another, surfacing as `Neo.ClientError.Statement.EntityNotFound` or phantom zero-count assertions. Because `go test ./...` runs package test binaries in parallel, every DB-touching package (`analysis`, `analysis/processors`, `graph`) holds an exclusive advisory file lock (`server/internal/dbtest`) for its run via `TestMain`. The lock is a no-op when `AGENTHOUND_NEO4J_URI` is unset, so unit-only (`-short`) runs keep full parallelism. New packages that run post-processors against a live DB **must** add the same `TestMain` guard.
