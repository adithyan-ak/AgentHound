# Phase 3: Post-Processing & Attack Path Engine

**Timeline:** Weeks 6–7
**Goal:** Compute composite edges (CAN_REACH, CAN_EXFILTRATE_VIA, SHADOWS, etc.), implement risk scoring, build pathfinding API endpoints, ship pre-built query library, and add CLI query mode.

**Depends on:** Phase 1 (graph infrastructure), Phase 2 (collectors populating graph with raw nodes/edges)

---

## 1. Architecture Overview

Post-processing runs **after each ingest**. It reads the current graph state from Neo4j, evaluates conditions, and writes composite edges that encode multi-hop attack semantics. This is the BloodHound pattern: raw edges collected → composite edges derived.

```
Raw Graph (from collectors)          Post-Processed Graph (attack paths)
─────────────────────────           ──────────────────────────────────
Agent → Server → Tool → Resource    Agent ──CAN_REACH──> Resource
Agent → Server → Tool (outbound)    Agent ──CAN_EXFILTRATE_VIA──> Tool
Tool description mentions Tool2     Tool ──SHADOWS──> Tool2
Tool has <IMPORTANT> tag            Tool ──POISONED_DESCRIPTION──> Tool (self)
A2A → A2A → Agent → Server → ...   A2A ──CAN_REACH──> Resource (cross-protocol)
```

---

## 2. Post-Processor Framework

### 2.1 Files

```
internal/analysis/
├── postprocessor.go           # PostProcessor interface + runner
├── processors/
│   ├── has_access_to.go       # Tool → Resource access inference
│   ├── can_execute.go         # Tool → Host shell access
│   ├── shadows.go             # Cross-origin tool shadowing
│   ├── poisoned.go            # Tool description injection detection
│   ├── can_reach.go           # Agent → Resource transitive access (THE critical edge)
│   ├── can_exfiltrate.go      # Agent → Tool data exfiltration paths
│   ├── can_impersonate.go     # A2A agent capability overlap
│   ├── cross_protocol.go      # A2A → MCP boundary crossing
│   └── risk_score.go          # Node risk score computation
├── riskscore/
│   ├── agent.go               # AgentInstance risk score formula
│   ├── server.go              # MCPServer risk score formula
│   ├── tool.go                # MCPTool risk score formula
│   └── weights.go             # Edge risk weight assignment
├── similarity/
│   └── tfidf.go               # TF-IDF cosine similarity for CAN_IMPERSONATE
├── sensitivity/
│   └── classifier.go          # Resource sensitivity auto-classification
└── analysis_test.go           # Tests
```

### 2.2 PostProcessor Interface

```go
// pkg/analysis/postprocessor.go (defined in Phase 1)
type PostProcessor interface {
    Name() string
    Dependencies() []string
    Process(ctx context.Context, graphDB GraphDB, scanID string) (ProcessingStats, error)
}

type ProcessingStats struct {
    EdgesCreated int
    EdgesUpdated int
    EdgesDeleted int
    Duration     time.Duration
}
```

### 2.3 Execution Engine

```go
// internal/analysis/postprocessor.go
func RunPostProcessors(ctx context.Context, graphDB GraphDB, scanID string) error {
    processors := []PostProcessor{
        // Order matters — respects dependencies
        &processors.HasAccessToProcessor{},       // 1. Tool → Resource
        &processors.CanExecuteProcessor{},         // 2. Tool → Host
        &processors.ShadowsProcessor{},            // 3. Tool → Tool
        &processors.PoisonedDescriptionProcessor{},// 4. Tool self-edge
        &processors.CanReachProcessor{},           // 5. Agent → Resource (depends on 1)
        &processors.CanExfiltrateProcessor{},      // 6. Agent → Tool (depends on 5)
        &processors.CanImpersonateProcessor{},     // 7. A2A → A2A
        &processors.CrossProtocolProcessor{},      // 8. A2A → MCP (depends on 1)
        &processors.RiskScoreProcessor{},          // 9. All nodes (depends on 1-8)
    }

    // Validate dependency ordering
    if err := validateDependencyOrder(processors); err != nil {
        return fmt.Errorf("invalid processor order: %w", err)
    }

    // Clean stale composite edges from previous scans FIRST
    if err := cleanStaleCompositeEdges(ctx, graphDB, scanID); err != nil {
        return fmt.Errorf("cleanup: %w", err)
    }

    for _, p := range processors {
        slog.Info("running post-processor", "name", p.Name())
        stats, err := p.Process(ctx, graphDB, scanID)
        if err != nil {
            return fmt.Errorf("post-processor %s: %w", p.Name(), err)
        }
        slog.Info("post-processor complete",
            "name", p.Name(),
            "created", stats.EdgesCreated,
            "duration", stats.Duration)
    }
    return nil
}
```

**Stale Edge Cleanup:**
Only delete composite edges whose source collector ran in this scan. This avoids a ping-pong effect where partial scans (e.g., MCP-only) delete A2A composite edges that won't be recomputed until the next A2A scan.

```cypher
// Delete composite edges from previous scans, scoped to the collectors that ran
MATCH ()-[r]->()
WHERE r.is_composite = true
  AND r.scan_id <> $current_scan_id
  AND r.source_collector IN $collectors_in_current_scan
DELETE r
RETURN count(r) AS deleted
```

---

## 3. Composite Edge Processors — Detailed Implementation

### 3.1 HAS_ACCESS_TO (Tool → Resource)

**Meaning:** This MCPTool can read/write this MCPResource.

**Cypher:**
```cypher
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
MATCH (s)-[:PROVIDES_RESOURCE]->(r:MCPResource)
WHERE
  (ANY(cap IN t.capability_surface WHERE cap IN ['database_access']) AND r.uri_scheme IN ['postgres', 'mysql', 'mongodb', 'sqlite', 'redis'])
  OR (ANY(cap IN t.capability_surface WHERE cap IN ['file_read', 'file_write']) AND r.uri_scheme = 'file')
  OR (toLower(t.description) CONTAINS toLower(r.name))
MERGE (t)-[e:HAS_ACCESS_TO]->(r)
SET e.confidence = CASE
  WHEN toLower(t.description) CONTAINS toLower(r.name) THEN 0.9
  WHEN ANY(cap IN t.capability_surface WHERE cap IN ['database_access', 'file_read', 'file_write']) THEN 0.7
  ELSE 0.5
END,
e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
e.source_collector = 'mcp', e.risk_weight = 0.2
```

### 3.2 CAN_EXECUTE (Tool → Host)

**Meaning:** This tool can execute arbitrary commands on this host.

```cypher
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
MATCH (s)-[:RUNS_ON]->(h:Host)
WHERE ANY(cap IN t.capability_surface WHERE cap IN ['shell_access', 'code_execution'])
MERGE (t)-[e:CAN_EXECUTE]->(h)
SET e.confidence = CASE
  WHEN 'shell_access' IN t.capability_surface THEN 1.0
  WHEN 'code_execution' IN t.capability_surface THEN 0.8
  ELSE 0.5
END,
e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
e.source_collector = 'mcp', e.risk_weight = 0.1
```

### 3.3 SHADOWS (Tool → Tool Cross-Server)

**Meaning:** Tool description references or attempts to influence a tool on another server.

```cypher
MATCH (s1:MCPServer)-[:PROVIDES_TOOL]->(t1:MCPTool)
MATCH (s2:MCPServer)-[:PROVIDES_TOOL]->(t2:MCPTool)
WHERE s1 <> s2
  AND (toLower(t1.description) CONTAINS toLower(t2.name) OR t1.has_cross_references = true)
MERGE (t1)-[e:SHADOWS]->(t2)
SET e.malicious_server = s1.name, e.victim_server = s2.name,
    e.confidence = CASE WHEN t1.has_injection_patterns = true THEN 0.9 ELSE 0.6 END,
    e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'mcp', e.risk_weight = 0.4
```

### 3.4 POISONED_DESCRIPTION (Tool Self-Edge)

```cypher
MATCH (t:MCPTool)
WHERE t.has_injection_patterns = true
MERGE (t)-[e:POISONED_DESCRIPTION]->(t)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'mcp'
```

### 3.5 CAN_REACH (Agent → Resource) — THE Critical Edge

**Direct path:**
```cypher
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
MERGE (a)-[e:CAN_REACH]->(r)
SET e.via_server = s.name, e.via_tool = t.name, e.hops = 3,
    e.confidence = CASE
      WHEN s.auth_method = 'none' THEN 1.0
      WHEN s.auth_method IN ['static_key', 'api_key'] THEN 0.8
      ELSE 0.5
    END,
    e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'mcp',
    e.evidence = 'Agent trusts ' + s.name + ' → ' + t.name + ' → ' + r.uri
```

**Credential chain path (extended CAN_REACH):**

Note: This path uses `HAS_ENV_VAR` edges (MCPServer → Credential) from the Config Collector. When a file-reading tool on Server1 can access files that contain credentials used by Server2, the agent can escalate through the credential chain.

```cypher
// Agent → Server1 (file reader) → Server1 has env var credentials → same credential → Identity → Server2 → Tool2 → Resource
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s1:MCPServer)
      -[:PROVIDES_TOOL]->(t1:MCPTool)
WHERE ANY(cap IN t1.capability_surface WHERE cap IN ['file_read', 'credential_access'])
MATCH (s2:MCPServer)-[:HAS_ENV_VAR]->(c:Credential)
MATCH (c)<-[:USES_CREDENTIAL]-(i:Identity)<-[:AUTHENTICATES_WITH]-(s2)
MATCH (s2)-[:PROVIDES_TOOL]->(t2:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE s1 <> s2 AND s1.auth_method IN ['none', 'static_key']
MERGE (a)-[e:CAN_REACH]->(r)
SET e.via_credential = c.name, e.hops = 6, e.confidence = 0.6,
    e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'mcp',
    e.evidence = 'Credential chain: ' + s1.name + ' (file access via ' + t1.name + ') → credential ' + c.name + ' → ' + s2.name + ' → ' + t2.name + ' → ' + r.uri
```

### 3.6 CAN_EXFILTRATE_VIA (Agent → Outbound Tool)

```cypher
MATCH (a:AgentInstance)-[:CAN_REACH]->(r:MCPResource)
WHERE r.sensitivity IN ['critical', 'high']
MATCH (a)-[:TRUSTS_SERVER]->(s:MCPServer)-[:PROVIDES_TOOL]->(outbound:MCPTool)
WHERE ANY(cap IN outbound.capability_surface WHERE cap IN ['email_send', 'network_outbound', 'file_write'])
MERGE (a)-[e:CAN_EXFILTRATE_VIA]->(outbound)
SET e.data_source = r.uri, e.data_sensitivity = r.sensitivity,
    e.exfil_channel = outbound.name,
    e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'mcp',
    e.evidence = 'Agent can reach ' + r.uri + ' AND exfiltrate via ' + outbound.name
```

### 3.7 CAN_IMPERSONATE (A2A → A2A)

Implemented in Go (not Cypher) because it requires TF-IDF cosine similarity:

```go
func (p *CanImpersonateProcessor) Process(ctx context.Context, db GraphDB, scanID string) (ProcessingStats, error) {
    // 1. Fetch all A2AAgent nodes with their skills
    agents, _ := db.Query(ctx,
        "MATCH (a:A2AAgent)-[:ADVERTISES_SKILL]->(s:A2ASkill) RETURN a, collect(s) AS skills", nil)

    // 2. For each pair of agents, compute skill description similarity
    for i, a := range agents {
        for j, b := range agents {
            if i >= j { continue }
            for _, skillA := range a.Skills {
                for _, skillB := range b.Skills {
                    sim := similarity.CosineSimilarity(
                        similarity.TFIDFVector(skillA.Description),
                        similarity.TFIDFVector(skillB.Description),
                    )
                    if sim > 0.8 {
                        // Write CAN_IMPERSONATE edge with source_collector = "a2a"
                    }
                }
            }
        }
    }
}
```

### 3.8 Cross-Protocol CAN_REACH (A2A → MCP)

```cypher
MATCH (ext:A2AAgent)-[:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[:RUNS_ON]->(h:Host)<-[:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE ext.auth_method = 'none'
MERGE (ext)-[e:CAN_REACH]->(r)
SET e.cross_protocol = true, e.via_mcp_server = s.name, e.via_mcp_tool = t.name,
    e.confidence = 0.5, e.scan_id = $scan_id, e.last_seen = datetime(),
    e.is_composite = true, e.source_collector = 'a2a',
    e.evidence = 'Cross-protocol: ' + ext.name + ' (A2A, no auth) → MCP server ' + s.name + ' → ' + t.name + ' → ' + r.uri
```

---

## 4. Risk Scoring (`internal/analysis/riskscore/`)

### 4.1 Edge Risk Weights (`weights.go`)

Assigned during post-processing on every edge:

| Edge Type | Condition | Risk Weight | Rationale |
|-----------|-----------|------------|-----------|
| TRUSTS_SERVER | auth_method = 'none' | 0.1 | No barrier |
| TRUSTS_SERVER | auth_method = 'static_key' | 0.3 | Key in config |
| TRUSTS_SERVER | auth_method = 'oauth' | 0.7 | Requires token |
| TRUSTS_SERVER | auth_method = 'mtls' | 0.9 | Requires cert |
| PROVIDES_TOOL | always | 0.1 | Available once server reached |
| HAS_ACCESS_TO | always | 0.2 | By design |
| CAN_EXECUTE | always | 0.1 | Direct shell |
| DELEGATES_TO | auth_method = 'none' | 0.1 | Open delegation |
| DELEGATES_TO | auth_method != 'none' | 0.5 | Requires cred |
| SHADOWS | always | 0.4 | Requires victim invocation |
| CAN_IMPERSONATE | always | 0.6 | Requires routing manipulation |

Lower weight = easier to exploit. Dijkstra finds minimum-weight path = maximum-risk path.

### 4.2 Node Risk Scores

**AgentInstance risk (0–100):**
```
agent_risk = 0.30 * credential_risk + 0.25 * blast_radius + 0.20 * auth_posture + 0.15 * tool_surface + 0.10 * poisoning_exposure
```

- `credential_risk`: max score across connected servers' credential handling
- `blast_radius`: count of critical resources reachable via CAN_REACH edges
- `auth_posture`: average auth strength of connected servers (inverted: none=100, mtls=10)
- `tool_surface`: weighted count of accessible tools by capability class
- `poisoning_exposure`: 100 if any connected tool is poisoned, 0 otherwise

**MCPServer risk (0–100):**
```
server_risk = 0.35 * auth_strength + 0.25 * tool_risk + 0.20 * exposure + 0.20 * credential_handling
```

**MCPTool risk (0–100):**
```
tool_risk = 0.30 * capability_class + 0.25 * poisoning_score + 0.25 * access_sensitivity + 0.20 * input_validation
```

### 4.3 Resource Sensitivity Auto-Classification (`sensitivity/classifier.go`)

| URI Pattern | Sensitivity |
|------------|-------------|
| `postgres://`, `mysql://`, `mongodb://` + prod patterns | critical |
| `file:///etc/`, `file:///root/`, `file:///*/.ssh/` | critical |
| `file:///*.env`, `*.key`, `*.pem`, `*.crt` | critical |
| `redis://` + prod | critical |
| Database URIs (non-prod) | high |
| `file:///` general | medium |
| `https://` external APIs | medium |
| Default | low |

---

## 5. Pathfinding API Endpoints

### 5.1 `POST /api/v1/analysis/shortest-path`

**Request:**
```json
{
  "source": { "kind": "AgentInstance", "name": "coding-assistant" },
  "target": { "kind": "MCPResource", "filter": { "sensitivity": "critical" } },
  "max_hops": 10,
  "algorithm": "shortest"
}
```

**Implementation:**
```go
func (h *AnalysisHandler) ShortestPath(w http.ResponseWriter, r *http.Request) {
    var req ShortestPathRequest
    json.NewDecoder(r.Body).Decode(&req)

    // Build Cypher based on algorithm
    var cypher string
    switch req.Algorithm {
    case "shortest":
        cypher = buildShortestPathQuery(req)
    case "all_shortest":
        cypher = buildAllShortestPathsQuery(req)
    case "weighted":
        cypher = buildWeightedPathQuery(req) // Uses APOC Dijkstra
    }

    results, _ := h.graphReader.Query(r.Context(), cypher, params)
    paths := convertToPathResponse(results)
    json.NewEncoder(w).Encode(paths)
}
```

**Cypher for shortest path (Neo4j 4.4 compatible):**
```cypher
MATCH (source {name: $source_name})
WHERE $source_kind IN labels(source)
MATCH (target)
WHERE $target_kind IN labels(target) AND target.sensitivity = $sensitivity
MATCH p = shortestPath((source)-[*1..$max_hops]->(target))
RETURN [n IN nodes(p) | {id: n.objectid, kind: labels(n)[0], name: coalesce(n.name, n.uri, 'unknown'), properties: properties(n)}] AS nodes,
       [r IN relationships(p) | {kind: type(r), risk_weight: coalesce(r.risk_weight, 0.5), properties: properties(r)}] AS edges,
       length(p) AS hops
ORDER BY hops ASC
LIMIT 10
```

### 5.2 `POST /api/v1/analysis/all-paths`

Bounded path enumeration:
```cypher
MATCH p = (source)-[*1..$max_hops]->(target)
WHERE $source_kind IN labels(source) AND source.name = $source_name
  AND $target_kind IN labels(target)
RETURN p
LIMIT $limit
```

### 5.3 `POST /api/v1/analysis/weighted-path`

Uses APOC Dijkstra for path of least resistance:
```cypher
MATCH (source {name: $source_name})
WHERE $source_kind IN labels(source)
MATCH (target)
WHERE $target_kind IN labels(target) AND target.sensitivity = $sensitivity
CALL apoc.algo.dijkstra(source, target, 'TRUSTS_SERVER|PROVIDES_TOOL|HAS_ACCESS_TO|CAN_EXECUTE|DELEGATES_TO', 'risk_weight')
YIELD path, weight
RETURN path, weight
LIMIT 10
```

### 5.4 `GET /api/v1/analysis/findings`

Returns all composite edges as security findings:
```go
type Finding struct {
    ID          string `json:"id"`
    Severity    string `json:"severity"`    // critical, high, medium, low, info
    Category    string `json:"category"`    // OWASP mapping
    Title       string `json:"title"`
    Description string `json:"description"`
    Evidence    string `json:"evidence"`
    SourceNode  Node   `json:"source_node"`
    TargetNode  Node   `json:"target_node"`
    EdgeKind    string `json:"edge_kind"`
}
```

Severity mapping:
- CAN_REACH to critical resource with no auth: **Critical**
- CAN_EXFILTRATE_VIA: **Critical**
- Cross-protocol CAN_REACH: **Critical**
- POISONED_DESCRIPTION: **High**
- SHADOWS: **High**
- WEAK_AUTH (no auth): **High**
- WEAK_AUTH (static key): **Medium**
- CAN_IMPERSONATE: **Medium**

### 5.5 `GET /api/v1/analysis/prebuilt/{query_id}`

Pre-built query library — 17 queries from PRD `05-attack-paths.md`:

| ID | Name | Category |
|----|------|----------|
| `agents-shell-access` | Agents with direct shell access | Critical Paths |
| `shortest-to-database` | Shortest path from any agent to any database | Critical Paths |
| `cross-protocol-paths` | Cross-protocol attack paths (A2A → MCP) | Critical Paths |
| `exfiltration-routes` | Data exfiltration routes | Critical Paths |
| `credential-chain` | Credential chain escalation | Critical Paths |
| `poisoned-tools` | Tools with injection patterns | Vulnerabilities |
| `tool-shadowing` | Cross-origin tool shadowing | Vulnerabilities |
| `no-auth-servers` | Servers with no authentication | Vulnerabilities |
| `no-auth-a2a` | A2A agents with no auth | Vulnerabilities |
| `rug-pull` | Tool descriptions changed between scans | Vulnerabilities |
| `unpinned-packages` | Unpinned MCP server packages | Supply Chain |
| `instruction-poisoning` | Suspicious instruction files | Supply Chain |
| `unsigned-cards` | Unsigned A2A Agent Cards | Supply Chain |
| `high-entropy-secrets` | High-entropy env var values | Supply Chain |
| `chokepoint-servers` | Most-connected servers (single points of failure) | Chokepoints |
| `chokepoint-tools` | Tools on most attack paths | Chokepoints |
| `unpinned-shell` | Agents trusting unpinned servers with shell access | Combined |

Each pre-built query is stored as a struct:
```go
type PreBuiltQuery struct {
    ID          string
    Name        string
    Description string
    Category    string
    Severity    string
    Cypher      string
    OWASPMap    []string // e.g., ["MCP03", "ASI02"]
}
```

---

## 6. CLI Query Mode

### 6.1 `agenthound query`

```bash
# Raw Cypher query
agenthound query "MATCH (n:MCPServer) RETURN n.name, n.auth_method"

# Pre-built query
agenthound query --prebuilt agents-shell-access

# Shortest path
agenthound query --shortest-path \
  --from "AgentInstance:coding-assistant" \
  --to "MCPResource:production-db"

# All findings
agenthound query --findings --severity critical
```

**Output format:** Table by default, `--format json` for JSON.

---

## 7. Integration with Ingest Pipeline

Update `internal/ingest/pipeline.go` to trigger post-processing after each ingest:

```go
func (p *Pipeline) Ingest(ctx context.Context, data *model.IngestData) (*IngestResult, error) {
    // ... existing validation, normalization, write ...

    // NEW: Run post-processing
    if err := analysis.RunPostProcessors(ctx, p.graphDB, data.Meta.ScanID); err != nil {
        slog.Error("post-processing failed", "error", err)
        // Non-fatal — raw data is already ingested
    }

    return result, nil
}
```

---

## 8. Tests

### Unit Tests

| Test | What It Validates |
|------|-------------------|
| `TestHasAccessToCapabilityMatch` | Database tool → database resource gets edge |
| `TestHasAccessToNameMatch` | Tool description mentions resource name → edge |
| `TestHasAccessToNoMatch` | Unrelated tool and resource → no edge |
| `TestCanExecuteShellAccess` | shell_access tool → host edge |
| `TestShadowsCrossServer` | Tool1 mentions Tool2 name from different server → SHADOWS edge |
| `TestShadowsSameServer` | Tool1 mentions Tool2 on same server → no SHADOWS edge |
| `TestPoisonedDescription` | Tool with injection patterns → self-edge |
| `TestCanReachDirect` | Agent → Server (no auth) → Tool → Resource → CAN_REACH edge |
| `TestCanReachCredentialChain` | Agent → Server1 → Tool → Credential → Server2 → Resource |
| `TestCanExfiltrate` | Agent reaches critical resource AND outbound tool → CAN_EXFILTRATE_VIA |
| `TestRiskScoreAgent` | Agent with no-auth servers scores higher than OAuth-only |
| `TestRiskScoreTool` | Shell access tool scores higher than read-only |
| `TestSensitivityClassifier` | postgres:// → critical, file:/// → medium |
| `TestEdgeRiskWeights` | Correct weights per edge type and auth method |
| `TestTFIDFSimilarity` | Similar skill descriptions → high cosine similarity |

### Integration Tests (require Neo4j)

| Test | Setup | Verification |
|------|-------|-------------|
| `TestFullPostProcessing` | Ingest all 3 test scans → run post-processors | CAN_REACH, CAN_EXFILTRATE_VIA edges exist |
| `TestShortestPathAPI` | Seeded graph with known path | API returns correct 3-hop path |
| `TestWeightedPathAPI` | Graph with multiple paths of different weights | Dijkstra returns minimum-weight path |
| `TestPreBuiltQueries` | Seeded graph | Each pre-built query returns expected results |
| `TestFindingsAPI` | Seeded graph with known vulns | Correct findings with severity |
| `TestStaleEdgeCleanup` | Run post-processing twice with different scan_ids | Old composite edges removed |
| `TestCrossProtocolPath` | A2A agent + MCP data on same host | Cross-protocol CAN_REACH edge created |

---

## 9. Success Metrics / Exit Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| 1 | After scanning a test environment with known attack paths, AgentHound correctly identifies all paths | Pre-seeded graph, run all pre-built queries, verify expected results |
| 2 | CAN_REACH edges exist for every Agent→Resource path that traverses trust + capability edges | Count CAN_REACH edges matches expected |
| 3 | CAN_EXFILTRATE_VIA edges exist where agent reaches sensitive data AND outbound channel | At least 1 exfiltration finding in test data |
| 4 | SHADOWS edges detect cross-server tool description references | Test with known shadowing tool description |
| 5 | Risk scores are non-zero and correctly ordered (no-auth server > OAuth server) | Compare risk scores in test data |
| 6 | `POST /api/v1/analysis/shortest-path` returns correct paths | API integration test |
| 7 | Dijkstra weighted path returns path of least resistance | API test with multiple paths |
| 8 | All 17 pre-built queries execute without error | Run each against seeded graph |
| 9 | `agenthound query --prebuilt agents-shell-access` returns results in table format | CLI test |
| 10 | Post-processing completes in < 5 seconds for a graph with 500 nodes and 2000 edges | Performance benchmark |
| 11 | Stale composite edges from previous scans are cleaned up | Verify old scan_id edges removed |

---

## 10. Risks and Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| APOC plugin not installed in Neo4j | Medium | All core post-processors use native Cypher. APOC only needed for Dijkstra (weighted path). Fall back to client-side Dijkstra if APOC unavailable. |
| Large graph makes post-processing slow | Low | Agent graphs are small (100s-1000s of nodes). If slow, add indexes and optimize Cypher. |
| Cross-protocol correlation (A2A ↔ MCP via host) produces false positives | Medium | Confidence=0.5 on cross-protocol edges. UI flags as "inferred." |
| TF-IDF similarity for CAN_IMPERSONATE is noisy | Medium | High threshold (0.8). Can be tuned per deployment. |
| Neo4j 4.4 Cypher limitations vs 5.x | Low | All queries use 4.4-compatible syntax. 5.x features (quantified paths) are optional. |

---

## 11. External References

| Resource | URL | Relevance |
|----------|-----|-----------|
| Neo4j shortestPath docs | https://neo4j.com/docs/cypher-manual/4.4/clauses/match/#query-shortest-path | Native BFS pathfinding |
| APOC Dijkstra | https://neo4j.com/labs/apoc/4.4/algorithms/path-finding-procedures/ | Weighted path |
| BloodHound post-processing | https://github.com/SpecterOps/BloodHound/tree/main/packages/go/analysis | Pattern reference |
| OWASP MCP Top 10 | https://owasp.org/www-project-mcp-top-10/ | Finding taxonomy |
| OWASP Agentic Top 10 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ | Finding taxonomy |

---

## 12. Additional Processors & Infrastructure

### 12.1 GraphDB Interface Definition

The `GraphDB` type referenced by all post-processors is defined in `internal/graph/`:

```go
// internal/graph/graphdb.go
type GraphDB interface {
    Query(ctx context.Context, cypher string, params map[string]interface{}) ([]map[string]interface{}, error)
    WriteEdges(ctx context.Context, edges []model.Edge, scanID string) (int, error)
    UpdateNodeProperties(ctx context.Context, objectID string, props map[string]interface{}) error
    GetNode(ctx context.Context, objectID string) (*model.Node, error)
    ExecuteWrite(ctx context.Context, cypher string, params map[string]interface{}) (int, error)
}
```

`UpdateNodeProperties` is needed by `RiskScoreProcessor` to write risk scores back to nodes. `ExecuteWrite` runs post-processor Cypher that creates composite edges.

### 12.2 WEAK_AUTH Processor (Missing from Main List)

Add `processors/weak_auth.go`:

```cypher
// Flag MCP servers with no auth or static keys
MATCH (s:MCPServer)
WHERE s.auth_method IN ['none', 'static_key', 'api_key']
SET s.weak_auth = true, s.weak_auth_severity = CASE
  WHEN s.auth_method = 'none' THEN 'critical'
  WHEN s.auth_method IN ['static_key', 'api_key'] THEN 'medium'
END

// Flag A2A agents with no auth
MATCH (a:A2AAgent)
WHERE a.auth_method = 'none' OR a.has_auth = false
SET a.weak_auth = true, a.weak_auth_severity = 'critical'
```

Note: WEAK_AUTH is implemented as a **node property** rather than an edge, since it's a property of the server/agent itself. The `AllowedEdgeKinds` entry has been removed from Phase 1.

### 12.3 Rug Pull / Historical Property Tracking

To support rug-pull detection (comparing `description_hash` across scans), the ingest writer must preserve the previous hash before overwriting:

```go
// In graph/writer.go, before MERGE:
// 1. Query existing node's description_hash
// 2. Store as previous_description_hash before SET

// Cypher:
UNWIND $nodes AS node
MERGE (n:MCPTool {objectid: node.id})
ON MATCH SET n.previous_description_hash = n.description_hash
SET n += node.properties, n.scan_id = $scan_id, n.last_seen = datetime()
```

The `ON MATCH SET` clause runs only when the node already exists, preserving the old `description_hash` as `previous_description_hash` before the new properties overwrite it.

### 12.4 Scan Management Endpoints

Add to Phase 1's API router and implement handlers:

```go
r.Route("/api/v1/scans", func(r chi.Router) {
    r.Get("/", handlers.ListScans)        // List scan history from PostgreSQL
    r.Post("/", handlers.TriggerScan)     // Queue a new scan
    r.Get("/{id}", handlers.GetScan)      // Get scan status/details
})
```

`TriggerScan` runs the collector as a subprocess via `os/exec`, writes output to a temp file, then calls the ingest pipeline. Scan status tracked in PostgreSQL `scans` table.

```go
func (h *ScanHandler) TriggerScan(w http.ResponseWriter, r *http.Request) {
    var req TriggerScanRequest // { type: "mcp"|"a2a"|"config"|"full", options: {...} }
    // 1. Create scan record in PostgreSQL (status: running)
    // 2. Launch collector as goroutine
    // 3. Return scan ID immediately (async)
    // 4. Goroutine: run collector → ingest → post-process → update scan status
}
```
