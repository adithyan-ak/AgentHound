# Graph Construction Pipeline — Technical Implementation Specification

## 1. Purpose

This document specifies how three isolated collector outputs merge into a single directed graph, how post-processing computes composite edges (`CAN_REACH`, `CAN_EXFILTRATE_VIA`, `SHADOWS`, `POISONED_DESCRIPTION`), and how shortest-path queries discover attack chains across MCP and A2A protocol boundaries.

**This is the core value of AgentHound.** Existing tools (Cisco MCP Scanner, Snyk agent-scan, Cisco A2A Scanner) scan individual servers or agents. None of them construct the cross-protocol trust graph. None of them find the path from "external A2A agent" through "MCP server" through "tool" to "production database." This document specifies exactly how that works.

## 2. Architecture — Three Phases

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ MCP Collector│  │ A2A Collector│  │Config Collect│
│   (JSON)    │  │   (JSON)    │  │   (JSON)    │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
              ┌─────────▼─────────┐
              │  PHASE 1: INGEST  │
              │  Validate, Merge, │
              │  Deduplicate,     │
              │  Write to Neo4j   │
              └─────────┬─────────┘
                        │
              ┌─────────▼─────────┐
              │  PHASE 2: POST-   │
              │  PROCESSING       │
              │  Compute composite│
              │  edges from raw   │
              │  graph state      │
              └─────────┬─────────┘
                        │
              ┌─────────▼─────────┐
              │  PHASE 3: QUERY   │
              │  Shortest path,   │
              │  weighted path,   │
              │  pre-built attack │
              │  path queries     │
              └───────────────────┘
```

## 3. Phase 1: Ingest Pipeline

### 3.1 Input Format

All three collectors produce JSON in the same standardized format:

```json
{
  "meta": {
    "version": 1,
    "type": "agenthound-ingest",
    "collector": "mcp|a2a|config",
    "collector_version": "0.1.0",
    "timestamp": "2026-04-06T10:30:00Z",
    "scan_id": "scan-abc123"
  },
  "graph": {
    "nodes": [
      {
        "id": "sha256:abc123...",
        "kinds": ["MCPServer"],
        "properties": { ... }
      }
    ],
    "edges": [
      {
        "source": "sha256:abc123...",
        "target": "sha256:def456...",
        "kind": "PROVIDES_TOOL",
        "properties": {
          "scan_id": "scan-abc123",
          "last_seen": "2026-04-06T10:30:00Z",
          "confidence": 1.0
        }
      }
    ]
  }
}
```

This format is deliberately aligned with [BloodHound OpenGraph's JSON schema](https://bloodhound.specterops.io/opengraph/schema):
- Nodes have `id`, `kinds[]`, and `properties`
- Edges have `source`, `target`, `kind`, and `properties`
- Edge `kind` values are PascalCase with underscores (e.g., `PROVIDES_TOOL`) — conforming to BloodHound's validation pattern `^[A-Za-z0-9_]+$`

Source: [BloodHound OpenGraph Schema](https://bloodhound.specterops.io/opengraph/schema)

### 3.2 Merge Strategy — How Isolated Collectors Become One Graph

The three collectors run independently and may produce overlapping node references. The merge works because of **deterministic, content-based node IDs**.

**The critical merge point is MCPServer nodes.** Both the Config Collector and the MCP Collector produce MCPServer nodes. They MUST generate the same `id` for the same server:

```
MCPServer ID = SHA-256(transport + ":" + endpoint_or_command + ":" + sorted_args_hash)
```

Example: A server configured as `{"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres"], "env": {"POSTGRES_URL": "..."}}`

- Config Collector sees: transport=stdio, command=npx, args=[-y, @modelcontextprotocol/server-postgres]
- MCP Collector connects to that same server via stdio
- Both compute: `SHA-256("stdio:npx:-y,@modelcontextprotocol/server-postgres")` → same ID

**When nodes with the same ID are ingested from different collectors, properties merge:**
- Config Collector writes: `{name, transport, endpoint, args}` (from config file)
- MCP Collector writes: `{protocolVersion, capabilities, serverInfo, instructions}` (from initialize handshake)
- Result: single MCPServer node with all properties from both collectors

This is the same merge behavior [BloodHound uses](https://specterops.io/blog/2025/08/04/adding-mssql-to-bloodhound-with-opengraph/): "BloodHound ingestion will make properties merge with existing nodes, otherwise it creates new nodes."

### 3.3 Ingest Pipeline Steps

```
1. VALIDATE
   - Parse JSON, validate against AgentHound ingest schema
   - Reject malformed files with specific error messages
   - Validate edge kinds match allowed set (PROVIDES_TOOL, TRUSTS_SERVER, etc.)
   - Validate node kinds match allowed set (MCPServer, MCPTool, A2AAgent, etc.)

2. NORMALIZE
   - Ensure all node IDs are present and deterministic
   - Ensure all edge source/target IDs reference valid nodes
   - Lowercase all property keys (Neo4j is case-sensitive)
   - Convert timestamps to ISO 8601

3. DEDUPLICATE
   - For each node: MERGE by id — if exists, update properties; if not, create
   - For each edge: MERGE by (source_id, target_id, kind) — update properties if exists
   - Properties from later scans overwrite earlier scans (last-write-wins)
   - But: previous_description_hash is preserved for rug pull detection

4. WRITE TO NEO4J
   - Batch writes using Neo4j transactions (1000 operations per transaction)
   - Use Cypher MERGE for idempotent upserts:

   MERGE (n:MCPServer {objectid: $id})
   SET n += $properties, n.last_seen = $timestamp

   MERGE (a)-[r:PROVIDES_TOOL]->(b)
   WHERE a.objectid = $source AND b.objectid = $target
   SET r += $edge_properties

5. RECORD SCAN METADATA
   - Write scan record to PostgreSQL: scan_id, collector, timestamp, node_count, edge_count
   - Update scan_id on all written nodes/edges for temporal tracking
```

### 3.4 Neo4j Schema (Created at First Boot)

Schema initialization detects Neo4j version and uses the appropriate syntax. See `plan/phase01.md` Section 4.1 for both Neo4j 5.x (`FOR...REQUIRE`) and 4.4 (`ON...ASSERT`) constraint variants.

```cypher
// Neo4j 5.x syntax (use ON...ASSERT for 4.4):
CREATE CONSTRAINT FOR (n:MCPServer) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:MCPTool) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:MCPResource) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:MCPPrompt) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:A2AAgent) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:A2ASkill) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:AgentInstance) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:Identity) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:Credential) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:Host) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:ConfigFile) REQUIRE n.objectid IS UNIQUE;

// Indexes for common lookups
CREATE INDEX FOR (n:MCPServer) ON (n.name);
CREATE INDEX FOR (n:MCPTool) ON (n.name);
CREATE INDEX FOR (n:MCPTool) ON (n.description_hash);
CREATE INDEX FOR (n:A2AAgent) ON (n.name);
CREATE INDEX FOR (n:A2AAgent) ON (n.url);
CREATE INDEX FOR (n:MCPResource) ON (n.uri);
CREATE INDEX FOR (n:MCPResource) ON (n.sensitivity);
```

## 4. What the Merged Graph Looks Like

After ingesting output from all three collectors, the graph contains these edges:

### Directly Collected Edges (from collectors)

| Edge | Source → Target | Which Collector |
|------|----------------|----------------|
| `TRUSTS_SERVER` | AgentInstance → MCPServer | **Config** |
| `PROVIDES_TOOL` | MCPServer → MCPTool | **MCP** |
| `PROVIDES_RESOURCE` | MCPServer → MCPResource | **MCP** |
| `PROVIDES_PROMPT` | MCPServer → MCPPrompt | **MCP** |
| `CONFIGURED_IN` | MCPServer → ConfigFile | **Config** |
| `AUTHENTICATES_WITH` | MCPServer → Identity | **Config** |
| `USES_CREDENTIAL` | Identity → Credential | **Config** |
| `RUNS_ON` | MCPServer → Host | **Config** |
| `HAS_ENV_VAR` | MCPServer → Credential | **Config** |
| `ADVERTISES_SKILL` | A2AAgent → A2ASkill | **A2A** |
| `DELEGATES_TO` | A2AAgent → A2AAgent | **A2A** |
| `SAME_AUTH_DOMAIN` | A2AAgent → A2AAgent | **A2A** |

**The MCPServer node is the merge point.** Config Collector creates the MCPServer node (with config metadata) and the `TRUSTS_SERVER` edge from AgentInstance. MCP Collector enriches the same MCPServer node (with protocol metadata) and adds `PROVIDES_TOOL`/`PROVIDES_RESOURCE` edges. Same node ID → merged.

### Why This Merge Matters

Without the merge, you have three disconnected subgraphs:
- Config: `AgentInstance → MCPServer` (trust, but no capabilities)
- MCP: `MCPServer → MCPTool → MCPResource` (capabilities, but no trust context)
- A2A: `A2AAgent → A2ASkill` (skills, but no MCP connection)

After merge:
```
AgentInstance → MCPServer → MCPTool → MCPResource
```

This connected path is the foundation of every attack path query.

## 5. Phase 2: Post-Processing — Computing Composite Edges

Post-processing runs **after each ingest**. It queries the current graph state and computes derived edges that encode multi-hop attack semantics in a single queryable relationship.

This follows [BloodHound's post-processing pattern](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/analysis/ad/owns.go): raw edges are collected, then a Go analysis pass reads the graph, evaluates conditions, and writes composite edges. BloodHound's `PostOwnsAndWriteOwner` function demonstrates the three-phase pattern:
1. **Query**: Fetch raw relationships with graph filters
2. **Compute**: Evaluate conditional logic per relationship
3. **Write**: Submit computed edges through buffered channels

AgentHound follows the same pattern for each composite edge type.

### 5.1 `HAS_ACCESS_TO` — Tool-to-Resource Access

**What it means:** This MCPTool can read or write this MCPResource.

**How it's computed:**
```cypher
// For each tool, check if any resource on the same server
// has a URI scheme matching the tool's capability surface
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
MATCH (s)-[:PROVIDES_RESOURCE]->(r:MCPResource)
WHERE
  // Tool has database_access capability and resource is a DB URI
  ('database_access' IN t.capability_surface AND r.uri_scheme IN ['postgres', 'mysql', 'mongodb', 'sqlite'])
  OR
  // Tool has file_read/file_write and resource is a file URI
  (ANY(cap IN t.capability_surface WHERE cap IN ['file_read', 'file_write']) AND r.uri_scheme = 'file')
  OR
  // Tool description explicitly mentions the resource name or URI
  (t.description CONTAINS r.name)
MERGE (t)-[e:HAS_ACCESS_TO]->(r)
SET e.confidence = CASE
  WHEN t.description CONTAINS r.name THEN 0.9
  WHEN t.description CONTAINS r.uri_scheme THEN 0.7
  ELSE 0.5
END,
e.scan_id = $scan_id,
e.last_seen = datetime(),
e.is_composite = true
```

**Confidence scoring:**
- 0.9: Tool description explicitly names the resource
- 0.7: Tool capability surface matches resource URI scheme
- 0.5: Inferred from co-location on same server

### 5.2 `CAN_EXECUTE` — Tool Has Shell Access

**What it means:** This MCPTool can execute arbitrary commands on this Host.

**How it's computed:**
```cypher
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
MATCH (s)-[:RUNS_ON]->(h:Host)
WHERE 'shell_access' IN t.capability_surface
   OR 'code_execution' IN t.capability_surface
MERGE (t)-[e:CAN_EXECUTE]->(h)
SET e.confidence = CASE
  WHEN 'shell_access' IN t.capability_surface THEN 1.0
  WHEN 'code_execution' IN t.capability_surface THEN 0.8
  ELSE 0.5
END,
e.scan_id = $scan_id,
e.last_seen = datetime(),
e.is_composite = true
```

### 5.3 `CAN_REACH` — Transitive Access (The Critical Edge)

**What it means:** This AgentInstance can transitively reach this MCPResource through its trust chain.

**This is the highest-value composite edge.** It collapses multi-hop paths into a single queryable relationship.

**How it's computed:**
```cypher
// Find all paths: Agent → Server (via TRUSTS_SERVER) → Tool → Resource
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
MERGE (a)-[e:CAN_REACH]->(r)
SET e.via_server = s.name,
    e.via_tool = t.name,
    e.hops = 3,
    e.confidence = CASE
      WHEN s.auth_method = 'none' THEN 1.0
      WHEN s.auth_method = 'static_key' THEN 0.8
      ELSE 0.5
    END,
    e.scan_id = $scan_id,
    e.last_seen = datetime(),
    e.is_composite = true,
    e.evidence = 'Agent trusts ' + s.name + ' which provides ' + t.name +
                 ' which has access to ' + r.uri
```

**Extended CAN_REACH through credential chains:**
```cypher
// Agent → Server1 → Tool (reads file) → Credential → Identity → Server2 → Tool2 → Resource
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s1:MCPServer)
      -[:PROVIDES_TOOL]->(t1:MCPTool)-[:HAS_ACCESS_TO]->(c:Credential)
MATCH (c)<-[:USES_CREDENTIAL]-(i:Identity)<-[:AUTHENTICATES_WITH]-(s2:MCPServer)
      -[:PROVIDES_TOOL]->(t2:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE s1 <> s2
MERGE (a)-[e:CAN_REACH]->(r)
SET e.via_credential = c.name,
    e.hops = 6,
    e.confidence = 0.6,
    e.scan_id = $scan_id,
    e.last_seen = datetime(),
    e.is_composite = true,
    e.evidence = 'Credential chain: ' + s1.name + ' → ' + t1.name +
                 ' → credential ' + c.name + ' → ' + s2.name + ' → ' + t2.name +
                 ' → ' + r.uri
```

### 5.4 `CAN_EXFILTRATE_VIA` — Data Exfiltration Path (The Other Critical Edge)

**What it means:** This AgentInstance can reach sensitive data AND has access to an outbound communication channel, enabling data exfiltration.

**How it's computed:**
```cypher
// Agent can reach a sensitive resource
MATCH (a:AgentInstance)-[:CAN_REACH]->(r:MCPResource)
WHERE r.sensitivity IN ['critical', 'high']
// AND the same agent can reach an outbound tool
MATCH (a)-[:TRUSTS_SERVER]->(s:MCPServer)-[:PROVIDES_TOOL]->(outbound:MCPTool)
WHERE ANY(cap IN outbound.capability_surface
          WHERE cap IN ['email_send', 'network_outbound', 'file_write'])
MERGE (a)-[e:CAN_EXFILTRATE_VIA]->(outbound)
SET e.data_source = r.uri,
    e.data_sensitivity = r.sensitivity,
    e.exfil_channel = outbound.name,
    e.exfil_capability = [cap IN outbound.capability_surface
                          WHERE cap IN ['email_send', 'network_outbound', 'file_write']][0],
    e.scan_id = $scan_id,
    e.last_seen = datetime(),
    e.is_composite = true,
    e.evidence = 'Agent can reach ' + r.uri + ' (sensitivity: ' + r.sensitivity +
                 ') and exfiltrate via ' + outbound.name + ' (' + e.exfil_capability + ')'
```

**Why this matters:** This is the finding that makes security teams act. "Your coding assistant can read the production database AND send Slack messages" = data exfiltration path.

### 5.5 `SHADOWS` — Cross-Origin Tool Shadowing

**What it means:** A tool's description references or attempts to influence behavior of a tool on a different server.

Source: [OWASP MCP03:2025 - Tool Poisoning](https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning) defines schema poisoning where "an adversary tampers with the contract or schema definitions that govern agent-to-tool interactions." Tool shadowing is a form of this where one tool's description manipulates how another tool is used.

Source: [Invariant Labs - Tool Poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) demonstrated that "hidden malicious instructions embedded in MCP tool descriptions" can "manipulate AI models into performing unauthorized actions."

**How it's computed:**
```cypher
// Find tools whose descriptions mention other tools by name
MATCH (s1:MCPServer)-[:PROVIDES_TOOL]->(t1:MCPTool)
MATCH (s2:MCPServer)-[:PROVIDES_TOOL]->(t2:MCPTool)
WHERE s1 <> s2
  AND (
    // t1's description mentions t2's name
    toLower(t1.description) CONTAINS toLower(t2.name)
    OR
    // t1's description contains imperative instructions about t2
    // (detected during collection as has_cross_references = true)
    t1.has_cross_references = true
  )
MERGE (t1)-[e:SHADOWS]->(t2)
SET e.malicious_server = s1.name,
    e.victim_server = s2.name,
    e.confidence = CASE
      WHEN t1.has_injection_patterns = true THEN 0.9
      ELSE 0.6
    END,
    e.scan_id = $scan_id,
    e.last_seen = datetime(),
    e.is_composite = true
```

### 5.6 `POISONED_DESCRIPTION` — Tool Description Contains Injection

**How it's computed:**
```cypher
MATCH (t:MCPTool)
WHERE t.has_injection_patterns = true
MERGE (t)-[e:POISONED_DESCRIPTION]->(t)
SET e.scan_id = $scan_id,
    e.last_seen = datetime(),
    e.is_composite = true
```

This is a self-referential edge (loop) — the tool node has a poisoning finding attached to it.

### 5.7 `CAN_IMPERSONATE` — A2A Agent Capability Overlap

**What it means:** An A2A agent's skill descriptions overlap suspiciously with another agent's skills, potentially enabling Agent-in-the-Middle (AITM) attacks.

Source: [Hacker News / MCP and A2A vulnerabilities](https://thehackernews.com/2025/04/experts-uncover-critical-mcp-and-a2a.html) describes how "an attacker who compromises an agent can craft a misleading Agent Card that exaggerates its capabilities, causing the host agent to route all requests to a rogue AI agent."

**How it's computed (in Go, not Cypher — requires string similarity):**

```go
// Pseudo-code for the Go post-processor
func computeCanImpersonate(agents []A2AAgent) []Edge {
    var edges []Edge
    for i, a := range agents {
        for j, b := range agents {
            if i == j { continue }
            for _, skillA := range a.Skills {
                for _, skillB := range b.Skills {
                    similarity := cosineSimilarity(
                        tfidfVector(skillA.Description),
                        tfidfVector(skillB.Description),
                    )
                    if similarity > 0.8 { // high overlap threshold
                        edges = append(edges, Edge{
                            Source: a.ID,
                            Target: b.ID,
                            Kind:   "CAN_IMPERSONATE",
                            Properties: map[string]interface{}{
                                "similarity":     similarity,
                                "skill_a":        skillA.Name,
                                "skill_b":        skillB.Name,
                                "confidence":     similarity,
                                "is_composite":   true,
                            },
                        })
                    }
                }
            }
        }
    }
    return edges
}
```

### 5.8 Cross-Protocol Composite Edges (A2A → MCP)

These are the edges that NO existing tool computes. They bridge the A2A and MCP protocol boundaries.

**Pattern: A2A Agent → MCP Resource via delegation + trust chain**

This requires correlating data from all three collectors:
1. A2A Collector: Agent A `DELEGATES_TO` Agent B
2. Config Collector: Agent B (as an AgentInstance) `TRUSTS_SERVER` MCP Server X
3. MCP Collector: MCP Server X `PROVIDES_TOOL` Tool Y which `HAS_ACCESS_TO` Resource Z

The correlation between A2A Agent B and AgentInstance B happens via:
- Same hostname/IP (A2A agent URL resolves to same host running the MCP client)
- Explicit configuration linking (future: config declares which A2A agent identity maps to which MCP client)
- Shared credentials (same OAuth token URL used by A2A agent and MCP server)

```cypher
// Cross-protocol: External A2A agent can reach MCP resources
// via delegation through an internal agent that trusts MCP servers
MATCH (ext:A2AAgent)-[:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (ai:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
// Correlation: internal A2A agent runs on same host as the MCP-connected agent
MATCH (int)-[:RUNS_ON]->(h:Host)<-[:RUNS_ON]-(s)
WHERE ext.auth_method = 'none'  // external agent has no auth = easy entry point
MERGE (ext)-[e:CAN_REACH]->(r)
SET e.cross_protocol = true,
    e.via_a2a_delegation = [a IN nodes(path) WHERE a:A2AAgent | a.name],
    e.via_mcp_server = s.name,
    e.via_mcp_tool = t.name,
    e.confidence = 0.5,  // lower confidence due to correlation inference
    e.scan_id = $scan_id,
    e.last_seen = datetime(),
    e.is_composite = true,
    e.evidence = 'Cross-protocol: ' + ext.name + ' (A2A, no auth) delegates to ' +
                 int.name + ' which trusts MCP server ' + s.name +
                 ' providing ' + t.name + ' with access to ' + r.uri
```

### 5.9 Post-Processor Execution Order

Composite edges depend on each other. Execution must be ordered:

```
1. HAS_ACCESS_TO      (Tool → Resource)         — depends on: raw edges only
2. CAN_EXECUTE         (Tool → Host)             — depends on: raw edges only
3. SHADOWS             (Tool → Tool)             — depends on: raw edges only
4. POISONED_DESCRIPTION (Tool → Tool self-edge)  — depends on: raw edges only
5. CAN_REACH           (Agent → Resource)        — depends on: HAS_ACCESS_TO
6. CAN_EXFILTRATE_VIA  (Agent → Tool)           — depends on: CAN_REACH
7. CAN_IMPERSONATE     (A2AAgent → A2AAgent)    — depends on: raw edges only
8. Cross-protocol CAN_REACH                      — depends on: HAS_ACCESS_TO, DELEGATES_TO
```

### 5.10 Post-Processor Go Architecture

Following [BloodHound's pattern](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/analysis/ad/owns.go):

```go
type PostProcessor interface {
    Name() string
    Dependencies() []string // Names of post-processors that must run first
    Process(ctx context.Context, graphDB GraphDB, scanID string) (ProcessingStats, error)
}

type ProcessingStats struct {
    EdgesCreated  int
    EdgesUpdated  int
    EdgesDeleted  int
    Duration      time.Duration
}

// Each composite edge type is a PostProcessor implementation:
// - HasAccessToProcessor
// - CanExecuteProcessor
// - ShadowsProcessor
// - PoisonedDescriptionProcessor
// - CanReachProcessor
// - CanExfiltrateViaProcessor
// - CanImpersonateProcessor
// - CrossProtocolReachProcessor

func RunPostProcessors(ctx context.Context, graphDB GraphDB, scanID string) error {
    processors := []PostProcessor{
        &HasAccessToProcessor{},
        &CanExecuteProcessor{},
        &ShadowsProcessor{},
        &PoisonedDescriptionProcessor{},
        &CanReachProcessor{},          // depends on HasAccessTo
        &CanExfiltrateViaProcessor{},  // depends on CanReach
        &CanImpersonateProcessor{},
        &CrossProtocolReachProcessor{}, // depends on HasAccessTo
    }

    // Topological sort by dependencies, then execute in order
    sorted := topologicalSort(processors)
    for _, p := range sorted {
        stats, err := p.Process(ctx, graphDB, scanID)
        if err != nil { return fmt.Errorf("post-processor %s: %w", p.Name(), err) }
        log.Info("post-processor", "name", p.Name(),
                 "created", stats.EdgesCreated, "duration", stats.Duration)
    }

    // Clean up stale composite edges from previous scans
    cleanupStaleEdges(ctx, graphDB, scanID)
    return nil
}
```

**Stale edge cleanup:** Before writing new composite edges, delete composite edges from previous scans that are no longer valid. This mirrors BloodHound's behavior: "Before regenerating post-processed edges, BloodHound deletes any existing ones."

## 6. Phase 3: Attack Path Queries

### 6.1 How Shortest Path Works in This Graph

In the AgentHound graph, **every edge represents an exploitable relationship**. The direction follows the flow of access/control: Agent → Server → Tool → Resource. Therefore, **any path through the graph IS an attack path**. Standard shortest-path algorithms find attack chains automatically.

This is the same insight that made [BloodHound](https://en.hackndo.com/bloodhound/) transformative for Active Directory: "BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment."

### 6.2 Shortest Path — "If X is Compromised, Can It Reach Y?"

Using [Neo4j's native shortestPath](https://neo4j.com/docs/cypher-manual/current/patterns/shortest-paths/):

```cypher
// From a specific agent to a specific resource
MATCH p = SHORTEST 1
  (a:AgentInstance {name: "coding-assistant"})
  (()-[]->()){1,}
  (r:MCPResource {name: "production-db"})
RETURN [n IN nodes(p) | coalesce(n.name, n.uri)] AS path,
       length(p) AS hops
```

**Legacy syntax (compatible with Neo4j 4.4):**
```cypher
MATCH p = shortestPath(
  (a:AgentInstance {name: "coding-assistant"})-[*1..]->(r:MCPResource {name: "production-db"})
)
RETURN p, length(p) AS hops
```

### 6.3 All Shortest Paths — "Show Me Every Equally Short Attack Chain"

```cypher
MATCH p = allShortestPaths(
  (a:AgentInstance)-[*1..]->(r:MCPResource {sensitivity: "critical"})
)
RETURN a.name AS agent, r.name AS resource,
       length(p) AS hops,
       [n IN nodes(p) | coalesce(n.name, n.uri)] AS path
ORDER BY hops ASC
```

### 6.4 Weighted Shortest Path — "Path of Least Resistance"

Not all edges are equally easy to exploit. A no-auth server is trivial; an OAuth-protected server requires token acquisition. [APOC's Dijkstra](https://neo4j.com/labs/apoc/4.3/algorithms/path-finding-procedures/) finds the path with the lowest total risk weight:

```cypher
MATCH (start:AgentInstance {name: "coding-assistant"})
MATCH (end:MCPResource {name: "production-db"})
CALL apoc.algo.dijkstra(start, end, 'TRUSTS_SERVER|PROVIDES_TOOL|HAS_ACCESS_TO|CAN_EXECUTE', 'risk_weight')
YIELD path, weight
RETURN path, weight
```

**Risk weight assignment (during post-processing):**

| Edge Type | Condition | Risk Weight | Rationale |
|-----------|-----------|------------|-----------|
| `TRUSTS_SERVER` | `auth_method = 'none'` | 0.1 | No barrier — trivial |
| `TRUSTS_SERVER` | `auth_method = 'static_key'` | 0.3 | Key often in config files |
| `TRUSTS_SERVER` | `auth_method = 'oauth'` | 0.7 | Requires token acquisition |
| `TRUSTS_SERVER` | `auth_method = 'mtls'` | 0.9 | Requires certificate |
| `PROVIDES_TOOL` | always | 0.1 | Tool is always available once server is reached |
| `HAS_ACCESS_TO` | always | 0.2 | Tool provides access by design |
| `CAN_EXECUTE` | always | 0.1 | Direct code execution |
| `DELEGATES_TO` | `auth_method = 'none'` | 0.1 | Open delegation |
| `DELEGATES_TO` | `auth_method != 'none'` | 0.5 | Requires credential |
| `SHADOWS` | always | 0.4 | Requires victim to invoke shadowed tool |

Lower weight = easier to exploit. Dijkstra finds the path with the minimum total weight = maximum risk.

**Path risk score (normalized to 0-100):**
```
raw_weight = sum(edge.risk_weight for edge in path)
max_possible = len(path) * 1.0  // worst case: every edge weight is 1.0
path_risk = (1.0 - raw_weight / max_possible) * 100
// Higher score = easier exploitation
```

### 6.5 Bounded Path Enumeration — "All Paths Within N Hops"

```cypher
// All paths from any agent to critical resources, max 6 hops
MATCH p = (a:AgentInstance)-[*1..6]->(r:MCPResource {sensitivity: "critical"})
RETURN a.name AS agent, r.name AS resource,
       length(p) AS hops,
       [n IN nodes(p) | coalesce(n.name, n.uri)] AS path
LIMIT 100
```

### 6.6 "Shortest Path To WHAT?" — Pre-Built Attack Path Targets

The system ships with pre-defined target classes. Users don't need to know specific resource names.

| Query Name | Source | Target | What It Finds |
|-----------|--------|--------|---------------|
| **Agents with shell access** | Any AgentInstance | Any Host (via CAN_EXECUTE) | Agents that can execute arbitrary commands |
| **Shortest path to databases** | Any AgentInstance | MCPResource where `uri_scheme IN ['postgres', 'mysql', 'mongodb']` | Data breach paths |
| **Data exfiltration routes** | Any AgentInstance with CAN_REACH to sensitive data | Any MCPTool with `email_send` or `network_outbound` | Complete exfiltration chains |
| **Cross-protocol paths** | Any A2AAgent with `auth_method = 'none'` | Any MCPResource with `sensitivity = 'critical'` | External agent → internal data |
| **Credential chain escalation** | Any AgentInstance | Any Credential that unlocks a different server | Privilege escalation via credential theft |
| **No-auth server exposure** | Any AgentInstance | MCPServer with `auth_method = 'none'` and sensitive tools | Trivially exploitable trust chains |
| **Poisoned tool blast radius** | MCPTool with `has_injection_patterns = true` | Any MCPResource reachable from agents trusting that tool's server | Impact of a tool poisoning attack |

### 6.7 Concrete Cross-Protocol Attack Path Example

**Scenario:** External A2A research agent → production database

```
A2AAgent("external-research-agent")     [no auth, publicly accessible Agent Card]
  │
  ├── DELEGATES_TO
  │
  A2AAgent("internal-coordinator")      [trusted internal agent]
  │
  ├── [correlation: runs on same host as MCP client]
  │
  AgentInstance("claude-desktop")       [user's coding assistant]
  │
  ├── TRUSTS_SERVER (auth: none)
  │
  MCPServer("postgres-mcp")            [database MCP server, no auth]
  │
  ├── PROVIDES_TOOL
  │
  MCPTool("execute_sql")               [capability: database_access, destructive: true]
  │
  ├── HAS_ACCESS_TO
  │
  MCPResource("production-db")         [sensitivity: critical, uri: postgres://prod:5432/main]
```

**Query that finds this path:**
```cypher
MATCH p = shortestPath(
  (ext:A2AAgent {auth_method: 'none'})-[*1..10]->(r:MCPResource {sensitivity: 'critical'})
)
RETURN ext.name AS entry_point,
       r.uri AS target,
       length(p) AS hops,
       [n IN nodes(p) | labels(n)[0] + ':' + coalesce(n.name, n.uri, 'unknown')] AS path,
       [r2 IN relationships(p) | type(r2)] AS edge_types
ORDER BY length(p) ASC
LIMIT 10
```

**What no other tool can find:** This path spans A2A discovery (Agent Card), config file analysis (trust binding), and MCP enumeration (tool capabilities). Cisco's A2A Scanner would find the no-auth A2A agent. Cisco's MCP Scanner would find the no-auth MCP server. Snyk would find the dangerous execute_sql tool. **None of them can find the 5-hop path connecting all three.**

## 7. Risk Scoring Model

### 7.1 Node Risk Scores

Every node receives a composite risk score (0-100):

**AgentInstance risk:**
```
agent_risk = weighted_sum(
  0.30 * credential_risk,         // Are connected servers' credentials static? Exposed? Shared?
  0.25 * blast_radius,            // How many critical resources can this agent transitively reach?
  0.20 * auth_posture,            // Average auth strength of connected servers
  0.15 * tool_surface,            // Number and capability class of accessible tools
  0.10 * poisoning_exposure       // Are any connected tools poisoned/shadowed?
)
```

**MCPServer risk:**
```
server_risk = weighted_sum(
  0.35 * auth_strength,           // none=100, static_key=70, oauth=30, mtls=10
  0.25 * tool_risk,               // Max risk across all provided tools
  0.20 * exposure,                // Local vs remote, TLS, binding address
  0.20 * credential_handling      // How credentials are stored and rotated
)
```

**MCPTool risk:**
```
tool_risk = weighted_sum(
  0.30 * capability_class,        // shell_access=100, db_access=80, file_write=60, network=50
  0.25 * poisoning_score,         // Injection patterns: 100 if poisoned, 0 if clean
  0.25 * access_sensitivity,      // Max sensitivity of resources this tool can access
  0.20 * input_validation         // Whether inputSchema constrains inputs (constrained=20, open=80)
)
```

### 7.2 Sensitivity Classification for Resources

Resources are auto-classified based on URI patterns:

| URI Pattern | Sensitivity | Rationale |
|------------|-------------|-----------|
| `postgres://`, `mysql://`, `mongodb://` production patterns | critical | Production database access |
| `file:///etc/`, `file:///root/`, `file:///home/*/.ssh/` | critical | System/credential files |
| `file:///.*\.(env\|key\|pem\|crt)$` | critical | Credential files |
| `postgres://`, `mysql://` non-production | high | Database access |
| `file:///` general | medium | Filesystem access |
| `https://` external APIs | medium | External service access |
| All others | low | Default |

## 8. Temporal Analysis

Every node and edge carries `scan_id` and `last_seen`. This enables:

**Rug pull detection:**
```cypher
MATCH (t:MCPTool)
WHERE t.description_hash <> t.previous_description_hash
  AND t.previous_description_hash IS NOT NULL
RETURN t.name, t.description_hash AS current, t.previous_description_hash AS previous
```
Source: Snyk agent-scan's [tool pinning](https://invariantlabs-ai.github.io/docs/mcp-scan/) uses SHA-based hashing to "detect changes to MCP tools via hashing."

**New path alerts:**
```cypher
// Edges that appeared in the current scan but not the previous
MATCH ()-[r]->()
WHERE r.scan_id = $current_scan_id
  AND NOT EXISTS {
    MATCH ()-[r2]->()
    WHERE type(r2) = type(r) AND r2.scan_id = $previous_scan_id
  }
RETURN type(r) AS edge_type, count(*) AS new_edges
```

**Scope creep:**
```cypher
// Servers that gained new tools between scans
MATCH (s:MCPServer)-[r:PROVIDES_TOOL]->(t:MCPTool)
WHERE r.scan_id = $current_scan_id
  AND NOT EXISTS {
    MATCH (s)-[r2:PROVIDES_TOOL]->(t)
    WHERE r2.scan_id = $previous_scan_id
  }
RETURN s.name AS server, collect(t.name) AS new_tools
```

## 9. API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `POST /api/v1/ingest` | POST | Upload collector JSON, triggers ingest + post-processing |
| `GET /api/v1/graph/nodes` | GET | List nodes with filtering by kind, risk score |
| `GET /api/v1/graph/nodes/:id` | GET | Get node with all properties and connected edges |
| `GET /api/v1/graph/edges` | GET | List edges with filtering by kind, source, target |
| `POST /api/v1/analysis/shortest-path` | POST | Find shortest path between two nodes |
| `POST /api/v1/analysis/all-paths` | POST | Find all paths between nodes (bounded) |
| `POST /api/v1/analysis/weighted-path` | POST | Find path of least resistance (Dijkstra) |
| `GET /api/v1/analysis/prebuilt/:query_id` | GET | Run a pre-built attack path query |
| `GET /api/v1/analysis/findings` | GET | All findings (composite edges) with severity |
| `POST /api/v1/query` | POST | Execute raw Cypher query (admin only) |

### Shortest Path API Request/Response:

**Request:**
```json
POST /api/v1/analysis/shortest-path
{
  "source": { "kind": "AgentInstance", "name": "coding-assistant" },
  "target": { "kind": "MCPResource", "filter": { "sensitivity": "critical" } },
  "max_hops": 10,
  "algorithm": "shortest"  // or "all_shortest" or "weighted"
}
```

**Response:**
```json
{
  "paths": [
    {
      "hops": 3,
      "risk_score": 87,
      "nodes": [
        { "id": "sha256:...", "kind": "AgentInstance", "name": "coding-assistant" },
        { "id": "sha256:...", "kind": "MCPServer", "name": "postgres-mcp", "auth_method": "none" },
        { "id": "sha256:...", "kind": "MCPTool", "name": "execute_sql", "capability_surface": ["database_access"] },
        { "id": "sha256:...", "kind": "MCPResource", "uri": "postgres://prod:5432/main", "sensitivity": "critical" }
      ],
      "edges": [
        { "kind": "TRUSTS_SERVER", "risk_weight": 0.1 },
        { "kind": "PROVIDES_TOOL", "risk_weight": 0.1 },
        { "kind": "HAS_ACCESS_TO", "risk_weight": 0.2 }
      ],
      "evidence": "Agent 'coding-assistant' trusts server 'postgres-mcp' (no auth) which provides 'execute_sql' with access to production database"
    }
  ],
  "total_paths": 1,
  "query_time_ms": 12
}
```

## 10. Summary — What Makes This Different

| Capability | Cisco MCP Scanner | Snyk agent-scan | Cisco A2A Scanner | **AgentHound** |
|-----------|------------------|----------------|-------------------|---------------|
| Scan individual MCP servers | Yes | Yes | No | Yes |
| Scan A2A Agent Cards | No | No | Yes | Yes |
| Parse client config files | Partial | Yes | No | Yes |
| Model trust relationships | No | No | No | **Yes** |
| Cross-server analysis | No | No | No | **Yes** |
| Cross-protocol analysis (A2A ↔ MCP) | No | No | No | **Yes** |
| Compute transitive reach (`CAN_REACH`) | No | No | No | **Yes** |
| Find data exfiltration paths | No | No | No | **Yes** |
| Shortest path to critical resources | No | No | No | **Yes** |
| Weighted path (least resistance) | No | No | No | **Yes** |
| Temporal drift detection | No | Partial (tool hashing) | No | **Yes** |
| Credential chain escalation | No | No | No | **Yes** |

The individual scanning capabilities are table stakes — Cisco and Snyk already do them well. The graph construction and attack path discovery across protocol boundaries is what no tool does today. That's the product.
