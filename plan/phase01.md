# Phase 1: Foundation

**Timeline:** Weeks 1–2
**Goal:** Project scaffolding, Docker Compose infrastructure, Neo4j graph schema, ingest pipeline, basic API server, and CI/CD — everything needed so that a hand-crafted JSON file can be ingested into Neo4j and queried.

---

## 1. Prerequisites

| Item | Details |
|------|---------|
| Go 1.25+ | Required by the MCP Go SDK v1.5.0 (`iter.Seq2` iterators, introduced in Go 1.23), also provides `go:embed`, generics, slog |
| Docker + Docker Compose v2 | For Neo4j + PostgreSQL containers |
| Node.js 20+ / pnpm | For frontend (scaffolded here, built in Phase 4) |
| Git | Version control |
| GitHub account | CI/CD via GitHub Actions |

---

## 2. Go Project Structure

Create the standard Go project layout. This follows the patterns used by BloodHound CE (`github.com/SpecterOps/BloodHound`) and other Go security tools (Nuclei, Trivy).

```
agenthound/
├── cmd/
│   └── agenthound/
│       └── main.go                 # Cobra root command entry point
├── internal/
│   ├── api/                        # REST API server
│   │   ├── server.go               # HTTP server setup (chi router)
│   │   ├── middleware/              # Auth, logging, CORS middleware
│   │   │   ├── logging.go
│   │   │   └── cors.go
│   │   └── handlers/
│   │       ├── health.go           # GET /api/v1/health
│   │       ├── graph.go            # Graph node/edge CRUD endpoints
│   │       ├── ingest.go           # POST /api/v1/ingest
│   │       └── analysis.go         # Pathfinding endpoints (stub)
│   ├── cli/                        # Cobra subcommands
│   │   ├── root.go                 # Root command with global flags
│   │   ├── serve.go                # `agenthound serve` — starts API server
│   │   ├── ingest.go               # `agenthound ingest <file>` — ingest JSON
│   │   ├── collect_mcp.go          # `agenthound collect mcp` (stub)
│   │   ├── collect_a2a.go          # `agenthound collect a2a` (stub)
│   │   ├── collect_config.go       # `agenthound collect config` (stub)
│   │   └── query.go                # `agenthound query <cypher>` (stub)
│   ├── graph/                      # Neo4j graph database layer
│   │   ├── driver.go               # Neo4j driver connection management
│   │   ├── schema.go               # Schema creation (constraints, indexes)
│   │   ├── writer.go               # Batch node/edge writer (MERGE-based)
│   │   └── reader.go               # Graph query execution
│   ├── ingest/                     # Ingest pipeline
│   │   ├── pipeline.go             # Main ingest orchestrator
│   │   ├── validator.go            # JSON schema validation
│   │   ├── normalizer.go           # ID normalization, property cleanup
│   │   └── deduplicator.go         # MERGE-based deduplication logic
│   ├── model/                      # Core data types
│   │   ├── node.go                 # Node struct (id, kinds, properties)
│   │   ├── edge.go                 # Edge struct (source, target, kind, properties)
│   │   ├── ingest.go               # IngestData, IngestMeta, GraphData structs
│   │   └── scan.go                 # Scan metadata struct
│   ├── appdb/                      # PostgreSQL application database
│   │   ├── driver.go               # pgx connection pool
│   │   ├── migrations/             # SQL migration files
│   │   │   └── 001_initial.sql     # Users, scans, audit_log tables
│   │   └── scans.go                # Scan CRUD operations
│   ├── auth/                        # Authentication (Phase 5, scaffolded here)
│   │   └── .gitkeep
│   ├── audit/                       # Audit logging (Phase 5, scaffolded here)
│   │   └── .gitkeep
│   └── config/                     # Application configuration
│       └── config.go               # Env-based config (Neo4j URL, PG URL, port)
├── pkg/                            # Public interfaces (for future plugin SDK)
│   ├── collector/
│   │   └── collector.go            # Collector interface definition
│   └── analysis/
│       └── postprocessor.go        # PostProcessor interface definition
├── ui/                             # React frontend (scaffolded, built Phase 4)
│   └── .gitkeep
├── docker/
│   ├── Dockerfile                  # Multi-stage Go build
│   └── docker-compose.yml          # Neo4j + PostgreSQL + app
├── scripts/
│   ├── seed-test-data.sh           # Load test JSON into running instance
│   └── wait-for-it.sh             # Container health check helper
├── testdata/
│   ├── valid_mcp_scan.json         # Valid MCP collector output for testing
│   ├── valid_a2a_scan.json         # Valid A2A collector output for testing
│   ├── valid_config_scan.json      # Valid Config collector output for testing
│   ├── merged_scan.json            # Combined output from all 3 collectors
│   └── invalid_scan.json           # Malformed JSON for error handling tests
├── go.mod
├── go.sum
├── Makefile
├── .github/
│   └── workflows/
│       └── ci.yml                  # Lint, test, build, Docker image
├── .gitignore
├── .golangci.yml                   # Linter configuration
└── LICENSE                         # Apache 2.0
```

### 2.1 Implementation Steps

**Step 1: Initialize Go module and install dependencies**

```bash
go mod init github.com/agenthound/agenthound
```

**Core dependencies:**

| Package | Version | Purpose | Reference |
|---------|---------|---------|-----------|
| `github.com/spf13/cobra` | v1.8+ | CLI framework | https://pkg.go.dev/github.com/spf13/cobra |
| `github.com/go-chi/chi/v5` | v5.1+ | HTTP router | https://pkg.go.dev/github.com/go-chi/chi/v5 |
| `github.com/neo4j/neo4j-go-driver/v5` | v5.28+ | Neo4j driver (v5 for 4.4 compat; v6 available for 5.x+) | https://pkg.go.dev/github.com/neo4j/neo4j-go-driver/v5 |
| `github.com/jackc/pgx/v5` | v5.7+ | PostgreSQL driver | https://pkg.go.dev/github.com/jackc/pgx/v5 |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0+ | JSON Schema validation | https://pkg.go.dev/github.com/santhosh-tekuri/jsonschema/v6 |
| `log/slog` | stdlib | Structured logging (Go 1.21+) | https://pkg.go.dev/log/slog |

**Step 2: Create `cmd/agenthound/main.go`**

Entry point. Initializes Cobra root command. Registers subcommands: `serve`, `ingest`, `collect`, `query`.

**Step 3: Create `internal/cli/root.go`**

Global flags: `--neo4j-uri` (default `bolt://localhost:7687`), `--neo4j-user`, `--neo4j-password`, `--pg-uri` (default `postgres://localhost:5432/agenthound`), `--log-level`, `--log-format`.

Environment variable overrides: `AGENTHOUND_NEO4J_URI`, `AGENTHOUND_PG_URI`, etc.

**Step 4: Create `internal/config/config.go`**

Struct-based configuration loaded from environment variables with sensible defaults:

```go
type Config struct {
    Neo4jURI      string // bolt://localhost:7687
    Neo4jUser     string // neo4j
    Neo4jPassword string // agenthound
    PostgresURI   string // postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable
    APIPort       int    // 8080
    LogLevel      string // info
}
```

---

## 3. Docker Compose Infrastructure

### 3.1 `docker/docker-compose.yml`

Three containers:

| Container | Image | Ports | Purpose |
|-----------|-------|-------|---------|
| `graph-db` | `neo4j:4.4-community` | 7474 (browser), 7687 (bolt) | Graph database |
| `app-db` | `postgres:16-alpine` | 5432 | Application database |
| `agenthound` | Built from Dockerfile | 8080 | Go API + embedded frontend |

**Neo4j Configuration:**
- `NEO4J_AUTH=neo4j/agenthound` — default credentials
- `NEO4J_PLUGINS=["apoc"]` — APOC plugin for Dijkstra and path expanders
- `NEO4J_dbms_security_procedures_unrestricted=apoc.*` — allow APOC procedures
- `NEO4J_dbms_memory_heap_initial__size=512m`
- `NEO4J_dbms_memory_heap_max__size=1G`
- Health check: `cypher-shell "RETURN 1"` every 10s

**PostgreSQL Configuration:**
- `POSTGRES_USER=agenthound`
- `POSTGRES_PASSWORD=agenthound`
- `POSTGRES_DB=agenthound`
- Health check: `pg_isready` every 5s

**Why Neo4j 4.4 and not 5.x:**
- BloodHound CE still supports 4.4 as the baseline
- 4.4 Community Edition is free and supports all needed features (constraints, indexes, shortestPath, APOC)
- The Cypher syntax for constraints differs between 4.4 and 5.x — we support both via version detection
- Migration to 5.x is straightforward when needed (schema syntax changes only)

**Note on Neo4j 5.x compatibility:**
- Neo4j 5.x uses `CREATE CONSTRAINT name FOR (n:Label) REQUIRE n.prop IS UNIQUE` (named constraints)
- Neo4j 4.4 uses `CREATE CONSTRAINT ON (n:Label) ASSERT n.prop IS UNIQUE`
- The schema initialization code (`internal/graph/schema.go`) must detect the Neo4j version via `CALL dbms.components()` and use the appropriate syntax

### 3.2 `docker/Dockerfile`

Multi-stage build:

```dockerfile
# Stage 1: Build Go binary
FROM golang:1.25-alpine AS builder
# ... build with CGO_ENABLED=0

# Stage 2: Runtime
FROM alpine:3.19
# Copy binary, expose 8080
```

The frontend is not embedded yet (Phase 4). For now, the API server just serves JSON endpoints.

---

## 4. Neo4j Graph Schema

### 4.1 `internal/graph/schema.go`

On first boot (or `agenthound schema init`), create all constraints and indexes.

**Constraints (unique IDs per node type):**

The schema initialization code must detect the Neo4j version via `CALL dbms.components() YIELD versions RETURN versions[0]` and use the appropriate syntax:

**Neo4j 5.x syntax:**
```cypher
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
CREATE CONSTRAINT FOR (n:InstructionFile) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:ResourceGroup) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:TrustZone) REQUIRE n.objectid IS UNIQUE;
```

**Neo4j 4.4 syntax (fallback):**
```cypher
CREATE CONSTRAINT ON (n:MCPServer) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:MCPTool) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:MCPResource) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:MCPPrompt) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:A2AAgent) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:A2ASkill) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:AgentInstance) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:Identity) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:Credential) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:Host) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:ConfigFile) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:InstructionFile) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:ResourceGroup) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT ON (n:TrustZone) ASSERT n.objectid IS UNIQUE;
```

**Indexes for common lookups:**

```cypher
CREATE INDEX FOR (n:MCPServer) ON (n.name);
CREATE INDEX FOR (n:MCPTool) ON (n.name);
CREATE INDEX FOR (n:MCPTool) ON (n.description_hash);
CREATE INDEX FOR (n:A2AAgent) ON (n.name);
CREATE INDEX FOR (n:A2AAgent) ON (n.url);
CREATE INDEX FOR (n:MCPResource) ON (n.uri);
CREATE INDEX FOR (n:MCPResource) ON (n.sensitivity);
CREATE INDEX FOR (n:MCPServer) ON (n.is_pinned);
CREATE INDEX FOR (n:A2AAgent) ON (n.is_signed);
CREATE INDEX FOR (n:InstructionFile) ON (n.type);
```

**Implementation notes:**
- Use `neo4j-go-driver/v5` session with `neo4j.AccessModeWrite`
- Wrap each statement in a separate transaction (constraints can't share tx)
- Detect existing constraints to make schema init idempotent
- Log each constraint/index creation

### 4.2 Schema Version Tracking

Store schema version in a `(:SchemaVersion {version: 1})` node. On boot, check if schema is current. If not, run migration. This enables forward-compatible schema changes.

---

## 5. Core Data Model (`internal/model/`)

### 5.1 `model/node.go`

```go
type Node struct {
    ID         string                 `json:"id"`
    Kinds      []string               `json:"kinds"`
    Properties map[string]interface{} `json:"properties"`
}
```

### 5.2 `model/edge.go`

```go
type Edge struct {
    Source     string                 `json:"source"`
    Target     string                 `json:"target"`
    Kind       string                 `json:"kind"`
    Properties map[string]interface{} `json:"properties"`
}
```

### 5.3 `model/ingest.go`

```go
type IngestData struct {
    Meta  IngestMeta `json:"meta"`
    Graph GraphData  `json:"graph"`
}

type IngestMeta struct {
    Version          int       `json:"version"`
    Type             string    `json:"type"`
    Collector        string    `json:"collector"`
    CollectorVersion string    `json:"collector_version"`
    Timestamp        time.Time `json:"timestamp"`
    ScanID           string    `json:"scan_id"`
}

type GraphData struct {
    Nodes []Node `json:"nodes"`
    Edges []Edge `json:"edges"`
}
```

### 5.4 Allowed Node Kinds and Edge Kinds

Define as constants for validation:

```go
var AllowedNodeKinds = map[string]bool{
    "MCPServer": true, "MCPTool": true, "MCPResource": true, "MCPPrompt": true,
    "A2AAgent": true, "A2ASkill": true, "AgentInstance": true,
    "Identity": true, "Credential": true, "Host": true,
    "ConfigFile": true, "InstructionFile": true,
    // ResourceGroup and TrustZone are synthetic-only nodes created by post-processors, not collectors.
    // Collectors should NOT produce these node kinds — the validator will reject them from collector input.
    // "ResourceGroup": true, "TrustZone": true,
}

var AllowedEdgeKinds = map[string]bool{
    "TRUSTS_SERVER": true, "PROVIDES_TOOL": true, "PROVIDES_RESOURCE": true,
    "PROVIDES_PROMPT": true, "ADVERTISES_SKILL": true, "DELEGATES_TO": true,
    "AUTHENTICATES_WITH": true, "USES_CREDENTIAL": true, "RUNS_ON": true,
    "CONFIGURED_IN": true, "HAS_ENV_VAR": true, "LOADS_INSTRUCTIONS": true,
    "SAME_AUTH_DOMAIN": true,
    // Composite edges (written by post-processor)
    "HAS_ACCESS_TO": true, "CAN_EXECUTE": true, "CAN_REACH": true,
    "CAN_EXFILTRATE_VIA": true, "SHADOWS": true, "POISONED_DESCRIPTION": true,
    "CAN_IMPERSONATE": true, "POISONED_INSTRUCTIONS": true,
}
```

---

## 6. Neo4j Driver Layer (`internal/graph/`)

### 6.1 `graph/driver.go`

Connection management using `neo4j-go-driver/v5`:

```go
func NewDriver(uri, username, password string) (neo4j.DriverWithContext, error) {
    driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
    if err != nil {
        return nil, fmt.Errorf("neo4j connection: %w", err)
    }
    // Verify connectivity
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if err := driver.VerifyConnectivity(ctx); err != nil {
        return nil, fmt.Errorf("neo4j verify: %w", err)
    }
    return driver, nil
}
```

**Reference:** https://neo4j.com/docs/go-manual/current/

### 6.2 `graph/writer.go` — Batch Ingest Writer

The writer takes a slice of Nodes and Edges, writes them to Neo4j using batched MERGE transactions.

**Key design decisions:**
- Batch size: 1000 operations per transaction (matches BloodHound's pattern)
- Use `MERGE` (not `CREATE`) for idempotent upserts — same node/edge from multiple collectors merges cleanly
- Use `UNWIND` for batch writes (send array of maps, iterate in Cypher)

**Node write Cypher:**
```cypher
UNWIND $nodes AS node
CALL {
  WITH node
  CALL apoc.merge.node(node.kinds, {objectid: node.id}, node.properties) YIELD node AS n
  SET n.scan_id = $scan_id, n.last_seen = datetime()
  RETURN n
}
RETURN count(*) AS written
```

**Fallback without APOC (if APOC unavailable):**
Generate per-label MERGE statements dynamically:
```cypher
UNWIND $nodes AS node
MERGE (n:MCPServer {objectid: node.id})
SET n += node.properties, n.scan_id = $scan_id, n.last_seen = datetime()
```

This requires grouping nodes by their primary kind and running separate queries per kind. Slightly less elegant but works without APOC.

**Edge write Cypher:**
```cypher
UNWIND $edges AS edge
MATCH (a {objectid: edge.source})
MATCH (b {objectid: edge.target})
CALL apoc.merge.relationship(a, edge.kind, {}, edge.properties, b) YIELD rel
SET rel.scan_id = $scan_id, rel.last_seen = datetime()
RETURN count(*) AS written
```

**Fallback without APOC:**
Cypher does not support parameterized relationship types (Neo4j < 5.26). Group edges by kind and dispatch a separate MERGE per kind:

```go
// In graph/writer.go — generate per-kind Cypher at runtime
var edgeKindCypher = map[string]string{
    "PROVIDES_TOOL":      `UNWIND $edges AS edge MATCH (a {objectid: edge.source}) MATCH (b {objectid: edge.target}) MERGE (a)-[r:PROVIDES_TOOL]->(b) SET r += edge.properties, r.scan_id = $scan_id, r.last_seen = datetime()`,
    "PROVIDES_RESOURCE":  `UNWIND $edges AS edge MATCH (a {objectid: edge.source}) MATCH (b {objectid: edge.target}) MERGE (a)-[r:PROVIDES_RESOURCE]->(b) SET r += edge.properties, r.scan_id = $scan_id, r.last_seen = datetime()`,
    "TRUSTS_SERVER":      `UNWIND $edges AS edge MATCH (a {objectid: edge.source}) MATCH (b {objectid: edge.target}) MERGE (a)-[r:TRUSTS_SERVER]->(b) SET r += edge.properties, r.scan_id = $scan_id, r.last_seen = datetime()`,
    // ... one entry per AllowedEdgeKind
}

func (w *Writer) WriteEdgesFallback(ctx context.Context, edges []model.Edge, scanID string) (int, error) {
    grouped := groupEdgesByKind(edges)
    total := 0
    for kind, batch := range grouped {
        cypher, ok := edgeKindCypher[kind]
        if !ok {
            return total, fmt.Errorf("unknown edge kind: %s", kind)
        }
        n, err := w.execBatch(ctx, cypher, batch, scanID)
        if err != nil {
            return total, err
        }
        total += n
    }
    return total, nil
}
```

### 6.3 `graph/reader.go` — Graph Query Execution

Execute arbitrary Cypher queries and return structured results:

```go
func (r *Reader) Query(ctx context.Context, cypher string, params map[string]interface{}) ([]map[string]interface{}, error)
func (r *Reader) GetNode(ctx context.Context, objectID string) (*model.Node, error)
func (r *Reader) GetNodeEdges(ctx context.Context, objectID string) ([]model.Edge, error)
func (r *Reader) GetStats(ctx context.Context) (*GraphStats, error)
```

`GetStats` returns: node counts by kind, edge counts by kind, total nodes, total edges.

---

## 7. PostgreSQL Application Database (`internal/appdb/`)

### 7.1 Schema — `migrations/001_initial.sql`

```sql
-- Scan history
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    collector   TEXT NOT NULL,            -- mcp, a2a, config
    status      TEXT NOT NULL DEFAULT 'pending', -- pending, running, completed, failed
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    node_count  INT DEFAULT 0,
    edge_count  INT DEFAULT 0,
    error       TEXT,
    metadata    JSONB DEFAULT '{}'
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action      TEXT NOT NULL,            -- ingest, query, scan_start, scan_complete
    user_id     TEXT,                     -- NULL for system actions
    details     JSONB DEFAULT '{}'
);

-- Users (basic auth for MVP)
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'analyst', -- admin, analyst, viewer
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login  TIMESTAMPTZ
);

-- API tokens
CREATE TABLE IF NOT EXISTS api_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    token_hash  TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    last_used   TIMESTAMPTZ
);

CREATE INDEX idx_scans_collector ON scans(collector);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_action ON audit_log(action);
```

### 7.2 Migration Runner

Use a simple file-based migration runner (no heavy ORM):
- Read SQL files from `internal/appdb/migrations/` in order
- Track applied migrations in a `schema_migrations` table
- Run on boot (`agenthound serve`) or via `agenthound migrate`

---

## 8. Ingest Pipeline (`internal/ingest/`)

### 8.1 `pipeline.go` — Main Orchestrator

```go
func (p *Pipeline) Ingest(ctx context.Context, data *model.IngestData) (*IngestResult, error) {
    // 1. Validate
    if err := p.validator.Validate(data); err != nil {
        return nil, fmt.Errorf("validation: %w", err)
    }

    // 2. Normalize
    p.normalizer.Normalize(data)

    // 3. Write nodes (batched)
    nodesWritten, err := p.graphWriter.WriteNodes(ctx, data.Graph.Nodes, data.Meta.ScanID)

    // 4. Write edges (batched)
    edgesWritten, err := p.graphWriter.WriteEdges(ctx, data.Graph.Edges, data.Meta.ScanID)

    // 5. Record scan in PostgreSQL
    p.appDB.RecordScan(ctx, data.Meta)

    // 6. Return result
    return &IngestResult{NodesWritten: nodesWritten, EdgesWritten: edgesWritten}, nil
}
```

### 8.2 `validator.go`

Validates:
- `meta.version` == 1
- `meta.type` == "agenthound-ingest"
- `meta.collector` is one of: mcp, a2a, config
- `meta.scan_id` is non-empty
- Every node has a non-empty `id` and at least one valid `kind`
- Every edge has valid `source`, `target`, and `kind`
- All edge source/target IDs reference nodes in the same file OR already exist in Neo4j
- Node kinds are in `AllowedNodeKinds`
- Edge kinds are in `AllowedEdgeKinds`

### 8.3 `normalizer.go`

- Convert all property keys from camelCase to snake_case (Neo4j is case-sensitive; all Cypher queries use snake_case convention). Use a camelCase→snake_case converter (e.g., `capabilitySurface` → `capability_surface`, `hasInjectionPatterns` → `has_injection_patterns`)
- Convert timestamps to ISO 8601 UTC
- Ensure `objectid` property matches the node `id` field
- Strip any null-valued properties

---

## 9. API Server (`internal/api/`)

### 9.1 `server.go`

Chi router with middleware stack:

```go
r := chi.NewRouter()
r.Use(middleware.RequestID)
r.Use(middleware.RealIP)
r.Use(middleware.Logger)    // slog-based request logging
r.Use(middleware.Recoverer)
r.Use(corsMiddleware)       // Allow all origins for dev

r.Route("/api/v1", func(r chi.Router) {
    r.Get("/health", handlers.Health)
    r.Get("/graph/stats", handlers.GraphStats)
    r.Get("/graph/nodes", handlers.ListNodes)
    r.Get("/graph/nodes/{id}", handlers.GetNode)
    r.Get("/graph/edges", handlers.ListEdges)
    r.Post("/ingest", handlers.IngestFile)
    r.Post("/query", handlers.ExecuteCypher)  // Admin-only raw Cypher
})
```

### 9.2 Handler Implementations

**`GET /api/v1/health`** — Returns 200 with Neo4j and PostgreSQL connectivity status.

**`GET /api/v1/graph/stats`** — Returns node/edge counts by kind.

**`POST /api/v1/ingest`** — Accepts JSON body or file upload. Runs ingest pipeline. Returns node/edge write counts.

**`GET /api/v1/graph/nodes?kind=MCPServer&limit=100`** — List nodes with filtering.

**`GET /api/v1/graph/nodes/{id}`** — Get node by objectid with connected edges.

**`POST /api/v1/query`** — Execute raw Cypher (admin only). Returns JSON result.

### 9.3 `serve` CLI Command

```go
// internal/cli/serve.go
var serveCmd = &cobra.Command{
    Use:   "serve",
    Short: "Start the AgentHound API server",
    RunE: func(cmd *cobra.Command, args []string) error {
        cfg := config.Load()
        neo4jDriver := graph.NewDriver(cfg.Neo4jURI, cfg.Neo4jUser, cfg.Neo4jPassword)
        pgPool := appdb.NewPool(cfg.PostgresURI)

        // Initialize schema on first boot
        graph.InitSchema(neo4jDriver)
        appdb.RunMigrations(pgPool)

        // Start HTTP server
        server := api.NewServer(neo4jDriver, pgPool, cfg)
        return server.ListenAndServe(cfg.APIPort)
    },
}
```

---

## 10. CI/CD — GitHub Actions

### 10.1 `.github/workflows/ci.yml`

```yaml
name: CI
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.25' }
      - uses: golangci/golangci-lint-action@v6
        with: { version: 'v1.61' }

  test:
    runs-on: ubuntu-latest
    services:
      neo4j:
        image: neo4j:4.4-community
        env:
          NEO4J_AUTH: neo4j/testpassword
        ports: ['7687:7687']
        options: >-
          --health-cmd "cypher-shell -u neo4j -p testpassword 'RETURN 1'"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 10
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: agenthound_test
        ports: ['5432:5432']
        options: >-
          --health-cmd pg_isready
          --health-interval 5s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.25' }
      - run: go test ./... -v -race -coverprofile=coverage.out
        env:
          AGENTHOUND_NEO4J_URI: bolt://localhost:7687
          AGENTHOUND_NEO4J_USER: neo4j
          AGENTHOUND_NEO4J_PASSWORD: testpassword
          AGENTHOUND_PG_URI: postgres://test:test@localhost:5432/agenthound_test?sslmode=disable
      - run: go tool cover -func=coverage.out

  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.25' }
      - run: go build -o agenthound ./cmd/agenthound
      - uses: actions/upload-artifact@v4
        with: { name: agenthound, path: agenthound }

  docker:
    runs-on: ubuntu-latest
    needs: [lint, test, build]
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: docker/Dockerfile
          push: false
          tags: ghcr.io/agenthound/agenthound:latest
```

---

## 11. Makefile

```makefile
.PHONY: build test lint docker up down clean

build:
	go build -o bin/agenthound ./cmd/agenthound

test:
	go test ./... -v -race -count=1

lint:
	golangci-lint run ./...

docker:
	docker build -f docker/Dockerfile -t agenthound:dev .

up:
	docker compose -f docker/docker-compose.yml up -d

down:
	docker compose -f docker/docker-compose.yml down

clean:
	rm -rf bin/ coverage.out
```

---

## 12. Test Data (`testdata/`)

Create hand-crafted JSON files that follow the ingest format. These files serve as:
1. Unit test fixtures for the ingest pipeline
2. Integration test fixtures for the full pipeline (JSON → Neo4j)
3. Demo data for verifying the API works

### 12.1 `testdata/valid_mcp_scan.json`

Contains: 1 MCPServer, 3 MCPTools, 1 MCPResource, edges: PROVIDES_TOOL × 3, PROVIDES_RESOURCE × 1.

### 12.2 `testdata/valid_config_scan.json`

Contains: 1 ConfigFile, 1 AgentInstance, 2 MCPServers (matching IDs from MCP scan), 1 Identity, 1 Credential, edges: TRUSTS_SERVER × 2, CONFIGURED_IN × 2, AUTHENTICATES_WITH, USES_CREDENTIAL, RUNS_ON × 2.

### 12.3 `testdata/valid_a2a_scan.json`

Contains: 2 A2AAgents, 3 A2ASkills, edges: ADVERTISES_SKILL × 3, DELEGATES_TO × 1.

### 12.4 `testdata/merged_scan.json`

Combined output from all three collectors — used to test that the merge works correctly (MCPServer node IDs match across config and MCP scans).

---

## 13. Golangci-lint Configuration

### `.golangci.yml`

```yaml
linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - gosimple
    - ineffassign
    - unused
    - misspell
    - gofmt
    - goimports

linters-settings:
  errcheck:
    check-type-assertions: true

issues:
  exclude-dirs:
    - testdata
```

---

## 14. Success Metrics / Exit Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| 1 | `docker compose up` starts all 3 containers and they reach healthy status | `docker compose ps` shows all healthy |
| 2 | `agenthound serve` starts API server on :8080 | `curl http://localhost:8080/api/v1/health` returns 200 |
| 3 | Health endpoint confirms Neo4j and PostgreSQL connectivity | Response includes `{"neo4j": "ok", "postgres": "ok"}` |
| 4 | Neo4j schema (constraints + indexes) created on first boot | `SHOW CONSTRAINTS` in Neo4j browser shows all 14 constraints |
| 5 | PostgreSQL migrations run on first boot | `scans`, `audit_log`, `users` tables exist |
| 6 | `agenthound ingest testdata/valid_mcp_scan.json` succeeds | Returns node/edge counts matching the file |
| 7 | After ingesting all 3 test files, `GET /api/v1/graph/stats` returns correct counts | All node kinds present with expected counts |
| 8 | MCPServer nodes from config and MCP scans merge correctly | Single MCPServer node with properties from both sources |
| 9 | `POST /api/v1/query` with `MATCH (n) RETURN count(n)` returns correct count | Total node count matches sum of all ingested nodes |
| 10 | `agenthound ingest testdata/invalid_scan.json` returns validation error | Error message specifies what's wrong |
| 11 | CI pipeline passes (lint, test, build) | GitHub Actions green |
| 12 | Unit test coverage > 70% on `internal/ingest/`, `internal/graph/`, `internal/model/` | `go test -coverprofile` |

---

## 15. Tests to Write

### Unit Tests

| Package | Test | What It Validates |
|---------|------|-------------------|
| `model` | `TestNodeSerialization` | Node JSON marshaling/unmarshaling |
| `model` | `TestEdgeSerialization` | Edge JSON marshaling/unmarshaling |
| `model` | `TestIngestDataParsing` | Full ingest JSON parsing |
| `ingest` | `TestValidatorAcceptsValid` | Valid JSON passes validation |
| `ingest` | `TestValidatorRejectsInvalidMeta` | Missing/invalid meta fields rejected |
| `ingest` | `TestValidatorRejectsInvalidNodes` | Nodes with missing id/kinds rejected |
| `ingest` | `TestValidatorRejectsInvalidEdges` | Edges with unknown kinds rejected |
| `ingest` | `TestNormalizerSnakeCaseProperties` | Property keys converted from camelCase to snake_case |
| `ingest` | `TestNormalizerTimestampISO` | Timestamps normalized to ISO 8601 |
| `config` | `TestConfigFromEnv` | Config loaded from environment |
| `config` | `TestConfigDefaults` | Defaults applied when env not set |

### Integration Tests (require Neo4j + PostgreSQL)

| Package | Test | What It Validates |
|---------|------|-------------------|
| `graph` | `TestSchemaInit` | Constraints and indexes created |
| `graph` | `TestSchemaIdempotent` | Running schema init twice doesn't error |
| `graph` | `TestWriteNodes` | Nodes written and queryable |
| `graph` | `TestWriteEdges` | Edges written and queryable |
| `graph` | `TestMergeOverwrite` | Re-writing same node updates properties |
| `graph` | `TestBatchWrite1000` | 1000 nodes written in single batch |
| `ingest` | `TestFullPipelineMCP` | MCP JSON → Neo4j, nodes/edges correct |
| `ingest` | `TestFullPipelineConfig` | Config JSON → Neo4j, trust edges correct |
| `ingest` | `TestFullPipelineMerge` | Config + MCP merge on MCPServer ID |
| `api` | `TestHealthEndpoint` | Returns 200 with db status |
| `api` | `TestIngestEndpoint` | POST JSON, verify nodes in Neo4j |
| `api` | `TestGraphStatsEndpoint` | Returns correct node/edge counts |
| `api` | `TestQueryEndpoint` | Raw Cypher execution works |

---

## 16. Risks and Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Neo4j 4.4 vs 5.x Cypher syntax differences | High | Version detection in `schema.go`; support both `CREATE CONSTRAINT ON` (4.4) and `CREATE CONSTRAINT ... FOR` (5.x) |
| APOC plugin not available in some Neo4j images | Medium | All APOC-dependent code has non-APOC fallbacks. APOC is only required for Dijkstra (Phase 3). |
| pgx vs lib/pq choice | Low | Use pgx (faster, pure Go, maintained by jackc). Direct replacement if needed. |
| Docker Compose v1 vs v2 | Low | Use `docker compose` (v2) in all scripts. Note in README. |
| Neo4j Community Edition limitations (single database) | Low | Single database is fine for MVP. Enterprise multi-database is post-MVP. |

---

## 17. Dependencies on Later Phases

| This Phase Creates | Used By |
|-------------------|---------|
| `pkg/collector/collector.go` (interface) | Phase 2: All collectors implement this |
| `pkg/analysis/postprocessor.go` (interface) | Phase 3: Post-processors implement this |
| `internal/graph/writer.go` (batch writer) | Phase 2: Collectors → ingest → writer |
| `internal/graph/reader.go` (query execution) | Phase 3: Attack path queries, Phase 4: API |
| `internal/api/server.go` (API framework) | Phase 4: Frontend consumes API |
| `internal/appdb/` (PostgreSQL layer) | Phase 5: Auth, audit logging |
| Docker Compose (infrastructure) | All subsequent phases |
| CI/CD pipeline | All subsequent phases |
| Ingest format + validation | Phase 2: Collectors must produce valid JSON |
