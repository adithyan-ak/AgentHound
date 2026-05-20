# API Reference

All endpoints are served at `/api/v1/*` by `agenthound-server`. The default bind is `127.0.0.1:8080` (loopback only).

The canonical, machine-readable spec is served at `GET /api/v1/docs` (OpenAPI 3.0 YAML). CI verifies it stays in sync with the route map. This document is a human-readable summary.

## Authentication

AgentHound is single-user. The server has **no application-layer login** — no JWT, no users table, no RBAC. Network scope (`127.0.0.1` by default) is the primary access control.

A second control catches browser drive-by attacks: **mutating endpoints require a localhost bearer token**. The token is a 32-byte random secret, auto-generated at first server start and persisted to `~/.agenthound/server.token` (mode `0o600`). Override the path with `AGENTHOUND_TOKEN_PATH` or `XDG_CONFIG_HOME`.

| Endpoint group | Auth |
|---|---|
| Read endpoints (`GET /api/v1/...`) | Open — no token required. |
| `GET /api/v1/auth/local-token` | Open — same-origin only via CORS allowlist. |
| Mutating endpoints (see table below) | Require `Authorization: Bearer <token>`. |

CORS uses `AllowCredentials: false` so a hostile origin cannot exfiltrate the token via a credentialed fetch. CLI tools (`agenthound-server ingest`, `agenthound-server query`) bypass HTTP entirely and don't need the token.

If you need to expose the server beyond loopback, do so at the network layer (VPN / SSH tunnel / Tailscale) — never by binding `0.0.0.0:8080` to a public interface. See [`security.md`](security.md).

### Mutating endpoints (token required)

- `POST /api/v1/ingest`
- `POST /api/v1/query`
- `POST /api/v1/scans`
- `DELETE /api/v1/scans/{id}`
- `POST /api/v1/analysis/shortest-path`
- `POST /api/v1/analysis/all-paths`
- `POST /api/v1/analysis/weighted-path`

A request to any of these without the header returns `401 Unauthorized`.

## Error format

All errors return a structured JSON response:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "description of the problem"
  }
}
```

Error codes: `VALIDATION_ERROR` (400), `UNAUTHORIZED` (401), `NOT_FOUND` (404), `SERVICE_UNAVAILABLE` (503), `INTERNAL_ERROR` (500). Internal errors include a request ID for log correlation; raw error strings are not leaked to clients.

---

## Health

### `GET /api/v1/health`

Returns connectivity status for Neo4j and PostgreSQL.

```json
{
  "status": "ok",
  "neo4j": "ok",
  "postgres": "ok"
}
```

`status` is `ok` or `degraded`; component fields are `ok` or `unavailable`.

### `GET /api/v1/docs`

Serves the OpenAPI 3.0 specification (`application/yaml`).

### `GET /api/v1/auth/local-token`

Returns the current localhost bearer token. Used by the embedded UI on first load. Same-origin enforced via the CORS allowlist.

```json
{ "token": "..." }
```

---

## Graph

### `GET /api/v1/graph/stats`

Returns node and edge counts by kind.

```json
{
  "nodes": { "MCPServer": 12, "MCPTool": 47, "MCPResource": 23, "AgentInstance": 3 },
  "edges": { "TRUSTS_SERVER": 15, "PROVIDES_TOOL": 47, "CAN_REACH": 8 }
}
```

### `GET /api/v1/graph/search`

Free-text search across node names, IDs, and identifying properties.

| Param | Type | Description |
|-------|------|-------------|
| `q` | string | Search term |
| `limit` | int | Max results (default 50) |

### `GET /api/v1/graph/nodes`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `kind` | string | (all) | Filter by node label |
| `limit` | int | 100 | Max results (1–10000) |

### `GET /api/v1/graph/nodes/{id}`

Returns a single node with all connected edges.

```json
{
  "node": {
    "id": "sha256:...",
    "kinds": ["MCPServer"],
    "properties": { "name": "...", "transport": "stdio" }
  },
  "edges": [
    { "source": "...", "target": "...", "kind": "PROVIDES_TOOL", "properties": {} }
  ]
}
```

### `GET /api/v1/graph/nodes/{id}/neighborhood`

Returns the N-hop neighborhood subgraph rooted at the node.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `depth` | int | 1 | Hop count (1–5) |

### `GET /api/v1/graph/nodes/{id}/blast-radius`

Returns reachable nodes grouped by ring (1-hop, 2-hop, ...). Useful for "what can this agent touch?" questions.

### `GET /api/v1/graph/edges`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `kind` | string | (all) | Filter by edge kind |
| `source` | string | | Filter by source node ID |
| `target` | string | | Filter by target node ID |
| `limit` | int | 100 | Max results (1–10000) |

---

## Ingest

### `POST /api/v1/ingest` *(token required)*

**Max body:** 100 MB.

Upload collector JSON output. Runs the full pipeline: validate → normalize → deduplicate → write → post-process.

```json
// Request body: collector JSON output (see graph-model.md for schema)

// Response (200)
{
  "scan_id": "scan-abc123",
  "nodes_written": 47,
  "edges_written": 82,
  "duration": "1.23s",
  "warnings": []
}
```

---

## Analysis

### `POST /api/v1/analysis/shortest-path` *(token required)*

Find the shortest path between two nodes.

```json
// Request
{
  "source": "my-agent",
  "source_kind": "AgentInstance",
  "target": "postgres://prod",
  "target_kind": "MCPResource",
  "max_hops": 10
}

// Response
{
  "paths": [
    {
      "nodes": [{ "id": "sha256:...", "name": "my-agent", "kinds": ["AgentInstance"] }],
      "edges": [{ "kind": "TRUSTS_SERVER", "source": "sha256:...", "target": "sha256:..." }],
      "hops": 3
    }
  ]
}
```

### `POST /api/v1/analysis/all-paths` *(token required)*

Enumerate all paths between two nodes (bounded). Same request as shortest-path, plus:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 10 | Max paths returned (1–100) |

### `POST /api/v1/analysis/weighted-path` *(token required)*

Find the lowest-risk-weight path using Dijkstra (APOC) or `shortestPath` + `reduce` fallback.

Same request format as shortest-path. Response includes `"algorithm": "dijkstra"` or `"algorithm": "shortestPath+reduce"`.

### `GET /api/v1/analysis/findings`

List all composite edges as security findings.

| Param | Type | Description |
|-------|------|-------------|
| `severity` | string | Filter: `critical`, `high`, `medium`, `low` |

### `GET /api/v1/analysis/findings/{id}`

Return evidence detail for a specific finding.

### `GET /api/v1/analysis/prebuilt`

List all 17 pre-built queries with metadata.

### `GET /api/v1/analysis/prebuilt/{id}`

Execute a pre-built query and return results.

```json
{
  "query": {
    "id": "agents-shell-access",
    "name": "Agents with Shell Access",
    "severity": "critical",
    "category": "Critical Paths",
    "owasp_map": ["MCP01", "ASI06"]
  },
  "rows": [...]
}
```

---

## Query

### `POST /api/v1/query` *(token required)*

Execute raw Cypher against Neo4j.

```json
// Request
{
  "cypher": "MATCH (n:MCPServer) RETURN n.name LIMIT 10",
  "params": { }
}
```

The token-gated endpoint protects against browser drive-by Cypher injection from a hostile origin. CLI use (`agenthound-server query`) bypasses HTTP and doesn't need the token.

---

## Scans

### `GET /api/v1/scans`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Max results |
| `offset` | int | 0 | Pagination offset |

### `POST /api/v1/scans` *(token required)*

Register a new scan (sets `scan_id`, `started_at`, `status: in_progress`). Used by the UI's "New scan" flow; CLI ingest creates scan records implicitly.

### `GET /api/v1/scans/{id}`

Get scan details by ID.

### `DELETE /api/v1/scans/{id}` *(token required)*

Delete a scan and cascade-delete the nodes and edges that scan owned. Composite edges are scoped by `source_collector` so partial scans don't bleed.

---

## Rules

### `GET /api/v1/rules`

List all 30 active YAML detection rules from `sdk/rules/builtin/`.

### `GET /api/v1/rules/{id}`

Return the YAML definition (parsed) for a single rule.
