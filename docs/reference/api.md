# API Reference

All endpoints are served at `/api/v1/*` by `agenthound-server`. The default bind is `127.0.0.1:8080` (loopback only).

The canonical, machine-readable spec is served at `GET /api/v1/docs` (OpenAPI 3.0 YAML). CI verifies it stays in sync with the route map. This document is a human-readable summary.

## Authentication

AgentHound is single-user. The server has **no application-layer login** — no JWT, no users table, no RBAC. Network scope (`127.0.0.1` by default) is the primary access control.

A second control catches browser drive-by attacks: **mutating endpoints are gated by an Origin allowlist** (`OriginGuard`). Browser requests must originate from an allowlisted origin; non-browser callers (no `Origin` header) pass through.

| Endpoint group | Auth |
|---|---|
| Read endpoints (`GET /api/v1/...`) | Open. |
| Mutating endpoints (see table below) | Browser `Origin` must be in `AGENTHOUND_CORS_ORIGINS` (default `http://localhost:8080`, `http://127.0.0.1:8080`). No `Origin` header (curl, CLI) → pass. |

The default allowlist covers the embedded UI. Stream-ingest from the host (`curl --data-binary @scan.json http://127.0.0.1:8080/api/v1/ingest`) works zero-config. The `agenthound-server` CLI (`ingest`, `query`) bypasses HTTP entirely.

If you need to expose the server beyond loopback, do so at the network layer (VPN / SSH tunnel / Tailscale) — never by binding `0.0.0.0:8080` to a public interface. See [`security.md`](../operator/security.md).

### Mutating endpoints (Origin-gated)

- `POST /api/v1/ingest`
- `POST /api/v1/query`
- `POST /api/v1/scans`
- `DELETE /api/v1/scans/{id}`
- `POST /api/v1/analysis/shortest-path`
- `POST /api/v1/analysis/all-paths`
- `POST /api/v1/analysis/weighted-path`
- `PUT /api/v1/findings/triage/{fingerprint}`

A request to any of these with a foreign or `null` `Origin` returns `403 Forbidden`.

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

Error codes: `VALIDATION_ERROR` (400), `FORBIDDEN` (403), `NOT_FOUND` (404), `SERVICE_UNAVAILABLE` (503), `INTERNAL_ERROR` (500). Internal errors include a request ID for log correlation; raw error strings are not leaked to clients.

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

---

## Graph

### `GET /api/v1/graph/stats`

Returns node and edge counts by kind.

```json
{
  "node_counts": { "MCPServer": 12, "MCPTool": 47, "MCPResource": 23, "AgentInstance": 3 },
  "edge_counts": { "TRUSTS_SERVER": 15, "PROVIDES_TOOL": 47, "CAN_REACH": 8 },
  "total_nodes": 85,
  "total_edges": 70
}
```

### `GET /api/v1/graph/search`

Free-text search across node names, IDs, and identifying properties.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `q` | string | _(required)_ | Search term. Must be at least 2 characters; shorter values return `400 VALIDATION_ERROR`. |
| `limit` | int | 20 | Max results (1–100; values above the cap are silently clamped). |

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
| `depth` | int | 1 | Hop count (1–3; values above the cap are silently clamped). |

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

### `POST /api/v1/ingest` *(Origin-gated)*

**Max body:** 100 MB.

Upload collector JSON output. Runs the full pipeline: validate → normalize → deduplicate → write → post-process.

Validation rejects the payload (HTTP 400 with a field-level error list) when `meta.identity_version` is present and not the version the server supports (`ingest.CurrentIdentityVersion`). Node IDs are content hashes whose derivation is versioned; an artifact from a different scheme would compute non-matching IDs and silently fail to merge (e.g. config + MCP observations of one MCPServer landing as two nodes). Re-collect and re-ingest with a current collector. A zero/absent `identity_version` defers to the current scheme (pre-contract fixtures).

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

// Response (400) — unsupported identity version
{
  "errors": [
    { "path": "meta.identity_version", "message": "unsupported identity version 1; server requires 2 — re-collect and re-ingest with a current collector" }
  ]
}
```

---

## Analysis

### `POST /api/v1/analysis/shortest-path` *(Origin-gated)*

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

### `POST /api/v1/analysis/all-paths` *(Origin-gated)*

Enumerate all paths between two nodes (bounded). Same request as shortest-path, plus:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 10 | Max paths returned (1–100) |

### `POST /api/v1/analysis/weighted-path` *(Origin-gated)*

Find the minimum-total-risk-weight path using a single bounded, forward-directed traversal (no APOC dependency). Same request format as shortest-path. The response includes `"algorithm": "bounded-min-weight"`, `"direction"`, `"max_hops"`, and the total weight is reported as `null` (unknown) when any edge on the chosen path lacks a `risk_weight` — never a benign zero.

**Generation scoping.** The shortest-path, all-paths, weighted-path, and pre-built analysis endpoints are scoped to the **current logical generations**: every node and relationship on a returned path (or every anchor of a pre-built query) must be observed by a promoted generation, so a path/result never traverses a retained (demoted) generation's facts. Each response carries a `completeness` disclosure; when no generation is promoted the result is an empty, disclosed-incomplete set.

### `GET /api/v1/analysis/findings`

List findings from the latest persisted snapshot (one row per fingerprint), each with inline `triage` state. Reads from the Postgres snapshot, not live graph edges, so results are stable across the next scan's stale-edge cleanup.

| Param | Type | Description |
|-------|------|-------------|
| `severity` | string | Filter: `critical`, `high`, `medium`, `low` |
| `include_suppressed` | bool | Default `false`. When `true`, include findings triaged `accepted-risk` / `false-positive` (hidden otherwise). |

Each finding carries an `owasp_map` (`[]string`) and, where the technique mapping is unambiguous, an `atlas_map` (`[]string`) of [MITRE ATLAS](https://atlas.mitre.org/) technique IDs (e.g. `["AML.T0051", "AML.T0110"]`). `atlas_map` is omitted when empty (`omitempty`); detections AgentHound has not confidently mapped carry no ATLAS tag. See the [ATLAS crosswalk](detection-rules.md#mitre-atlas-crosswalk) for the per-edge mapping.

### `GET /api/v1/analysis/findings/{id}`

Return evidence detail for a specific finding.

### `GET /api/v1/findings/triage/{fingerprint}`

Return the cross-scan triage decision for a finding fingerprint (16-char hex). Open read; a fingerprint with no recorded decision returns the implicit `new` state.

```json
{ "status": "accepted-risk", "note": "Approved by sec-review", "updated_at": "2026-06-19T12:00:00Z" }
```

### `PUT /api/v1/findings/triage/{fingerprint}` *(Origin-gated)*

Record (or update) the triage decision for a finding fingerprint. Triage state has no foreign key to findings, so it survives scan deletion and re-detection.

```json
// Request
{ "status": "accepted-risk", "note": "Approved by sec-review" }
```

`status` must be one of `new`, `triaging`, `confirmed`, `accepted-risk`, `false-positive`.

### `GET /api/v1/analysis/prebuilt`

List all 19 pre-built queries with metadata.

### `GET /api/v1/analysis/prebuilt/{id}`

Execute a pre-built query and return results.

```json
{
  "query": {
    "id": "poisoned-tools",
    "name": "Poisoned Tool Descriptions",
    "severity": "high",
    "category": "Vulnerabilities",
    "owasp_map": ["MCP05", "ASI03"],
    "atlas_map": ["AML.T0051", "AML.T0110"]
  },
  "rows": [...]
}
```

Like findings, pre-built queries carry an optional `atlas_map` (`[]string`) of [MITRE ATLAS](https://atlas.mitre.org/) technique IDs on confidently-mappable queries; it is omitted (`omitempty`) on queries with no ATLAS mapping (e.g. infrastructure/path/chokepoint queries). See the [ATLAS crosswalk](detection-rules.md#mitre-atlas-crosswalk).

---

## Query

### `POST /api/v1/query` *(Origin-gated)*

Execute raw Cypher against Neo4j.

```json
// Request
{
  "cypher": "MATCH (n:MCPServer) RETURN n.name LIMIT 10",
  "params": { }
}
```

The Origin gate protects against browser drive-by Cypher injection from a hostile origin: a browser request from outside `AGENTHOUND_CORS_ORIGINS` returns `403 Forbidden` before Cypher is executed. CLI use (`agenthound-server query`) bypasses HTTP and never goes through the gate.

---

## Scans

Scan records serialize `model.Scan` verbatim. The `status` field is one of:

| Status | Meaning |
|--------|---------|
| `pending` | Registered but not yet started. |
| `running` | Ingest in progress. |
| `completed` | Collection and analysis post-processing both succeeded. |
| `completed_with_errors` | Node/edge writes succeeded (real counts persisted) but post-processing failed; `error` holds the detail. |
| `failed` | Collection/write failure; counts are `0, 0` and `error` holds the write error. |

### `GET /api/v1/scans`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Max results |
| `offset` | int | 0 | Pagination offset |

### `POST /api/v1/scans` *(Origin-gated)*

Register a new scan (sets `scan_id`, `started_at`, `status: pending`). Used by the UI's "New scan" flow; CLI ingest creates scan records implicitly.

### `GET /api/v1/scans/{id}`

Get scan details by ID.

### `DELETE /api/v1/scans/{id}` *(Origin-gated)*

Durably delete a scan's generation from Neo4j and Postgres. The delete is recoverable and idempotent:

1. The scan is marked `delete_state = "deleting"` (persisted) **before** the graph is mutated.
2. The generation's contribution is removed in a **single Neo4j transaction** (edge + node decrement/GC), so a shared fact another generation still owns survives.
3. The finding snapshot is dropped, the prior valid generation is rematerialized as current (current-pointer exposure only after the recoverable delete completes), and the scan row is removed.

Any failure records `delete_state = "delete_failed"` and returns an internal error; the scan row is retained so a retry (or the startup recovery sweep) completes the delete idempotently. A non-terminal scan cannot be deleted unless it is already in a delete lifecycle. `?preview=true` reports the affected generation/observations and the generation that would be rematerialized, without mutating anything.

The `scans` object exposes `delete_state` (`""` normal, `deleting`, or `delete_failed`).

---

## Rules

### `GET /api/v1/rules`

List all 35 active YAML detection rules from `sdk/rules/builtin/`.

### `GET /api/v1/rules/{id}`

Return the YAML definition (parsed) for a single rule.
