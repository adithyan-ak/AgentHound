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
- `POST /api/v1/analysis/topology/shortest-path`
- `POST /api/v1/analysis/topology/all-paths`
- `POST /api/v1/analysis/topology/weighted-path`
- `PATCH /api/v1/findings/triage/{fingerprint}`

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

Error codes: `VALIDATION_ERROR` (400), `FORBIDDEN` (403), `NOT_FOUND`
(404), `REVISION_CONFLICT` (409), `PROJECTION_CONFLICT` (409),
`SERVICE_UNAVAILABLE` (503), `INTERNAL_ERROR` (500). Graph-backed reads
return `PROJECTION_CONFLICT` unless one stable, complete published projection
is available for the entire read. `error.details.reason` is `absent`,
`updating`, `incomplete`, or `changed`; clients must retry the whole read
rather than interpret an empty result as an all-clear. Internal errors include
a request ID for log correlation; raw error strings are not leaked to clients.

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

Returns public node and edge counts by kind. Internal `SchemaVersion` nodes are
excluded from stats, node lists, and search results.

```json
{
  "node_counts": { "MCPServer": 12, "MCPTool": 47, "MCPResource": 23, "AgentInstance": 3 },
  "edge_counts": { "TRUSTS_SERVER": 15, "PROVIDES_TOOL": 47, "CAN_REACH": 8 },
  "total_nodes": 85,
  "total_edges": 70,
  "projection": { "scan_id": "scan-abc123", "revision": 12 }
}
```

`projection` is required and identifies the immutable publication represented
by the counts.

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
| `offset` | int | 0 | Nonnegative pagination offset |
| `revision` | string | | Opaque `page.revision` from the first page |

Node, edge, and scan lists use typed JSON envelopes. For example:

```json
{
  "nodes": [],
  "page": {
    "offset": 0,
    "limit": 100,
    "total": 0,
    "has_more": false,
    "complete": true,
    "revision": "...",
    "projection": { "scan_id": "scan-abc123", "revision": 12 }
  }
}
```

Edge and scan responses use `edges` and `scans` respectively. Continue with the
same revision token. A graph change returns `409 REVISION_CONFLICT` with
`error.details.expected_revision` and `error.details.actual_revision`; restart
at offset 0. Every graph page also requires the same `projection` identity.
A missing, incomplete, or changing publication returns
`409 PROJECTION_CONFLICT`. Page metadata describes read completeness only; it
does not assert that collector coverage or analysis stages completed.

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
| `limit` | int | 100 | Max results (1–100000) |
| `offset` | int | 0 | Nonnegative pagination offset |
| `revision` | string | | Opaque `page.revision` from the first page |

---

## Ingest

### `POST /api/v1/ingest` *(Origin-gated)*

**Max body:** 100 MB.

Upload strict ingest-v2 collector JSON. Unknown structural fields, v1
artifacts, missing collection/rules/identity metadata, unscoped facts, omitted
edge endpoint kinds, legacy property aliases, and incomplete canonical
credential/host/auth evidence are rejected before any write. Runs the
serialized lifecycle: validate →
normalize → freeze pre-write totals → write → reconcile complete observation
domains → post-process → freeze post-analysis totals → snapshot → publish.

```json
// Request body (abridged; see graph-model.md for the complete schema)
{
  "meta": {
    "version": 2,
    "type": "agenthound-ingest",
    "collector": "mcp",
    "collector_version": "0.1.0",
    "timestamp": "2026-07-11T00:00:00Z",
    "scan_id": "scan-abc123",
    "collection": {
      "state": "complete",
      "coverage_keys": ["mcp:target:sha256:..."],
      "outcomes": [{
        "collector": "mcp",
        "coverage_key": "mcp:target:sha256:...",
        "target": "https://example.test/mcp",
        "method": "mcp",
        "state": "complete"
      }]
    },
    "ruleset": { "...": "required" },
    "identity_schemes": [{ "...": "required" }]
  },
  "graph": { "nodes": [], "edges": [] }
}

// Response (200)
{
  "scan_id": "scan-abc123",
  "outcome": "complete",
  "projection_status": "complete",
  "submitted": { "nodes": 47, "edges": 82 },
  "write_rows": { "nodes": 47, "edges": 82 },
  "graph_totals": {
    "before": { "node_counts": {}, "edge_counts": {}, "total_nodes": 0, "total_edges": 0 },
    "after": { "node_counts": {}, "edge_counts": {}, "total_nodes": 47, "total_edges": 82 }
  },
  "stages": [
    { "name": "write_nodes", "state": "complete", "required": true }
  ],
  "published_revision": 12,
  "warnings": [],
  "normalization_status": "complete",
  "normalization_warnings": [],
  "collection": {
    "state": "complete",
    "coverage_keys": ["mcp:target:sha256:..."],
    "outcomes": [{
      "collector": "mcp",
      "coverage_key": "mcp:target:sha256:...",
      "target": "https://example.test/mcp",
      "method": "mcp",
      "state": "complete"
    }]
  },
  "duration": 1230000000
}
```

`meta.collection` is required on every ingest request, and `collection` is
required on every successful ingest result. A missing collection report is a
validation error, not an implicit complete scan.
Completed dynamic exhaustive runs may include `authoritative_roots`, each with
a stable root `coverage_key` and the complete `child_coverage_keys` active set.
The server reconciles prior children omitted from that set as complete-empty.
Targeted and non-exhaustive runs omit this field and cannot retire siblings.

`submitted` counts input facts, `write_rows` counts Neo4j write-result rows
(including matches of existing facts), and `graph_totals` freezes public
inventory before and after processing. A batch failure returns
`500 INGEST_FAILED` with the same typed partial result under `error.details`,
including committed write rows. The scan and global projection state are
marked incomplete.

Only explicitly complete, attributable target/config coverage keys can retire
prior raw observations. Partial/failed/truncated collection never retires data
and never replaces the latest published posture.
Lossless normalization coercions are persisted as `warning` and may publish;
only warnings explicitly marked `publication_unsafe` produce `degraded` and
withhold publication.

---

## Analysis

### `POST /api/v1/analysis/shortest-path` *(Origin-gated)*

Find a bounded hop-shortest path using the explicit directed security
relationship policy. Unknown request fields, including `scope`, are rejected.
Use the separate `/analysis/topology/...` operations for undirected topology.

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
  ],
  "metadata": {
    "scope": "security",
    "direction": "out",
    "relationship_kinds": ["TRUSTS_SERVER", "PROVIDES_TOOL", "HAS_ACCESS_TO"],
    "max_hops": 10,
    "algorithm": "bounded-min-weight",
    "complete": true
  },
  "projection": { "scan_id": "scan-abc123", "revision": 12 }
}
```

Every traversal result requires `projection`; it identifies the stable
published graph used for endpoint resolution and traversal. An unavailable or
changing projection returns `409 PROJECTION_CONFLICT`.

### `POST /api/v1/analysis/all-paths` *(Origin-gated)*

Enumerate directed security paths between two nodes, bounded by
`max_hops`, `limit`, and the server expansion cap. Same request as
shortest-path, plus:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 10 | Max paths returned (1–100) |

### `POST /api/v1/analysis/weighted-path` *(Origin-gated)*

Find the bounded minimum-risk-weight path with one deployment-independent
algorithm. APOC availability does not change results. Missing `risk_weight`
fails the request; negative or non-finite values also fail. The response
includes `metadata.algorithm: "bounded-min-weight"` and traversal completeness
metadata.

### Explicit topology traversal *(Origin-gated)*

The undirected topology capability is available only through separate
operations:

- `POST /api/v1/analysis/topology/shortest-path`
- `POST /api/v1/analysis/topology/all-paths`
- `POST /api/v1/analysis/topology/weighted-path`

They accept the same scope-free request body and return metadata with
`scope: "topology"` and `direction: "both"`.

### `GET /api/v1/analysis/findings`

List findings from the immutable currently published Postgres snapshot with
inline `triage` state.

| Param | Type | Description |
|-------|------|-------------|
| `severity` | string | Filter: `critical`, `high`, `medium`, `low` |
| `include_suppressed` | bool | Default `false`. When `true`, include findings triaged `accepted-risk` / `false-positive` (hidden otherwise). |
The response is `{ "findings": [...], "scope": {...} }`. `scope` carries the
published scan ID, revision, publication time, projection/snapshot status,
availability, and staleness. A partial live Neo4j projection does not move the
published pointer. Clients require explicit available/complete/non-stale
metadata before interpreting an empty findings array as a current all-clear.
A failed refresh may show cached rows only when labelled as cached.

Each finding carries `owasp_map` and `atlas_map` arrays. Detections without a
confident ATLAS mapping return `atlas_map: []`. `variant`, typed `evidence`,
and exact witness evidence are persisted with the same scan row, so a
published credential reference cannot be silently reclassified from a later
live graph. See the [ATLAS crosswalk](detection-rules.md#mitre-atlas-crosswalk).

### `GET /api/v1/analysis/findings/{id}`

Return evidence detail for a specific finding in the same published snapshot.
`attack_path` is the literal typed detector witness. It reports `shape`
(`linear`, `branched`, `disconnected`, `cyclic`, or `nodes_only`), continuity,
recorded relationship direction, completeness reasons, and synthetic-join
provenance. `linearization` is present only when every supplied node and edge
forms one complete directed source-to-target path. `total_risk_weight` and
`cost.value` are nullable; any missing relationship weight produces
`cost.state: "incomplete"` rather than a numeric zero. Non-linear,
mixed-direction, and reverse-to-finding evidence has
`cost.state: "not_applicable"` because summing branches is not an attack-path
cost.

Detail starts from the same persisted finding row used by the list. The schema
stores the detector witness graph with each finding snapshot. Detail serves it directly with
`snapshot.evidence_state: "persisted_exact_evidence"` even when the
mutable projection has advanced or is incomplete; detail does not run a second
query or reconstruct evidence from mutable Neo4j.

### `GET /api/v1/findings/triage/{fingerprint}`

Return the cross-scan triage decision for a finding fingerprint (16-char hex). Open read; a fingerprint with no recorded decision returns the implicit `new` state.

```json
{ "status": "accepted-risk", "note": "Approved by sec-review", "updated_at": "2026-06-19T12:00:00Z" }
```

### `PATCH /api/v1/findings/triage/{fingerprint}` *(Origin-gated)*

Update the triage decision for a finding fingerprint. Omitting `note` preserves
the current note; sending `note: ""` clears it. Triage state has no foreign key
to findings, so it survives scan deletion and re-detection.

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
  "rows": [...],
  "projection": { "scan_id": "scan-abc123", "revision": 12 }
}
```

Like findings, pre-built queries carry an optional `atlas_map` (`[]string`) of [MITRE ATLAS](https://atlas.mitre.org/) technique IDs on confidently-mappable queries; it is omitted (`omitempty`) on queries with no ATLAS mapping (e.g. infrastructure/path/chokepoint queries). See the [ATLAS crosswalk](detection-rules.md#mitre-atlas-crosswalk).
`projection` is required on every result. The `shortest-to-database` result
also requires traversal `metadata`; other pre-built results omit it. An
unavailable or changing projection returns `409 PROJECTION_CONFLICT`.

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

## Posture publication

### `GET /api/v1/posture`

Returns the mutable projection state separately from the latest published
revision. When an ingest is updating or incomplete, `scan_id` identifies that
attempt while `published_scan_id` / `published_revision` continue to identify
the last complete snapshot.

### `GET /api/v1/posture/export`

Returns one persisted publication revision. The export is assembled inside the
same PostgreSQL transaction that replaces the scan's finding snapshot and
advances publication. It includes exact scope, stage/coverage completeness,
normalization warnings, managed-observation completeness, observation and
publication timestamps, suppression policy, frozen public graph totals,
comparison metadata, rules provenance, and all findings with the triage state
observed at publication. `scope.dirty_coverage` is always an explicit empty
array for a published revision; `scope.active_coverage_keys` lists all active
coverage heads. `completeness.observation_details` reports property-incomplete
public managed node/raw-relationship counts plus public tokenless-node and raw
relationship-incident-to-tokenless-node counts. Any non-zero count withholds
publication.
`health.state` is
`not_captured` because publication does not
perform a timestamped dependency health probe. `limits.findings` declares
returned/total counts and whether the finding set is complete. It never
combines fresh reads from Neo4j, finding history, and scan history.

Returns `404` until a complete posture has been published.

---

## Scans

Scan records serialize `model.Scan` verbatim. The `status` field is one of:

| Status | Meaning |
|--------|---------|
| `pending` | Registered but not yet started. |
| `running` | Ingest in progress. |
| `completed` | Required collection, graph, analysis, stats, snapshot, and publication stages succeeded. |
| `completed_with_errors` | Graph writes completed, but coverage or a required later stage was incomplete/failed; the prior published posture remains available. |
| `failed` | A graph write failed. `write_rows` preserves rows committed before failure. |

Additive lifecycle fields expose `collection_status`, `graph_status`,
`analysis_status`, `snapshot_status`, `projection_status`, and
`publication_status`. Detailed coverage, rules, identity, stage, and graph
statistics payloads live under `metadata`.
`publication_status` is `published` for the selected revision,
`superseded` for prior published revisions, and `unpublished` otherwise.

Each scan has `submitted: {nodes, edges}`, `write_rows: {nodes, edges}`, and
`graph_totals: {before, after}`. The frozen graph totals are public-inventory
totals, not write counts. Deltas are
comparable only when a non-empty `comparison_key` matches. The key includes
canonical target/config coverage, rules and identity semantics, plus the
revisions of every other active coverage head; the server records
`comparable_to_scan_id` only in that case.

### `GET /api/v1/scans`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Max results |
| `offset` | int | 0 | Pagination offset |
| `revision` | string | | Opaque `page.revision` from the first page |
| `order` | string | `started` | Stable descending order: `started`; latest usable `completed`; or current/latest `published` |

### `POST /api/v1/scans` *(Origin-gated)*

Register a new scan (sets `scan_id`, `started_at`, `status: pending`). Used by the UI's "New scan" flow; CLI ingest creates scan records implicitly.

### `GET /api/v1/scans/{id}`

Get scan details by ID. The Rules view uses this endpoint for an explicit
`?scan=<id>` selection, so provenance is not limited to the newest scan-history
page.

### `DELETE /api/v1/scans/{id}` *(Origin-gated)*

Delete PostgreSQL history only; this endpoint never mutates Neo4j or infers
ownership from scalar `scan_id`. It returns `409 SCAN_DELETE_CONFLICT` for
pending/running scans, active coverage heads, and the currently published
scan. Historical finding rows cascade with the scan; cross-scan triage state
remains.

---

## Rules

### `GET /api/v1/rules`

List the server process's current active YAML detection-rule catalog. This is
not a substitute for the scan-specific `metadata.ruleset` manifest.

### `GET /api/v1/rules/{id}`

Return the parsed definition for one rule in the server's current catalog.

Imported scan records persist their own effective manifest under
`metadata.ruleset`. Each entry includes `type`, `id`, `version`,
`semantic_sha256`, source class, and a canonical `effective_matcher` object.
Read/parse/validation/compile failures are retained in `errors` and reflected
by `load_state`. `digest` and `semantic_sha256` identify content only;
`authenticity: unverified` explicitly disclaims signature/authenticity.
