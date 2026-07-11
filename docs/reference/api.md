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

Error codes: `VALIDATION_ERROR` (400), `FORBIDDEN` (403), `NOT_FOUND` (404), `REVISION_CONFLICT` (409), `SERVICE_UNAVAILABLE` (503), `INTERNAL_ERROR` (500). Internal errors include a request ID for log correlation; raw error strings are not leaked to clients.

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

Returns public node and edge counts by kind. Internal `SchemaVersion` nodes and
the reserved, unimplemented `ResourceGroup`/`TrustZone` labels are excluded
from stats, node lists, and search results.

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
| `offset` | int | 0 | Nonnegative pagination offset |
| `revision` | string | | Opaque `X-Revision` from the first page |

Node, edge, and scan list bodies remain JSON arrays. Pagination metadata is
additive in `X-Total-Count`, `X-Has-More`, `X-Offset`,
`X-Collection-Complete`, and `X-Revision`; `X-Truncated` remains an exact
compatibility alias for `X-Has-More`. Continue with the same revision token.
A graph change returns `409 REVISION_CONFLICT`; restart at offset 0.
These headers describe page/read completeness only; they do not assert that
collector coverage or analysis stages completed.

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
| `revision` | string | | Opaque `X-Revision` from the first page |

---

## Ingest

### `POST /api/v1/ingest` *(Origin-gated)*

**Max body:** 100 MB.

Upload collector JSON output. Runs the serialized lifecycle: validate →
normalize → freeze pre-write totals → write → reconcile complete observation
domains → post-process → freeze post-analysis totals → snapshot → publish.

```json
// Request body: collector JSON output (see graph-model.md for schema)

// Response (200)
{
  "scan_id": "scan-abc123",
  "outcome": "complete",
  "projection_status": "complete",
  "nodes_written": 47,
  "edges_written": 82,
  "nodes_submitted": 47,
  "edges_submitted": 82,
  "count_semantics": "neo4j_write_rows_v1",
  "stages": [
    { "name": "write_nodes", "state": "complete", "required": true }
  ],
  "published_revision": 12,
  "warnings": [],
  "normalization_status": "complete",
  "normalization_warnings": [],
  "duration": 1230000000
}
```

`nodes_written` and `edges_written` are retained compatibility fields. They
count Neo4j write-result rows, including matches of existing facts; they are
not unique discoveries. A batch failure returns `500 INGEST_FAILED` with this
same partial result under `error.details`, including the rows committed before
the failure. The scan and global projection state are marked incomplete.

Only explicitly complete, attributable target/config coverage keys can retire
prior raw observations. Missing legacy coverage and partial/failed/truncated
collection never retire data and never replace the latest published posture.
Lossless normalization coercions are persisted as `warning` and may publish;
only warnings explicitly marked `publication_unsafe` produce `degraded` and
withhold publication.

---

## Analysis

### `POST /api/v1/analysis/shortest-path` *(Origin-gated)*

Find a bounded hop-shortest path between two nodes. `scope` defaults to
`security`, following the explicit directed security relationship policy.
`scope: "topology"` explicitly requests the legacy undirected graph view.

```json
// Request
{
  "source": "my-agent",
  "source_kind": "AgentInstance",
  "target": "postgres://prod",
  "target_kind": "MCPResource",
  "scope": "security",
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
  "algorithm": "bounded-min-weight",
  "metadata": {
    "scope": "security",
    "direction": "out",
    "relationship_kinds": ["TRUSTS_SERVER", "PROVIDES_TOOL", "HAS_ACCESS_TO"],
    "max_hops": 10,
    "algorithm": "bounded-min-weight",
    "complete": true
  }
}
```

### `POST /api/v1/analysis/all-paths` *(Origin-gated)*

Enumerate paths between two nodes under the same explicit scope, bounded by
`max_hops`, `limit`, and the server expansion cap. Same request as
shortest-path, plus:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 10 | Max paths returned (1–100) |

### `POST /api/v1/analysis/weighted-path` *(Origin-gated)*

Find the bounded minimum-risk-weight path with one deployment-independent
algorithm. APOC availability does not change results. Missing `risk_weight`
uses the disclosed compatibility default `0.5`; negative or non-finite values
fail the request. The response includes `"algorithm": "bounded-min-weight"`
and traversal completeness metadata.

### `GET /api/v1/analysis/findings`

List findings from Postgres with inline `triage` state.

| Param | Type | Description |
|-------|------|-------------|
| `severity` | string | Filter: `critical`, `high`, `medium`, `low` |
| `include_suppressed` | bool | Default `false`. When `true`, include findings triaged `accepted-risk` / `false-positive` (hidden otherwise). |
| `scope` | string | `published` returns exactly the current published scan. Omitted/`history` preserves the legacy latest-per-fingerprint historical union. |

Published responses identify their immutable source via
`X-Snapshot-Scan-ID` and `X-Published-Revision`. They also expose
`X-Projection-Status`, `X-Snapshot-Status`, `X-Snapshot-Available`, and
`X-Snapshot-Stale`; a partial live Neo4j projection does not move the published
pointer. Clients require explicit available/complete/non-stale metadata before
interpreting an empty array as a current all-clear. A failed refresh may show
cached rows only when they are labelled as cached rather than current.

Each finding carries an `owasp_map` (`[]string`) and, where the technique mapping is unambiguous, an `atlas_map` (`[]string`) of [MITRE ATLAS](https://atlas.mitre.org/) technique IDs (e.g. `["AML.T0051", "AML.T0110"]`). `atlas_map` is omitted when empty (`omitempty`); detections AgentHound has not confidently mapped carry no ATLAS tag. `variant` and the typed `evidence` object are persisted with the same scan row, so a published credential reference cannot be silently reclassified from a later live graph. Legacy rows use `variant: "unknown"` and `evidence.state: "unknown"`. See the [ATLAS crosswalk](detection-rules.md#mitre-atlas-crosswalk) for the per-edge mapping.

Upgrade migration 008 deterministically backfills empty historical
`atlas_map` values from `edge_kind` using that same crosswalk. Existing
non-empty mappings are preserved.

### `GET /api/v1/analysis/findings/{id}`

Return evidence detail for a specific finding. `attack_path` is a literal typed
evidence graph, despite the compatibility field name. It reports `shape`
(`linear`, `branched`, `disconnected`, `cyclic`, or `nodes_only`), continuity,
recorded relationship direction, completeness reasons, and synthetic-join
provenance. `linearization` is present only when every supplied node and edge
forms one complete directed source-to-target path. `total_risk_weight` and
`cost.value` are nullable; any missing relationship weight produces
`cost.state: "incomplete"` rather than a numeric zero. Non-linear,
mixed-direction, and reverse-to-finding evidence has
`cost.state: "not_applicable"` because summing branches is not an attack-path
cost.

With `scope=published`, detail starts from the same persisted finding row used
by the published list. Migration `007_exact_finding_evidence.sql` adds the
persisted detector witness graph. New snapshots serve that graph directly with
`snapshot.live_evidence_state: "persisted_exact_evidence"` even when the
mutable projection has advanced or is incomplete; detail does not run a second
`LIMIT 1` reconstruction query. Legacy rows have no recoverable exact witness
and return `attack_path: null` with unavailable evidence rather than borrowing
a later graph match. Omitted scope reads the current finding set, but still
uses the witness references captured by the detector.

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
coverage heads. `completeness.observation_details` reports legacy, unscoped,
property-incomplete node/relationship counts and identity-quarantined nodes.
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
| `failed` | A graph write failed. `node_count` / `edge_count` preserve the write rows committed before failure. |

Additive lifecycle fields expose `collection_status`, `graph_status`,
`analysis_status`, `snapshot_status`, `projection_status`, and
`publication_status`. Detailed coverage, rules, identity, stage, and graph
statistics payloads live under `metadata`.
`publication_status` is `published` for the selected revision,
`superseded` for prior published revisions, and `unpublished` otherwise.

`node_count` and `edge_count` are deprecated write-row counters. Frozen
`graph_total_*_before/after` fields are public-inventory totals. Deltas are
comparable only when a non-empty `comparison_key` matches. The key includes
canonical target/config coverage, rules and identity semantics, plus the
revisions of every other active coverage head; the server records
`comparable_to_scan_id` only in that case.

### `GET /api/v1/scans`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Max results |
| `offset` | int | 0 | Pagination offset |
| `revision` | string | | Opaque `X-Revision` from the first page |
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
