# API reference

`agenthound-server serve` exposes the dashboard and REST API on `127.0.0.1:8080` by default. API routes use the `/api/v1` prefix.

The live OpenAPI document at `GET /api/v1/docs` is the field-level contract. This page describes how to use the endpoint groups.

## Access model

The server is a single-user application without an application login. Keep it on loopback or place it behind your own VPN, SSH tunnel, or authenticated reverse proxy.

Read endpoints are available to the local client. Mutating browser requests must send an `Origin` allowed by `AGENTHOUND_CORS_ORIGINS`. Non-browser clients without an `Origin` header can use mutating endpoints directly.

JSON responses use conventional HTTP status codes. Invalid request bodies return `400`; missing resources return `404`; projection conflicts return `409`; internal storage or analysis failures return `500` or `503` as appropriate.

## Endpoints

| Area | Method and path | Purpose |
|---|---|---|
| Health | `GET /health` | Report API and storage readiness. |
| Schema | `GET /docs` | Serve OpenAPI JSON. |
| Graph | `GET /graph/stats`, `/graph/search`, `/graph/nodes`, `/graph/nodes/{id}`, `/graph/nodes/{id}/neighborhood`, `/graph/nodes/{id}/blast-radius`, `/graph/edges` | Inspect the published graph. |
| Ingest | `POST /ingest` | Validate and ingest one complete `{meta, graph}` envelope. |
| Security paths | `POST /analysis/shortest-path`, `/analysis/all-paths`, `/analysis/weighted-path` | Traverse directed security relationships. |
| Topology paths | `POST /analysis/topology/shortest-path`, `/analysis/topology/all-paths`, `/analysis/topology/weighted-path` | Explore undirected graph connectivity. |
| Findings | `GET /analysis/findings`, `GET /analysis/findings/{id}` | List findings or retrieve detail with its persisted evidence subgraph. |
| Prebuilt analysis | `GET /analysis/prebuilt`, `GET /analysis/prebuilt/{id}` | List or execute registered security queries. |
| Triage | `GET`, `PATCH /findings/triage/{fingerprint}` | Read or update a finding's cross-scan triage state. |
| Posture | `GET /posture`, `GET /posture/export` | Summarize and export the current published posture. |
| Scans | `GET /scans`, `POST /scans`, `GET`, `DELETE /scans/{id}` | Inspect scan history and manage scan records. |
| Rules | `GET /rules`, `GET /rules/{id}` | Inspect the compiled detection rules. |
| Cypher | `POST /query` | Execute an explicit administrative Cypher query. |

## Published projection

Normal graph, finding, path, posture, and prebuilt-query reads use one published projection. Responses that include projection identity report its scan ID and publication revision. If the current projection is incomplete, guarded analysis endpoints fail instead of mixing revisions.

Raw administrative Cypher reads the live graph and is intended for operators who explicitly need storage-level access.

## Ingest

The ingest body is a complete V1 envelope:

```json
{
  "meta": {
    "version": 1,
    "type": "agenthound-ingest",
    "collector": "scan",
    "scan_id": "..."
  },
  "graph": {
    "nodes": [],
    "edges": []
  }
}
```

The full schema requires collection identity, timestamps, coverage semantics, valid node and edge kinds, and consistent property types. Use the collector artifact directly rather than constructing envelopes by hand.

Scan execution data remains under `meta.extra.scan_execution`. The server stores the complete record in `metadata.artifact_extra.scan_execution` and promotes its mode, deep flag, status, timestamps, and summary for scan-history views.

## Findings

Finding list entries include severity, category, affected endpoints, confidence, variant, evidence state, framework mappings, and triage. A scan-verified path includes a bounded `evidence.proof` object. Resource contents and raw credential values stay on their graph nodes instead of being copied into finding metadata.

Finding detail adds the exact evidence nodes and edges selected during publication. `INSTRUCTION_SIGNAL` and `POISONED_INSTRUCTIONS` details also include `instruction_evidence`: file path, scope, verdict, metadata, total and truncation counts, retained source-exact excerpts with positions, and decoded previews when an encoded payload contributes to the verdict. For encoded signals, `match` may be a bounded excerpt of a larger token and is selected to contain the bytes corresponding to the decisive decoded semantics. This larger object is intentionally absent from finding lists.

Explicit graph and query responses can contain raw Credential `value` properties and literal instruction evidence JSON; clients must treat them as sensitive operator evidence.

## Path requests

Path selectors use node IDs or `Kind:name` values. Security traversal follows directed policy relationships. Topology traversal treats graph connectivity as undirected and should be used for investigation rather than exploitability claims.

Weighted traversal prefers lower-cost relationships. All-paths queries are bounded by server limits defined in the OpenAPI schema.
