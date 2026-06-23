# Ingest Pipeline

The server-side ingest pipeline transforms raw collector JSON into a Neo4j trust graph. It runs as a serialized 5-stage process within `server/internal/ingest/`.

Serialization is intentional: the post-processing stage's stale-edge cleanup scopes deletes by `source_collector`, so two concurrent ingests from the same collector would each treat the other's fresh edges as stale. Single-user server, rare operator-driven ingests, no concurrent UI uploads -- serialization via `sync.Mutex` is the correct trade-off.

## Entry Points

- **CLI:** `agenthound-server ingest <file.json>` or `agenthound-server ingest -` (stdin)
- **HTTP:** `POST /api/v1/ingest` (Origin-gated by `OriginGuard`; non-browser callers pass through)
- **UI:** Drag-drop import in Scan Manager (hits the same HTTP endpoint)

All paths invoke `Pipeline.Ingest(ctx, *sdkingest.IngestData)`.

## Wire Contract

Input is the `sdk/ingest.IngestData` struct:

```json
{
  "meta": { "version": 1, "type": "agenthound-ingest", "collector": "mcp", "scan_id": "..." },
  "graph": {
    "nodes": [{ "id": "sha256:...", "kinds": ["MCPServer"], "properties": {...} }],
    "edges": [{ "source": "sha256:...", "target": "sha256:...", "kind": "PROVIDES_TOOL", "properties": {...} }]
  }
}
```

## Stage 1: Validate

`Validator.Validate()` rejects malformed payloads before any graph writes.

Checks performed:
- `meta.version` must be `1`
- `meta.type` must be `"agenthound-ingest"`
- `meta.collector` must be in `AllowedCollectors` (mcp, a2a, config, scan)
- `meta.scan_id` must be non-empty
- Every node must have a non-empty `id` and at least one `kind` from `AllowedNodeKinds` (23 kinds)
- Every edge must have non-empty `source`/`target` and a `kind` from `RawEdgeKinds` (17 kinds)

Validation errors are structured (`FieldError` with JSON path + message) and returned as a `ValidationError` to the caller. On failure, the pipeline aborts -- no partial writes.

## Stage 2: Normalize

`Normalizer.Normalize()` transforms collector output into Neo4j-ready shape. Returns warnings (non-fatal).

Transformations:
- Sets `objectid` property to match node `id`
- Converts all property keys from camelCase to snake_case (`CamelToSnake`)
- Strips nil values
- Serializes complex values (nested maps, heterogeneous arrays) to JSON strings
- Preserves homogeneous arrays (all-string, all-number, all-bool) as native Neo4j lists
- Converts `json.Number` to `int64` or `float64`

## Stage 3: Record Scan Start

Creates a scan record in PostgreSQL (`appdb.ScanStore`) with status `running`. Non-fatal on failure (logs warning, continues). This provides the scan history visible in the UI.

## Stage 4: Write (Neo4j Batch)

`graph.Writer.WriteNodes()` and `graph.Writer.WriteEdges()` batch-write to Neo4j.

Implementation details:
- Uses `UNWIND $nodes AS node` pattern for batch efficiency
- 1000 operations per transaction (configurable batch size)
- Multi-label support: nodes carry multiple `kinds` (e.g., `["OllamaInstance", "AIService"]`); the writer MERGEs on the primary label and SETs umbrella labels
- Merge strategy: `MERGE` by `objectid` -- same node from Config + MCP collectors merges properties (last-write-wins)
- On merge, preserves `previous_description_hash` for rug-pull detection: `ON MATCH SET n.previous_description_hash = n.description_hash`
- Edge writes use per-kind Cypher strings (`edgeKindCypher` map) to support different source/target label pairs per edge kind
- `EdgeKindEndpoints` registry resolves source/target labels when not explicitly set by the collector

On failure, the scan record is updated to `failed` and the error propagates.

## Stage 5: Post-Process

`analysis.RunPostProcessors()` computes composite edges and risk scores from graph state.

Before running processors:
1. **Stale-edge cleanup:** Deletes composite edges where `scan_id != current AND source_collector IN $collectors`. This scopes deletion to only the collector(s) that ran in the current scan -- prevents ping-pong deletion on partial scans (e.g., an MCP-only re-scan won't delete A2A composite edges).

Then runs 11 processors in dependency-validated order. See `docs/architecture/post-processors.md` for details.

Post-processing is non-fatal to the ingest: failures are logged and included in the result stats, and the written nodes/edges stay queryable (a processor bug won't block data). The scan is, however, recorded as `completed_with_errors` — the real node/edge counts plus the `post-processing: ...` error — rather than `completed`, so an analysis failure is surfaced instead of reported as a clean success.

## Processing Order

```
1.  has_access_to               (no deps)
2.  can_execute                  (no deps)
3.  shadows                      (no deps)
4.  poisoned_description         (no deps)
5.  poisoned_instructions        (no deps)
6.  can_reach                    (depends: has_access_to)
7.  cross_service_credential_chain (depends: has_access_to, can_reach)
8.  can_exfiltrate               (depends: can_reach)
9.  can_impersonate              (no deps)
10. cross_protocol               (depends: has_access_to)
11. risk_score                   (depends: all above)
```

Dependency validation runs before the first processor executes. If a processor appears before a dependency it declares, the pipeline returns an ordering error immediately.

## Result

`Pipeline.Ingest()` returns `*sdkingest.IngestResult`:
- `ScanID` -- the scan identifier
- `NodesWritten`, `EdgesWritten` -- counts from the batch write
- `Warnings` -- normalizer warnings
- `PostProcessingStats` -- per-processor name, edges created, nodes updated, duration, error
- `Duration` -- total pipeline wall-clock time

## Scan Lifecycle

```
Created (POST /api/v1/scans) --> Running (ingest starts) --> Completed | Completed with errors | Failed
```

Terminal statuses:
- `completed` — node/edge collection and analysis post-processing both succeeded.
- `completed_with_errors` — node/edge writes succeeded (real counts persisted) but post-processing returned an error; the `error` field carries the `post-processing: ...` detail.
- `failed` — collection/write failure; counts are `0, 0` and the `error` field carries the write error.

The scan record in Postgres tracks: ID, collector, status, start time, node/edge counts, error message. Scans can be deleted via `DELETE /api/v1/scans/{id}`, which also removes owned edges/nodes from Neo4j.
