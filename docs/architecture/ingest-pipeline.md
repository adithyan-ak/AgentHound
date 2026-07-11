# Ingest Pipeline

The server-side ingest pipeline transforms raw collector JSON into a mutable
Neo4j projection and, only after all required stages succeed, publishes an
immutable posture revision in PostgreSQL. It runs as a serialized lifecycle
within `server/internal/ingest/`.

Serialization is intentional: raw observation promotion and post-success
composite cleanup mutate shared ownership epochs. Two concurrent attempts could
otherwise retire one another's fresh tokens.

## Entry Points

- **CLI:** `agenthound-server ingest <file.json>` or `agenthound-server ingest -` (stdin)
- **HTTP:** `POST /api/v1/ingest` (Origin-gated by `OriginGuard`; non-browser callers pass through)
- **UI:** Drag-drop import in Scan Manager (hits the same HTTP endpoint)

All paths invoke `Pipeline.Ingest(ctx, *sdkingest.IngestData)`.

## Wire Contract

Input is the `sdk/ingest.IngestData` struct:

```json
{
  "meta": {
    "version": 1,
    "type": "agenthound-ingest",
    "collector": "mcp",
    "scan_id": "...",
    "collection": {
      "state": "complete",
      "coverage_keys": ["mcp:target:sha256:..."],
      "outcomes": [{
        "collector": "mcp",
        "coverage_key": "mcp:target:sha256:...",
        "target": "https://mcp.example/api",
        "state": "complete"
      }]
    },
    "ruleset": {
      "digest": "sha256:...",
      "load_state": "complete",
      "authenticity": "unverified",
      "entries": [{
        "type": "text",
        "id": "rule-id",
        "version": 1,
        "semantic_sha256": "sha256:...",
        "source": "custom",
        "effective_matcher": {"type": "keyword", "keywords": ["example"]}
      }],
      "errors": []
    },
    "identity_schemes": []
  },
  "graph": {
    "nodes": [{ "id": "sha256:...", "kinds": ["MCPServer"], "properties": {...}, "observation_domains": ["mcp:target:sha256:..."] }],
    "edges": [{ "source": "sha256:...", "target": "sha256:...", "kind": "PROVIDES_TOOL", "properties": {...}, "observation_domains": ["mcp:target:sha256:..."] }]
  }
}
```

Wire version `1` is unchanged. `collection`, `ruleset`,
`identity_schemes`, and `identity_aliases` are optional additive contracts.
Their absence in a legacy artifact means unknown. Collection outcomes
distinguish complete-empty from failed/partial/truncated-empty collection;
ruleset entries persist canonical effective matcher definitions and every
non-fatal load failure. Digests identify semantics but do not attest
authenticity.
`observation_domains` is also optional. A single declared coverage domain can
be attributed unambiguously by the server; merged artifacts preserve each
child collector's per-fact domain. Missing attribution in a multi-domain or
legacy artifact disables retirement.

## Stage 1: Validate

`Validator.Validate()` rejects malformed payloads before any graph writes.

Checks performed:
- `meta.version` must be `1`
- `meta.type` must be `"agenthound-ingest"`
- `meta.collector` must be in `AllowedCollectors` (mcp, a2a, config, scan)
- `meta.scan_id` must be non-empty
- Every node must have a non-empty `id` and at least one `kind` from `AllowedNodeKinds` (23 kinds)
- Every edge must have non-empty `source`/`target` and a `kind` from `RawEdgeKinds` (18 kinds)

Validation errors are structured (`FieldError` with JSON path + message) and returned as a `ValidationError` to the caller. On failure, the pipeline aborts -- no partial writes.

## Stage 2: Normalize

`Normalizer.Normalize()` transforms collector output into Neo4j-ready shape and
returns deterministic typed warnings. Lossless coercions are classified
`warning` and do not block publication. Dropped properties and normalized-key
collisions are classified `degraded`, marked `publication_unsafe`, and prevent
replacement/reconciliation/publication for that attempt.

Transformations:
- Sets `objectid` property to match node `id`
- Converts all property keys from camelCase to snake_case (`CamelToSnake`)
- Strips nil values
- Serializes complex values (nested maps, heterogeneous arrays) to JSON strings
- Preserves homogeneous arrays (all-string, all-number, all-bool) as native Neo4j lists
- Converts `json.Number` to `int64` or `float64`

## Stage 3: Record Scan and Projection Start

Creates or restarts a scan record with status `running` and atomically marks
the singleton projection state `updating`. Dirty coverage is the sorted union
of inherited dirty keys and every key attempted by this scan; beginning a
narrow scan never erases unrelated dirty MCP, A2A, or config scope. In
production this persistence is required before graph mutation.

## Stages 4–6: Freeze and Write (Neo4j Batch)

The pipeline freezes public graph totals before mutation, then
`graph.Writer.WriteNodes()` and `graph.Writer.WriteEdges()` batch-write to
Neo4j.

Implementation details:
- Uses `UNWIND $nodes AS node` pattern for batch efficiency
- 1000 operations per transaction (configurable batch size)
- Multi-label support: nodes carry multiple `kinds` (e.g., `["OllamaInstance", "AIService"]`); the writer MERGEs on the primary label and SETs umbrella labels
- Merge strategy: `MERGE` by `objectid`. A complete observation replaces
  properties only when it replaces every active owner of that fact; partial,
  shared-unreplaced, and unknown observations remain additive/non-destructive.
  This removes omitted stale managed properties without erasing unrelated
  owners. Additive updates are marked property-incomplete and block global
  publication until a complete observation replaces every active owner.
- New facts carry length-delimited observation owner tokens. Shared facts keep
  one token per active coverage domain.
- Existing pre-lifecycle facts are marked `legacy_observation` and remain
  non-destructive. A complete exact re-observation replaces their properties
  and migrates them to managed ownership.
- On merge, preserves `previous_description_hash` for rug-pull detection: `ON MATCH SET n.previous_description_hash = n.description_hash`
- Edge writes use per-kind Cypher strings (`edgeKindCypher` map) to support different source/target label pairs per edge kind
- `EdgeKindEndpoints` registry resolves source/target labels when not explicitly set by the collector

Each 1000-row batch commits independently. On failure, the scan and HTTP error
details preserve the actual node/edge write rows committed before the failed
batch, and the projection is marked incomplete.

## Stage 7: Reconcile stdio Identity Compatibility

When an artifact carries stdio-v1 compatibility aliases, the server queries
Neo4j for every already-persisted v2 node with the same `legacy_objectid`.
Only a complete one-candidate claim that remains one-candidate in the graph is
persisted as `one_to_one`. Multiple candidates quarantine the legacy aggregate
and all candidate nodes without changing their relationships. A proven
one-to-one alias is migrated in one Neo4j transaction: node properties and
observation owners are merged into the v2 node, every allowlisted incoming,
outgoing, and self-relationship is merged without fan-out, and the v1 node is
deleted. The transaction rechecks that the exact v2 target exists and remains
the sole candidate; it uses static per-kind Cypher and does not require APOC.
A failed compatibility write disables observation promotion and publication
for the attempt.

## Stage 8: Reconcile Complete Observation Domains

Only domain states derived as explicit `complete` outcomes may replace their
prior owner token. Reconciliation removes old owner tokens, deletes unowned raw
relationships, then deletes unowned isolated nodes. Facts with another active
owner survive. Partial, failed, truncated, unknown, and unattributed legacy
coverage performs no retirement.

Coverage keys are target/config scoped opaque hashes (for example,
`mcp:target:sha256:...`, `a2a:target:sha256:...`, and
`config:path:sha256:...`). The same keys drive per-fact ownership,
reconciliation, dirty-state repair, coverage heads, and comparison keys. A
successful scan of target B therefore cannot retire target A. Published
comparison keys also include the scan revisions of every *other* active
coverage head, so global graph deltas are withheld when an intervening target
or config scope changed.

## Stages 9–13: Analyze, Snapshot, and Publish

`analysis.RunPostProcessors()` computes composite edges and risk scores from graph state.

It runs all 15 processors in dependency-validated order. Prior composite edges
remain until every processor succeeds; only then does the pipeline delete
composite edges not refreshed by the current scan within the
dependency-expanded complete collector scope. See
`docs/architecture/post-processors.md`.

After analysis, the pipeline explicitly counts legacy/unknown raw observations,
including pre-target-scope collector-wide ownership tokens, incomplete
property ownership, and quarantined stdio identities. Their presence is
persisted as an incomplete required stage and the `legacy:unknown` dirty
sentinel until every such fact is migrated, re-observed, or resolved. The
pipeline then freezes a second public graph total and queries
the candidate finding snapshot. PostgreSQL finalization atomically replaces all
finding rows for the scan (including a successful empty retry), advances
complete coverage heads, finalizes scan state, and optionally inserts a
persisted export/publication revision. Analysis, stats, or snapshot failure
withholds publication and leaves the prior published revision available.
Finalization re-locks cumulative dirty state and publishes only when no inherited
or current dirty key remains.

## Processing Order

The annotations below are each processor's declared `Dependencies() []string` return — the *processor-level* ordering contract enforced by the pipeline. Raw collector edges (`INGESTS_UNTRUSTED`, `DELEGATES_TO`, `HAS_ENV_VAR`, etc.) and pre-existing node properties (`schema_keys`, `auth_method`, …) are Cypher traversal inputs, not processor dependencies — they are present from ingest, so they do not appear here.

```
 1. auth_strength                    (deps: none; pre-pass, sets node property)
 2. has_access_to                    (deps: none)
 3. can_execute                      (deps: none)
 4. shadows                          (deps: none; also emits POISONS_CONTEXT)
 5. poisoned_description             (deps: none)
 6. poisoned_instructions            (deps: none)
 7. taints                           (deps: none; runs before can_reach so its cross-tool
                                     edges influence transitive reachability)
 8. can_reach                        (deps: has_access_to)
 9. cross_service_credential_chain   (deps: has_access_to, can_reach)
10. ifc_violation                    (deps: has_access_to)
11. can_exfiltrate                   (deps: can_reach)
12. can_impersonate                  (deps: none)
13. confused_deputy                  (deps: auth_strength, can_reach)
14. cross_protocol                   (deps: has_access_to)
15. risk_score                       (deps: has_access_to, can_execute, shadows,
                                     poisoned_description, poisoned_instructions,
                                     can_reach, can_exfiltrate, can_impersonate,
                                     cross_protocol)
```

Dependency validation runs before the first processor executes. If a processor appears before a dependency it declares, the pipeline returns an ordering error immediately.

## Result

`Pipeline.Ingest()` returns `*sdkingest.IngestResult`:
- `ScanID` -- the scan identifier
- `Outcome`, `ProjectionStatus` -- attempt result and mutable projection state
- `NodesWritten`, `EdgesWritten` -- Neo4j write-result rows (compatibility
  fields, not unique discoveries)
- `NodesSubmitted`, `EdgesSubmitted`, `CountSemantics` -- literal artifact row
  counts and the interpretation of the legacy write counts
- `Warnings` -- normalizer warnings
- `NormalizationStatus`, `NormalizationWarnings` -- deterministic
  `complete`/`warning`/`degraded` classification, codes, context, and the
  explicit publication-safety bit
- `Collection` -- optional collection report echoed by integrations that carry it
- `Stages` -- typed required/optional outcomes (`complete`, `partial`,
  `failed`, `truncated`, `unknown`, `not_applicable`)
- `PostProcessingStats` -- per-processor name, edges created, nodes updated, duration, error
- `GraphBefore`, `GraphAfter`, `PublishedRevision` -- frozen public totals and
  the revision published by this attempt, when any
- `Duration` -- total pipeline wall-clock time

## Scan Lifecycle

```
Created --> Running / Projection updating --> Completed + Published
                                      \-----> Completed with errors / Projection incomplete
                                      \-----> Failed / Projection incomplete
```

Terminal statuses:
- `completed` — complete attributable coverage, graph reconciliation,
  analysis, graph totals, finding snapshot, and publication succeeded.
- `completed_with_errors` — graph writes completed but coverage or a required
  later stage was degraded; the previous published posture remains selected.
- `failed` — a raw graph write failed; actual committed write rows and the
  failed stage are persisted.

The scan row stores summary lifecycle/publication state and frozen totals;
metadata JSONB stores detailed coverage, rules, identity, normalization
warnings, observation completeness, stage, count, and reconciliation payloads.
`coverage_heads` records active raw ownership.
`posture_state` separates the current mutable attempt from the selected
published revision.

`DELETE /api/v1/scans/{id}` is history-only. It never mutates Neo4j and rejects
pending/running, active coverage-head, and currently published scans.
