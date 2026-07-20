# Ingest Pipeline

The server-side ingest pipeline transforms raw collector JSON into a mutable
Neo4j projection and, only after all required stages succeed, publishes an
immutable posture revision in PostgreSQL. It runs as a serialized lifecycle
within `server/internal/ingest/`.

Serialization is intentional: raw observation promotion and global composite
epoch replacement mutate shared graph state. Two concurrent attempts could
otherwise retire one another's fresh tokens or derived epoch.

## Entry Points

- **CLI:** `agenthound-server ingest <file.json>` or `agenthound-server ingest -` (stdin)
- **HTTP:** `POST /api/v1/ingest` (Origin-gated by `OriginGuard`; non-browser callers pass through)
- **UI:** Drag-drop import in Scan Manager (hits the same HTTP endpoint)

All paths invoke `Pipeline.Ingest(ctx, *sdkingest.IngestData)`.
Every ingest requires the lifecycle store's `BeginScan` and `RecordFailure`
operations and the publication store's atomic `FinalizeScan`; there is no
non-publishing compatibility path.

## Wire Contract

Input is the `sdk/ingest.IngestData` struct:

```json
{
  "meta": {
    "version": 3,
    "type": "agenthound-ingest",
    "collector": "mcp",
    "scan_id": "...",
    "origin": {
      "host_id": "security-laptop",
      "network_realm_id": "corp-lab"
    },
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
    "identity_schemes": [{
      "entity_kind": "MCPServer",
      "transport": "stdio",
      "scheme": "mcp_stdio_v3_hashed_argv",
      "version": 3
    }]
  },
  "graph": {
    "nodes": [{ "id": "sha256:...", "kinds": ["MCPServer"], "properties": {...}, "observation_domains": ["mcp:target:sha256:..."] }],
    "edges": [{ "source": "sha256:...", "target": "sha256:...", "kind": "PROVIDES_TOOL", "source_kind": "MCPServer", "target_kind": "MCPTool", "properties": {...}, "observation_domains": ["mcp:target:sha256:..."] }]
  }
}
```

Wire version `3` is the only accepted contract; v1 and v2 artifacts are
rejected. `origin`, `collection`, `ruleset`, and `identity_schemes` are
required. Origin IDs are exact canonical identifiers for the collector host
and its private-network realm. Every collection outcome names a canonical
scoped coverage key, target, method, and explicit state; complete-empty
collection is represented by an outcome with `items: 0`. Ruleset entries
persist canonical effective matcher definitions and every non-fatal load
failure. Digests identify semantics but do not attest authenticity.
Stdio MCP server nodes publish an ordered `arg_hashes` array and matching
`arg_count`; raw argv remains collector-local and is rejected by ingest. Every
MCP server rejects executable `args`, `env`, `headers`, and `url` properties
regardless of its declared transport. Every present MCP `endpoint` must be valid
and already equal the canonical output of `SanitizeHTTPEndpoint`, even when the
transport discriminator is missing or malformed. Authoritative MCP servers
require the canonical string transport `http` or `stdio`; HTTP requires the
endpoint property, while stdio publishes `command` and omits `endpoint`.
User-info, query, fragments, invalid raw endpoint text, and the fixed invalid
placeholder cannot enter the graph. Property-neutral `reference_only` endpoints
remain exempt from authoritative property requirements.
Every node and edge must carry one or more `observation_domains` drawn from the
declared coverage keys. The server never infers fact ownership from a
single-domain report. A node may set `property_semantics: "reference_only"` to
assert only its ID and kinds; that mode requires an empty `properties` object.
Omitting `property_semantics` remains an authoritative property observation.
Edge endpoint kinds are likewise explicit in v3.

### Eligible-rule semantic digest boundary

A text rule's `semantic_sha256` normally hashes the canonicalized rule shape
alone. For a rule that participates in the config instruction canonical shadow
(finding type `has_injection_patterns`, scope `config`/`all`, target
`instruction.content`), the digest payload additionally binds the canonicalizer
version string `instruction-shadow-v1+unicode-15.0.0`, built as
`"instruction-shadow-v1+unicode-" + norm.Version` (currently Unicode 15.0.0). An
eligible rule's semantic identity changes when its canonicalized rule shape
changes and additionally when the frozen V1 transform contract or its Unicode
edition changes. Ineligible rules do not bind the canonicalizer version. The
version string is a digest-payload boundary only: it is never serialized into
the manifest JSON, does not alter the manifest's field shape, and does not
change `authenticity`, which remains `unverified` because a digest attests
content identity, not source trust.

Dynamic exhaustive collectors also declare `authoritative_roots`, pairing the
stable collector-root key with the complete current child-key set. After a
completed root run, previously headed children absent from that set are
reconciled as complete-empty and their heads are retired. Targeted, partial,
failed, and otherwise non-exhaustive runs do not declare authoritative roots
and cannot retire sibling scopes.

## Stage 0: Admit Collection Realm and Storage Pair

Before generic validation or any lifecycle/audit write, the pipeline invokes a
mandatory admission guard. It rereads immutable binding markers from both
PostgreSQL and Neo4j on every ingest, verifies their marker version, exact
host/realm tuple, and shared storage-pair UUID, then compares the artifact's
`meta.origin` with the configured tuple.

This ordering is a security and data-integrity boundary. A wrong-realm or
unverifiable-storage artifact cannot create a failed scan row, persist a
campaign-rejection audit, retire lifecycle coverage, or touch the graph.
PostgreSQL stores the internal singleton binding row; Neo4j stores an internal
`AgentHoundStorageBinding` node. Neither is part of the public graph API,
inventory counts, search, or collector wire format.

## Stage 1: Validate

`Validator.Validate()` rejects malformed payloads before any graph writes.

Checks performed:
- `meta.version` must be `3`; v1 and v2 are rejected
- `meta.origin` must contain canonical exact `host_id` and `network_realm_id`
- `meta.type` must be `"agenthound-ingest"`
- `meta.collector` must be in `AllowedCollectors` (mcp, a2a, config, scan)
- collector version, RFC3339 timestamp, and scan ID must be non-empty
- collection, ruleset, and current identity-scheme metadata must be complete
- coverage keys must use `<collector>:<scope>:sha256:<digest>`
- every raw fact must carry explicit declared observation domains
- Every node must have a non-empty `id` and at least one `kind` from `AllowedNodeKinds` (23 kinds)
- Every edge must have non-empty `source`/`target` and a `kind` from `RawEdgeKinds` (20 kinds)
- v1 property aliases are rejected; canonical status/evidence fields are
  required for credentials, hosts, MCP servers, and A2A agents
- configured MCP/A2A method, assurance, and evidence must form a
  producer-compatible tuple
- MCP observed auth must be a complete protocol-valid tuple; A2A observed auth
  is accepted only for the exact bounded nonexistent-task positive probe with
  its method and status metadata

Validation errors are structured (`FieldError` with JSON path + message) and returned as a `ValidationError` to the caller. On failure, the pipeline aborts -- no partial writes.

## Stage 2: Normalize

`Normalizer.Normalize()` transforms collector output into Neo4j-ready shape and
returns deterministic typed warnings. Property keys must already be canonical
snake_case because validation runs first. Lossless value coercions are
classified `warning` and do not block publication. Dropped properties are
classified `degraded`, marked `publication_unsafe`, and prevent
replacement/reconciliation/publication for that attempt.

Transformations:
- Sets `objectid` property to match node `id`
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
  one token per active coverage domain. Complete authoritative writes also
  retain an internal stable-domain semantic fingerprint. Collectors and the
  ingest pipeline preserve one contribution per owner domain; the writer
  fingerprints each contribution before deterministically unioning compatible
  contributions into one database fact. Conflicting overlapping semantic
  values fail the write before graph execution instead of selecting a value by
  input order. A co-owner can rotate its scan token without downgrading the
  union only when its new fingerprint exactly matches the one already recorded
  for that domain. Writer/observation timestamps (`scan_id`, `first_seen`,
  `last_seen`, `last_verified_at`, and `extracted_at`) are excluded from this
  comparison; the latest timestamp wins when contributions are unioned. Any
  other collected-property, label, endpoint-kind, or observation-semantics
  change remains property-incomplete while another owner is active. Such an
  incompatible targeted refresh preserves the last coherent public properties
  and labels, invalidates that owner's stored fingerprint, and cannot be
  re-certified by retrying an older targeted artifact. A complete joint write,
  or an exact remaining-owner write after the other owners retire, replaces the
  fact and restores completeness.
- Reference-only node observations add ownership without merging managed
  properties or downgrading an existing complete authoritative observation.
  Their owner tokens are tracked as an explicit subset of node owners.
- On merge, preserves `previous_description_hash` for rug-pull detection: `ON MATCH SET n.previous_description_hash = n.description_hash`
- Edge writes use per-kind Cypher strings selected from the explicitly
  validated `source_kind` and `target_kind` values

Each 1000-row batch commits independently. On failure, the scan and HTTP error
details preserve the actual node/edge write rows committed before the failed
batch, and the projection is marked incomplete.

## Stage 7: Reconcile Complete Observation Domains

Only domain states derived as explicit `complete` outcomes may replace their
prior owner token. Reconciliation removes old owner tokens, deletes unowned raw
relationships, then deletes unowned isolated nodes. Facts with another active
owner survive. Partial, failed, truncated, and unknown coverage performs no
retirement. Stable semantic fingerprints are retired with their authoritative
owner domain and are never returned by the public graph reader.
When reconciliation retires a node's last authoritative property owner but a
reference-only owner remains, managed properties are cleared to truthful
reference identity instead of certifying stale rich properties.

Coverage keys are target/config scoped opaque hashes (for example,
`mcp:target:sha256:...`, `a2a:target:sha256:...`, and
`config:path:sha256:...`). The same keys drive per-fact ownership,
reconciliation, dirty-state repair, coverage heads, and comparison keys. A
successful scan of target B therefore cannot retire target A. Published
comparison keys also include the scan revisions of every *other* active
coverage head, so global graph deltas are withheld when an intervening target
or config scope changed.

## Stages 8–12: Analyze, Snapshot, and Publish

`analysis.RunPostProcessors()` computes composite edges and risk scores from graph state.

It runs all 15 processors in dependency-validated order. When any complete raw
domain was promoted, the pipeline first retires the entire prior composite
epoch, then rebuilds every derived edge from the retained current raw
projection. This global replacement is required because a narrow MCP, config,
or A2A change can invalidate cross-domain evidence whose `source_collector`
names another detector domain. Unknown, partial, and failed collection does not
publish. An attempt with no promotably complete domain skips derived processing
and leaves the epoch untouched. See `docs/architecture/post-processors.md`.

After analysis, the pipeline checks property completeness for public managed
raw facts. Internal nodes such as `SchemaVersion` and derived relationships are
excluded. Incomplete shared-owner property coverage remains dirty and withholds
publication. The pipeline then freezes a second public graph total and queries
the candidate finding snapshot. PostgreSQL finalization atomically replaces all
finding rows for the scan (including a successful empty retry), advances
complete coverage heads, finalizes scan state, and optionally inserts a
persisted export/publication revision. Analysis, stats, or snapshot failure
withholds publication and leaves the prior published revision available.
Finalization re-locks cumulative dirty state and publishes only when no inherited
or current dirty key remains. Epoch-retirement or processor failure can leave
the mutable Neo4j projection incomplete, but it cannot advance or overwrite the
previous immutable PostgreSQL publication.

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
- `Submitted` -- literal artifact contribution counts
- `WriteRows` -- unique logical nodes/relationships affected by successful
  Neo4j writes, including matches of facts that already existed
- `GraphTotals` -- frozen public inventory totals before and after processing
- `Warnings` -- normalizer warnings
- `NormalizationStatus`, `NormalizationWarnings` -- deterministic
  `complete`/`warning`/`degraded` classification, codes, context, and the
  explicit publication-safety bit
- `Collection` -- required collection report echoed from the artifact
- `Stages` -- typed required/optional outcomes (`complete`, `partial`,
  `failed`, `truncated`, `unknown`, `not_applicable`)
- `PostProcessingStats` -- per-processor name, edges created, nodes updated, duration, error
- `PublishedRevision` -- revision published by this attempt, when any
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
