# Graph Data Model

AgentHound builds a directed trust graph in Neo4j. The core principle: **edges represent exploitable relationships** and **direction follows the flow of access and control**.

The fundamental traversal pattern:

```
Agent → Server → Tool → Resource
```

An attacker (or a compromised agent) moves along edge direction to escalate access. Shortest-path and weighted-path queries over this graph surface attack paths that cross protocol boundaries — including MCP-to-A2A paths that single-protocol scanners cannot see.

---

## 1. Node Types

### Collector-Produced (23 kinds)

These are the node kinds accepted in ingest input (`sdk/ingest.AllowedNodeKinds`).

| Label | Source | Key Properties |
|-------|--------|----------------|
| `MCPServer` | Config + MCP | `name`, `endpoint`, `transport` (stdio/http), `auth_method`, `auth_assurance`, `auth_strength` (numeric weakness only when known, post-processor), `auth_evidence`, `protocol_version`, `instructions`, `instructions_hash` (SHA-256), `capabilities`, `pinning_status`, `is_pinned` (only when known), `id_scheme`, `legacy_objectid`, `identity_compatibility`, `identity_alias_target`, `identity_alias_candidates`, `identity_quarantined`, `legacy_alias_state`, `legacy_identity_quarantined`, `has_tasks_capability` |
| `MCPTool` | MCP | `name`, `description`, `input_schema`, `output_schema`, `annotations`, `description_hash` (SHA-256), `input_schema_hash` (SHA-256), `schema_keys[]`, `capability_surface[]`, `source_trust` (untrusted_web/email/fileshare), `has_injection_patterns`, `has_cross_references` |
| `MCPResource` | MCP | `uri`, `name`, `mime_type`, `size`, `uri_scheme`, `sensitivity` (`critical`/`high`/`medium`/`low`/`none`/`unknown`), `sensitivity_rule_id`, `sensitivity_evidence` |
| `MCPPrompt` | MCP | `name`, `description`, `arguments` |
| `A2AAgent` | A2A | `name`, `description`, `url`, `provider`, `version`, `protocol_versions`, `capabilities`, `security_schemes`, `auth_method`, `auth_assurance`, `auth_evidence`, `auth_posture`/`auth_strength` (numeric only when known), `is_https`, `is_signed`, `signature_valid`, `signature_verification_status`, `card_hash` |
| `A2ASkill` | A2A | `id`, `name`, `description`, `input_modes`, `output_modes`, `description_hash`, `has_injection_patterns` |
| `AgentInstance` | Config | `name`, `framework`, `config_path` |
| `Identity` | Config + MCP | `type` (none/apiKey/oauth/bearer/mtls), `scope`, `is_static` |
| `Credential` | Config + LiteLLM/Open WebUI Looters | `type`, `name`, `source`, `identity_basis` (`value_hash`/`provider_name`/`metadata`/`unknown`), `material_status` (`observed`/`masked`/`hashed`/`unobserved`/`unknown`), `exposure_status` (`exposed`/`not_observed`/`unknown`), legacy `is_exposed`/`high_entropy`, `format`, `value_hash`, `blast_radius` |
| `Host` | Config + A2A + MCP | `hostname`, `ip`, `scope` (`local`/`private`/`public`/`unknown`), legacy `is_local`/`is_private`/`is_public` |
| `ConfigFile` | Config | `path`, `client`, `server_count` |
| `InstructionFile` | Config | `path`, `type` (agents.md/claude.md/cursorrules/copilot-instructions/memory.md), `hash`, `is_suspicious` |
| `OllamaInstance` | Network scan + Ollama fingerprinter + Open WebUI config | `endpoint`, `version`, observed `auth_method`, `probe_status` (`configured_unverified`/`verified`/`failed`/`unknown`), `last_verified_at`, `configuration_observed`, `configured_via`, `configured_auth_method`, `is_anonymous_loot`, `discovered_via` |
| `VLLMInstance` | Network scan + vLLM fingerprinter | `endpoint`, `version`, `auth_method`, `is_anonymous_loot` |
| `QdrantInstance` | Network scan + Qdrant fingerprinter + Qdrant Looter | `endpoint`, `version`, `collection_count`, `collections` (sorted names), `total_points`, `anonymous_listing` (Looter-enriched) |
| `MLflowServer` | Network scan + MLflow fingerprinter | `endpoint`, `version`, `experiment_count` |
| `LiteLLMGateway` | Network scan + LiteLLM fingerprinter | `endpoint`, `auth_method`, `is_anonymous_loot`, `docs_enabled` |
| `JupyterServer` | Network scan + Jupyter fingerprinter | `endpoint`, `version`, `token_required` |
| `LangServeApp` | Network scan + LangServe fingerprinter | `endpoint`, `chains` |
| `OpenWebUIInstance` | Network scan + Open WebUI fingerprinter + Open WebUI Looter | `endpoint`, `version`, `signup_enabled`, `auth_required`, `ollama_backend_url` (first canonicalized backend URL), `ollama_backend_urls` (full list, Looter-enriched from admin `/ollama/config`) |
| `AIService` | Multi-label umbrella (see below) | _(no unique properties — carried as companion label)_ |
| `AIModel` | Ollama Looter | `name`, `size_bytes`, `digest`, `family`, `parameter_size` (canonical), `parameters` (deprecated alias, one-release dual-emit), `is_finetune`, `modified_at`, `value_hash` (when modelfile present), `has_system_prompt`, `modelfile_size_bytes` |
| `ExtractedTrainingSignal` | Extractors | `kind`, `source_model`, `sample_count`, `confidence` |

Config collection normalizes stdio executable basenames (including
path-qualified and Windows `.exe`/`.cmd`/`.bat` launchers) before assessing
`npx`/`uvx` package pinning. Unrecognized launchers use
`pinning_status=unknown`, not `not_applicable`; `is_pinned` is emitted only for
explicit pinned/unpinned evidence.

### Reserved / unimplemented synthetic labels

These compatibility labels exist in `AllNodeLabels` but NOT in
`AllowedNodeKinds`. No current collector or post-processor produces them. They
are excluded from public inventory, list, and search responses.

| Label | Source | Key Properties |
|-------|--------|----------------|
| `ResourceGroup` | Reserved / unimplemented (no producer) | `type`, `sensitivity` |
| `TrustZone` | Reserved / unimplemented (no producer) | `name`, `level`, `node_count` |

Neo4j's internal `SchemaVersion` node is likewise excluded from every public
inventory count and node collection.

### A2AAgent Signature Verification (`is_signed`, `signature_valid`, `signature_verification_status`)

`A2AAgent` carries three signature properties:

- **`is_signed`** — `true` when the agent card has a non-empty `signatures[]` array, regardless of cryptographic validity.
- **`signature_valid`** — `true` when **at least one** signature cryptographically verifies against a resolvable key (any-valid semantics). Retained for backward compatibility.
- **`signature_verification_status`** — the authoritative outcome, disambiguating the two cases `signature_valid=false` previously conflated:
  - `unsigned` — no `signatures[]`.
  - `verified` — every signature verified.
  - `partially_verified` — at least one, but not all, signatures verified.
  - `failed` — signatures were checked against resolvable keys but none verified (tampered card, wrong key, unsupported algorithm).
  - `unverifiable` — no key could be resolved for any signature, so verification could not be attempted.

**Key resolution** (per signature, in order): the card's inline `jwks`; operator-supplied trusted keys (`--a2a-trusted-keys`, a JWKS file); then — unless `--no-verify-jwks` is set — the JWS protected-header **`jku`** URL (the A2A spec §8.4 mechanism) and, as a fallback, a top-level `jwks_uri`. Remote resolution is **on by default** via an SSRF-hardened fetcher: it validates the resolved IP at dial time (refusing link-local/cloud-metadata `169.254.0.0/16`, `fe80::/10`, and unspecified addresses; loopback and RFC1918 remain allowed for internal engagements), caps redirects and response size, honors `--insecure` for TLS, and never forwards `--auth-token` to the `jku` host.

The collector accepts both JWS serializations a card may use:

- **Compact** — each `signatures[]` entry is a compact JWS string.
- **Flattened JSON (object form)** — each entry is `{ "protected": "<b64url>", "signature": "<b64url>" }`, the spec-conformant A2A shape. The signed payload is the agent card with the `signatures` member removed and JCS-canonicalized (key ordering, no insignificant whitespace); it is embedded base64url-encoded as the JWS payload and verified per RFC 7515. Tampering with any other card field invalidates the signature.

---

## 2. Umbrella Labels

The `AIService` label is a **multi-label companion**, not a standalone node kind. Every per-service node (`OllamaInstance`, `VLLMInstance`, `QdrantInstance`, `MLflowServer`, `LiteLLMGateway`, `JupyterServer`, `LangServeApp`, `OpenWebUIInstance`) also carries `:AIService` as a secondary Neo4j label.

This enables queries like `MATCH (n:AIService)` to find all AI infrastructure regardless of specific service type, while per-kind queries (`MATCH (n:OllamaInstance)`) still work.

**Schema constraint implication:** The schema-init loop skips labels in `UmbrellaLabels` when creating `objectid IS UNIQUE` constraints. A uniqueness constraint on `:AIService` would falsely collide between distinct service kinds.

---

## 3. Edge Types

### Raw Edges (18 collector-produced)

| Edge | Source | Target | Collector | Meaning |
|------|--------|--------|-----------|---------|
| `TRUSTS_SERVER` | AgentInstance | MCPServer | Config | Agent trusts this server to provide tools |
| `PROVIDES_TOOL` | MCPServer | MCPTool | MCP | Server exposes this tool |
| `PROVIDES_RESOURCE` | MCPServer / JupyterServer / MLflowServer / QdrantInstance | MCPResource | MCP / Jupyter Looter / MLflow Looter (Model Registry storage URIs) / Qdrant Looter (scrolled point payloads under `--include-points`) | Server exposes this resource. MLflow URIs are plain `storage_location or source` (s3://, gs://, dbfs:/, file:///), NOT presigned credentials. Qdrant point resources are per-collection payload samples. |
| `PROVIDES_PROMPT` | MCPServer | MCPPrompt | MCP | Server exposes this prompt template |
| `ADVERTISES_SKILL` | A2AAgent | A2ASkill | A2A | Agent advertises this skill |
| `DELEGATES_TO` | A2AAgent | A2AAgent | A2A | Lexical possible-delegation hypothesis. `match_type`, `match_field`, and `matched_reference` preserve the boundary/context witness; not proof of runtime delegation. |
| `AUTHENTICATES_WITH` | MCPServer / A2AAgent | Identity | Config / A2A | Entity uses this auth identity |
| `USES_CREDENTIAL` | Identity | Credential | Config | Identity backed by this credential material |
| `RUNS_ON` | MCPServer / A2AAgent | Host | Config / A2A / MCP | Entity runs on this host |
| `CONFIGURED_IN` | MCPServer | ConfigFile | Config | Server defined in this config file |
| `HAS_ENV_VAR` | MCPServer | Credential | Config | Server has access to this env var |
| `LOADS_INSTRUCTIONS` | AgentInstance | InstructionFile | Config | Agent loads this instruction file |
| `SAME_AUTH_DOMAIN` | A2AAgent | A2AAgent | A2A | Agents share an authentication domain |
| `EXPOSES` | AIService | AIService | Fingerprinters / Looters | Service relationship. Open WebUI backend references carry `assertion_type=configured_reference` and `confidence_scope=configuration_presence`; they do not prove backend availability or authentication until a direct probe sets `probe_status=verified`. |
| `EXPOSES_CREDENTIAL` | AIService | Credential | LiteLLM Looter, Open WebUI Looter | Credential evidence relationship. Inspect `exposure_status`/`assertion_type`: masked provider references and returned hashes remain compatibility edges but are not usable secret exposure. |
| `PROVIDES_MODEL` | OllamaInstance | AIModel | Ollama Looter | Instance serves this model |
| `EXTRACTED_FROM` | AIModel | ExtractedTrainingSignal | Extractors | Extracted signal was derived from this model |
| `INGESTS_UNTRUSTED` | MCPTool | MCPResource | MCP | Tool with rule-derived `source_trust` (web/email/fileshare) ingests untrusted input that taints same-server resources. **Raw edge** — not swept by composite cleanup (see post-processors doc) |

### Composite Edges (12 post-processor computed)

| Edge | Source | Target | Depends On | Meaning |
|------|--------|--------|------------|---------|
| `HAS_ACCESS_TO` | MCPTool | MCPResource | Raw edges | Capability surface matches resource URI scheme |
| `CAN_EXECUTE` | MCPTool | Host | Raw edges | Tool metadata matched the narrow shell_access or code_execution classifier (80% confidence; confirm implementation) |
| `SHADOWS` | MCPTool | MCPTool | Raw edges | Tool on another server references this tool's name/description |
| `POISONED_DESCRIPTION` | MCPTool | MCPTool (self-edge) | Raw edges | Tool description contains injection patterns |
| `POISONED_INSTRUCTIONS` | InstructionFile | InstructionFile (self-edge) | Raw edges | Suspicious patterns: imperative overrides, exfiltration commands, hidden Unicode |
| `TAINTS` | MCPTool | MCPTool | INGESTS_UNTRUSTED + `schema_keys` | Untrusted-input tool shares ≥2 schema keys with a tool on another server, so attacker data can flow between them |
| `CAN_REACH` | AgentInstance / A2AAgent | MCPResource / Credential | HAS_ACCESS_TO and correlation joins | Inferred transitive access. Credential variants distinguish observed material from references; cross-protocol shared-host variants are 50%-confidence hypotheses, not proven invocation paths. |
| `CAN_EXFILTRATE_VIA` | AgentInstance | MCPTool | CAN_REACH | Inferred sensitive-data access plus a matched output-channel capability (incl. `auto_fetch_render` / `allowlisted_proxy`); not observed exfiltration |
| `IFC_VIOLATION` | MCPTool | MCPTool | INGESTS_UNTRUSTED + HAS_ACCESS_TO (≤3 hops) | Untrusted source shares a resource with a high-impact sink (credential_access/file_write/email_send) |
| `CAN_IMPERSONATE` | A2AAgent | A2AAgent | Raw edges | TF-IDF cosine similarity > 0.8 on skill descriptions |
| `CONFUSED_DEPUTY` | A2AAgent | A2AAgent | auth_strength + can_reach | Weakly-authed agent (`auth_strength` ≥ 80) delegates to a strongly-authed one (≤ 30) |
| `POISONS_CONTEXT` | MCPTool | MCPTool | Raw edges | Injection-bearing tool can poison context driving a high-capability tool (fan-out truncated to 20 sinks per (agent, source) pair) |

### Edge Struct (Go SDK)

```go
type Edge struct {
    Source             string         `json:"source"`
    Target             string         `json:"target"`
    Kind               string         `json:"kind"`
    SourceKind         string         `json:"source_kind,omitempty"`
    TargetKind         string         `json:"target_kind,omitempty"`
    Properties         map[string]any `json:"properties"`
    ObservationDomains []string       `json:"observation_domains,omitempty"`
}
```

`Node` has the same optional `observation_domains` field. It is additive to
wire version 1. New collector artifacts preserve the producing target/config
scope per fact using opaque canonical keys such as
`mcp:target:sha256:...`, `a2a:target:sha256:...`, and
`config:path:sha256:...`; a single-domain legacy artifact can still be
attributed by its sole declared coverage key.

### Edge Properties (all edges carry these)

| Property | Type | Description |
|----------|------|-------------|
| `scan_id` | string | Most recent scan that wrote this edge (compatibility metadata; not ownership) |
| `last_seen` | ISO 8601 | Timestamp of last observation |
| `confidence` | float64 | 0.0–1.0 confidence score |
| `risk_weight` | float64 | Lower = easier to exploit (used by Dijkstra) |
| `is_composite` | bool | True for post-processed edges |
| `evidence` | map[string]any | Structured evidence: `endpoint`, `source`, `engagement_id`, and edge-specific keys (e.g. `digest` for `PROVIDES_MODEL`, `backend_url` for `EXPOSES`, `model_name`/`model_version` for MLflow `PROVIDES_RESOURCE`, `collection`/`point_id` for Qdrant `PROVIDES_RESOURCE`) |

Composite edges additionally carry `source_collector` (`mcp`, `a2a`, `config`,
or a processor-owned source such as `cross_service_credential_chain`) as
provenance and stale-cleanup scope. It is not raw-fact ownership.

Finding-producing composite edges also carry transient
`evidence_version`, `evidence_node_ids`, and `evidence_relationship_ids`
references selected by the detector. The findings snapshot stage dereferences
and persists those exact witnesses; detail does not reconstruct them later
from a similar graph pattern.

### Active observation ownership

The writer derives internal `observation_tokens` from the validated
`observation_domains` field and current scan ID. Complete-scope reconciliation
retires only old tokens for that exact target/config key. A shared node or raw
relationship remains while any owner token survives. Unknown, partial, failed,
truncated, and unattributed legacy observations are non-destructive.

Pre-lifecycle facts are marked `legacy_observation` when first touched; the
reconciler never deletes them because their original coverage cannot be
proven. A complete exact re-observation replaces stale managed properties and
migrates the matched fact out of legacy state. Remaining legacy/unknown raw
facts, including collector-wide ownership tokens that predate target scoping,
are counted explicitly and keep global publication incomplete. These internal
properties are reserved and stripped from imported `properties` maps.
When a complete narrow observation cannot safely replace properties because
another active owner is not present, the writer remains additive and marks the
fact property-incomplete; publication stays withheld until all active owners
are re-observed together.

Composite edges are epoch-recomputed separately: stale composite cleanup runs
only after every processor succeeds and at least one complete raw domain was
promoted. Deletion remains scoped to dependency-expanded
`source_collector` values from those domains.

---

## 4. Node ID Strategy

All node IDs are deterministic, content-based SHA-256 hashes. This ensures identical entities from different collectors merge on the same Neo4j node.

| Node Kind | ID Computation |
|-----------|----------------|
| `MCPServer` (HTTP) | v1 unchanged: `SHA-256("MCPServer:" + transport + ":" + endpoint)` |
| `MCPServer` (stdio v2) | SHA-256 over domain-separated, length-framed command plus **order-preserving argv** (`mcp_stdio_v2_ordered`) |
| `MCPTool` | `SHA-256("MCPTool:" + server_id + ":" + tool_name)` |
| `MCPResource` | `SHA-256("MCPResource:" + server_id + ":" + resource_uri)` |
| `MCPPrompt` | `SHA-256("MCPPrompt:" + server_id + ":" + prompt_name)` |
| `A2AAgent` | `SHA-256("A2AAgent:" + normalized_agent_base_url)` |
| `A2ASkill` | `SHA-256("A2ASkill:" + agent_id + ":" + skill_id)` |
| `AgentInstance` | `SHA-256("AgentInstance:" + config_file_id + ":" + client_name)` |
| `ConfigFile` | `SHA-256("ConfigFile:" + absolute_path)` |
| `Host` | `SHA-256("Host:" + hostname_or_ip)` |
| `Identity` | `SHA-256("Identity:" + parent_id + ":" + type)` |
| `Credential` | `SHA-256("Credential:" + source + ":" + name)` |
| `InstructionFile` | `SHA-256("InstructionFile:" + absolute_path)` |
| `AIModel` | `SHA-256("AIModel:" + instance_id + ":" + model_name)` |

**Critical invariant:** Config and MCP collectors use the same identity helper.
HTTP IDs remain byte-for-byte v1 compatible. Stdio v2 preserves argv order and
bytes because process behavior can depend on them. New stdio nodes expose
`legacy_objectid` (the v1 sorted-argv ID).

During ingest, the server combines the artifact's alias candidates with every
v2 candidate already resident in Neo4j. A complete collector claim becomes
`one_to_one` only when that combined set contains exactly one current ID; the
legacy node and exact v2 target are annotated before a guarded transactional
migration merges node properties, observation owners, and all allowlisted
incoming/outgoing relationships into the v2 node, then deletes the v1 node.
Relationship collisions merge properties and owner tokens rather than creating
parallel edges. Two or more candidates mark the legacy aggregate and all
current candidates as `ambiguous`/quarantined and leave their nodes and
relationships untouched, so a many-to-one v1 aggregate cannot fan out trust
edges.
Identity-quarantined nodes make managed-observation completeness partial and
withhold publication until a later complete rescan resolves them.

---

## 5. Cross-Collector Merge via value_hash

The `value_hash` property on `Credential` nodes is the cross-collector merge primitive. It enables the `cross_service_credential_chain` post-processor to join credentials discovered independently by different collectors.

**How it works:**

1. Config Collector emits a Credential node via `HAS_ENV_VAR` (MCP server → credential)
2. LiteLLM Looter emits a Credential node via `EXPOSES_CREDENTIAL` (gateway → master/upstream/virtual keys)
3. Both compute `value_hash = SHA-256(credential_value)` via `sdk/common.HashCredentialValue`
4. Same secret value → same `value_hash` → nodes merge on `objectid` regardless of how each collector derives it

This enables evidence graphs like `AgentInstance → MCPServer → Credential ← LiteLLMGateway → upstream provider`. An observed `value_hash` match correlates the local and gateway credential records; the upstream target is classified separately as observed material or a reference.

**Requirement:** Every collector or looter MUST populate `value_hash` on every emitted Credential node.

**Exception:** when a producer cannot observe raw material, it may retain a stable identity while setting explicit evidence states. LiteLLM `/model/info` references use `merge_key=identity`, `identity_basis=provider_name`, `material_status=masked`, and `exposure_status=not_observed`. Returned one-way virtual-key digests use `material_status=hashed`. These nodes are excluded from exposure, entropy, rotation, and observed-material joins. Legacy nodes without explicit material/exposure fields remain unknown and cannot satisfy exposed-secret claims.

---

## 6. Post-Processor Execution Order

Processors run in strict dependency order. A processor may only read edges produced by earlier processors.

| Order | Processor | Produces | Dependencies |
|-------|-----------|----------|--------------|
| 1 | auth_strength | `auth_strength` node property (pre-pass) | None |
| 2 | has_access_to | `HAS_ACCESS_TO` | Raw edges only |
| 3 | can_execute | `CAN_EXECUTE` | Raw edges only |
| 4 | shadows | `SHADOWS` + `POISONS_CONTEXT` | Raw edges only |
| 5 | poisoned_description | `POISONED_DESCRIPTION` | Raw edges only |
| 6 | poisoned_instructions | `POISONED_INSTRUCTIONS` | Raw edges only |
| 7 | taints | `TAINTS` | INGESTS_UNTRUSTED + `schema_keys` |
| 8 | can_reach | `CAN_REACH` | 2 (HAS_ACCESS_TO) |
| 9 | cross_service_credential_chain | `CAN_REACH` (credential variant) + `Credential.blast_radius` | 2, 8 (joins on `Credential.value_hash`) |
| 10 | ifc_violation | `IFC_VIOLATION` | 2 (HAS_ACCESS_TO) + INGESTS_UNTRUSTED |
| 11 | can_exfiltrate | `CAN_EXFILTRATE_VIA` | 8 (CAN_REACH) |
| 12 | can_impersonate | `CAN_IMPERSONATE` | Raw edges only |
| 13 | confused_deputy | `CONFUSED_DEPUTY` | 1 (auth_strength) + 8 (can_reach) |
| 14 | cross_protocol | `CAN_REACH` (cross-protocol) | 2 (HAS_ACCESS_TO) + DELEGATES_TO |
| 15 | risk_score | Node property updates | 1–14 (all prior processors) |

---

## 7. Risk Scoring

### Edge Risk Weights

Lower weight = easier to exploit = higher risk. Used by Dijkstra weighted-path queries.

| Edge | Weight | Condition |
|------|--------|-----------|
| `TRUSTS_SERVER` | 0.1 | auth_method = none |
| `TRUSTS_SERVER` | 0.3 | auth_method = apiKey |
| `TRUSTS_SERVER` | 0.5 | auth_method = bearer |
| `TRUSTS_SERVER` | 0.7 | auth_method = oauth |
| `TRUSTS_SERVER` | 0.9 | auth_method = mtls |
| `PROVIDES_TOOL` | 0.1 | Always (tools are always available once trusted) |
| `HAS_ACCESS_TO` | 0.2 | — |
| `CAN_EXECUTE` | 0.1 | — |
| `DELEGATES_TO` | 0.1 | auth_method = none |
| `DELEGATES_TO` | 0.5 | authenticated |
| `SHADOWS` | 0.4 | — |
| `CAN_IMPERSONATE` | 0.6 | — |

### Node Risk Scores (0–100)

**Agent:** `0.30 * credential + 0.25 * blast_radius + 0.20 * auth_posture + 0.15 * tool_surface + 0.10 * poisoning`

**Server:** `0.35 * auth_strength + 0.25 * tool_risk + 0.20 * exposure + 0.20 * credential_handling`

**Tool:** `0.30 * capability_class + 0.25 * poisoning + 0.25 * access_sensitivity + 0.20 * input_validation`

### Resource Sensitivity Auto-Classification

| Pattern | Sensitivity |
|---------|------------|
| postgres/mysql/mongodb + prod | critical |
| `file:///etc/` | critical |
| `*.env`, `*.key`, `*.pem` | critical |
| redis + prod | critical |
| Database (non-prod) | high |
| `file:///` (general) | medium |

---

## 8. Merge Semantics

### Node Merge

Nodes merge by `objectid` using Cypher `MERGE`. When the same entity appears from multiple collectors:

- Properties use **last-write-wins** semantics
- The node MERGE pivots the previous-hash trio (`previous_description_hash`, `previous_input_schema_hash`, `previous_instructions_hash`) on both `ON CREATE` (seeded from the incoming hashes) and `ON MATCH` (set to the prior values before `n += node.properties` overwrites them) for rug-pull detection
- Edges accumulate (different collectors contribute different edge types to the same node)

### Stale Edge Cleanup

On partial scans (e.g., only the MCP collector ran), only composite edges whose `source_collector` matches the current scan's collector or derived processor-owned source are deleted and recomputed. This prevents ping-pong deletion when collectors run independently on different schedules while still cleaning cross-collector findings when one of their source collectors changes.

### Neo4j Version Compatibility

Schema init detects Neo4j version via `CALL dbms.components()`:

- **4.4:** Uses `CREATE CONSTRAINT ... ON (n:Label) ASSERT n.objectid IS UNIQUE`
- **5.x:** Uses `CREATE CONSTRAINT ... FOR (n:Label) REQUIRE n.objectid IS UNIQUE`

---

## 9. Emitting Nodes and Edges (Module Author Guide)

New modules emit nodes and edges via the `sdk/ingest` wire format:

```json
{
  "meta": {
    "version": 1,
    "type": "agenthound-ingest",
    "collector": "mcp|a2a|config|scan",
    "collector_version": "0.1.0",
    "timestamp": "2025-01-15T10:30:00Z",
    "scan_id": "scan-abc123",
    "collection": {
      "state": "complete",
      "coverage_keys": [
        "config:path:sha256:...",
        "mcp:target:sha256:..."
      ],
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
      "entries": []
    },
    "identity_schemes": []
  },
  "graph": {
    "nodes": [{"id": "sha256:...", "kinds": ["MCPServer"], "properties": {...}}],
    "edges": [{"source": "sha256:...", "target": "sha256:...", "kind": "PROVIDES_TOOL", "properties": {...}}]
  }
}
```

The wire version remains `1`; all evidence metadata is additive. Its absence in
a legacy artifact means **unknown**, not complete, clean, unsigned, or
unauthenticated. Ruleset digests identify effective text/fingerprint semantics
but do not claim cryptographic authenticity.

**Rules for module authors:**

1. Only emit node kinds in `AllowedNodeKinds` and edge kinds in `RawEdgeKinds`
2. Compute deterministic `id` values per the Node ID Strategy above
3. Populate `value_hash` on all `Credential` nodes
4. Set `source_kind` / `target_kind` on edges when the endpoint map has multiple valid sources/targets
5. Use snake_case for all property keys (the normalizer converts camelCase, but emit clean data)
6. Valid collectors: `mcp`, `a2a`, `config`, `scan`
