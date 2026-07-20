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
| `MCPServer` | Config + MCP | configured `name`, live `server_name`, `endpoint`, `transport` (stdio/http), configured `auth_method`/`auth_assurance`/`auth_evidence`, live `observed_auth_method`/`observed_auth_assurance`/`observed_auth_evidence`, `auth_strength` (numeric weakness only when known, post-processor), `protocol_version`, `instructions`, `instructions_hash` (SHA-256), `capabilities`, `pinning_status`, `is_pinned` (only when known), `id_scheme`, `has_tasks_capability` |
| `MCPTool` | MCP | `name`, `description`, `input_schema`, `output_schema`, `annotations`, `description_hash` (SHA-256), `input_schema_hash` (SHA-256), `schema_keys[]`, `capability_surface[]`, `source_trust` (untrusted_web/email/fileshare), `has_injection_patterns`, `has_cross_references` |
| `MCPResource` | MCP | `uri`, `name`, `mime_type`, `size`, `uri_scheme`, `sensitivity` (`critical`/`high`/`medium`/`low`/`none`/`unknown`), `sensitivity_rule_id`, `sensitivity_evidence` |
| `MCPPrompt` | MCP | `name`, `description`, `arguments` |
| `A2AAgent` | A2A | `name`, `description`, `url`, `provider`, `version`, `card_schema_version`, `card_present_fields`, `card_conformant`, `card_conformance_errors`, ordered `interfaces`, `protocol_versions`, `capabilities`, `security_schemes`, OR-of-AND `security_requirements`, `auth_method`, `auth_assurance`, `auth_evidence`, `auth_strength` (numeric only when known), `is_https`, `is_signed`, `signature_verification_status`, `signature_key_source`, `signature_key_trust`, `card_hash` |
| `A2ASkill` | A2A | `id`, `name`, `description`, `input_modes`, `output_modes`, `security_requirements`, `conformant`, `conformance_errors`, `description_hash`, `has_injection_patterns` |
| `AgentInstance` | Config | `name`, `framework`, `config_path` |
| `Identity` | Config + MCP | `type` (none/apiKey/oauth/bearer/mtls), `scope`, `is_static` |
| `Credential` | Config + LiteLLM/Open WebUI Looters | `type`, `name`, `source`, required `merge_key` (`value_hash`/`identity`), `identity_basis` (`value_hash`/`provider_name`/`metadata`/`unknown`), `material_status` (`observed`/`masked`/`hashed`/`unobserved`/`unknown`), `exposure_status` (`exposed`/`not_observed`/`unknown`), `high_entropy`, `format`, `value_hash`, `blast_radius` |
| `Host` | Config + A2A + MCP | `hostname`, `ip`, `scope` (`local`/`private`/`public`/`unknown`) |
| `ConfigFile` | Config | `path`, sorted `clients`, singular `client` only for one applicable client, unique enabled `server_count` |
| `InstructionFile` | Config | `path`, `type` (agents.md/claude.md/cursorrules/copilot-instructions/memory.md/cursor-rule), `hash`, `is_suspicious` |
| `OllamaInstance` | Network scan + Ollama fingerprinter + Open WebUI config | `endpoint`, `version`, observed `auth_method`, `probe_status` (`configured_unverified`/`verified`/`failed`/`unknown`), `last_verified_at`, `configuration_observed`, `configured_via`, `configured_auth_method`, `is_anonymous_loot`, `discovered_via` |
| `VLLMInstance` | Network scan + vLLM fingerprinter | `endpoint`, upstream `version`, `auth_method` (`unknown` from fingerprinting) |
| `QdrantInstance` | Network scan + Qdrant fingerprinter + Qdrant Looter | `endpoint`, `version`, `collection_count`, `collections` (sorted names), `total_points`, `anonymous_listing` (Looter-enriched) |
| `MLflowServer` | Network scan + MLflow fingerprinter | `endpoint`, `version`, `experiment_count` |
| `LiteLLMGateway` | Network scan + LiteLLM fingerprinter | `endpoint`, `auth_method`, `is_anonymous_loot`, `docs_enabled` |
| `JupyterServer` | Network scan + Jupyter fingerprinter + Jupyter Looter | `endpoint`, fingerprint-owned `version`, `status_access`, `status_anonymous_access`, `fingerprint_detector_id`, `fingerprint_detector_version`, `fingerprint_detector_source`; Looter-owned `sessions_access`, `contents_access`, `auth_required` (only when known), observed `auth_method`, `auth_assurance`, `auth_evidence`, `anonymous_access_observed`, `is_anonymous_loot` |
| `LangServeApp` | Network scan + LangServe fingerprinter | `endpoint`, `chains` |
| `OpenWebUIInstance` | Network scan + Open WebUI fingerprinter + Open WebUI Looter | `endpoint`, `version`, `signup_enabled`, `auth_required`, `ollama_backend_urls` (canonicalized list, Looter-enriched from admin `/ollama/config`) |
| `AIService` | Multi-label umbrella (see below) | _(no unique properties — carried as companion label)_ |
| `AIModel` | Ollama Looter | `name`, `size_bytes`, `digest`, `family`, `parameter_size`, `is_finetune`, `modified_at`, `value_hash` (when modelfile present), `has_system_prompt`, `modelfile_size_bytes` |
| `ExtractedTrainingSignal` | Extractors | `kind`, `source_model`, `sample_count`, `confidence` |

Config collection normalizes stdio executable basenames (including
path-qualified and Windows `.exe`/`.cmd`/`.bat` launchers) before assessing
`npx`/`uvx` package pinning. Unrecognized launchers use
`pinning_status=unknown`, not `not_applicable`; `is_pinned` is emitted only for
explicit pinned/unpinned evidence.

Neo4j's internal `SchemaVersion` node is excluded from every public inventory
count and node collection.

### A2A conformance, interfaces, and signatures

The A2A collector treats discovery and protocol conformance as separate facts.
`card_schema_version` is pinned to v0.3.0 or v1.0.1,
`card_present_fields` records raw top-level presence, and
`card_conformant`/`card_conformance_errors` record versioned required-field
validation. Nonconformant cards remain observable. `interfaces` preserves wire
order and marks entry zero `preferred=true`; later JSON-RPC entries never
replace it. Invalid skills and interfaces remain properties/nodes where they
have stable identity, but do not produce `ADVERTISES_SKILL` or `RUNS_ON`.
Optional skill `examples`, `inputModes`, and `outputModes` accept absent/null
ProtoJSON fields or arrays of strings; another JSON shape makes that skill
nonconformant and suppresses its functional edge.

`security_requirements` preserves alternatives in array order. Each alternative
contains the schemes that must be used together plus their scopes. Scheme
declarations alone are inactive. `auth_method` and `AUTHENTICATES_WITH` are
emitted only when active conformant requirements reduce unambiguously to one
scalar method; AND combinations or distinct OR methods remain `unknown`. In
v1.0.1, an empty requirement (`{}`, including ProtoJSON's omitted empty
`schemes` map) is a conformant anonymous alternative. Omitted/null `list`
inside a `StringList` is likewise an empty scope list. These forms preserve the
skill's `ADVERTISES_SKILL` edge and record declared `auth_method=none` where the
requirements reduce to anonymous access; they are not runtime proof of
anonymous access.

`is_signed` records a non-empty signature declaration.
`signature_verification_status` is:

- `unsigned` — absent, ProtoJSON `null`, or empty `signatures[]`.
- `unsupported_version` — a v0.3 signature is structurally observed, but v0.3
  has no v1 canonicalization contract.
- `malformed` — the object signature, protected header, required `alg`/`kid`,
  bounds, ProtoJSON normalization, or JCS input is invalid.
- `key_unavailable` — the signature is structurally usable but no permitted,
  current key resolved.
- `invalid` — a permitted key resolved but did not verify the canonical card.
- `valid_untrusted` — verification succeeded with an HTTPS `jku` key.
- `valid_trusted` — verification succeeded with an operator-pinned key.

`signature_key_source` (`none`/`trusted_store`/`jku`) and
`signature_key_trust` (`unknown`/`untrusted`/`trusted`) keep cryptographic
validity separate from identity trust. Ingest rejects contradictory
status/source/trust/`is_signed` tuples. v1.0.1 verification applies pinned
ProtoJSON presence/default metadata, removes `signatures`, bounds signed-card
size/depth/object width, then uses RFC 8785 JCS and object-form JWS. Compact
strings, duplicate protected/unprotected JOSE parameters, inline `jwks`, and
top-level `jwks_uri` are not accepted inputs; a JWK `alg` constraint must match.
An absent or ProtoJSON `null` unprotected `header` is equivalent to no header;
a non-null non-object header is malformed.
Remote `jku` is HTTPS-only across redirects, always validates TLS server
identity (independent of target `--insecure`), refuses link-local/metadata
addresses, rejects fragments, and filters explicitly expired or revoked keys.
Each card is limited to 16 signatures and four unique remote key sources under
one aggregate verification deadline.

---

## 2. Umbrella Labels

The `AIService` label is a **multi-label companion**, not a standalone node kind. Every per-service node (`OllamaInstance`, `VLLMInstance`, `QdrantInstance`, `MLflowServer`, `LiteLLMGateway`, `JupyterServer`, `LangServeApp`, `OpenWebUIInstance`) also carries `:AIService` as a secondary Neo4j label.

This enables queries like `MATCH (n:AIService)` to find all AI infrastructure regardless of specific service type, while per-kind queries (`MATCH (n:OllamaInstance)`) still work.

**Schema constraint implication:** The schema-init loop skips labels in `UmbrellaLabels` when creating `objectid IS UNIQUE` constraints. A uniqueness constraint on `:AIService` would falsely collide between distinct service kinds.

---

## 3. Edge Types

### Raw Edges (20 collector-produced)

| Edge | Source | Target | Collector | Meaning |
|------|--------|--------|-----------|---------|
| `TRUSTS_SERVER` | AgentInstance | MCPServer | Config | Agent trusts this server to provide tools |
| `PROVIDES_TOOL` | MCPServer | MCPTool | MCP | Server exposes this tool |
| `PROVIDES_RESOURCE` | MCPServer / JupyterServer / MLflowServer / QdrantInstance | MCPResource | MCP / Jupyter Looter / MLflow Looter (Model Registry storage URIs) / Qdrant Looter (scrolled point payloads under `--include-points`) | Server exposes this resource. MLflow URIs are plain `storage_location or source` (s3://, gs://, dbfs:/, file:///), NOT presigned credentials. Qdrant point resources are per-collection payload samples. |
| `PROVIDES_PROMPT` | MCPServer | MCPPrompt | MCP | Server exposes this prompt template |
| `ADVERTISES_SKILL` | A2AAgent | A2ASkill | A2A | A conformant skill declaration advertises this skill; invalid skill observations do not emit the edge |
| `DELEGATES_TO` | A2AAgent | A2AAgent | A2A | Lexical possible-delegation hypothesis. `match_type`, `match_field`, and `matched_reference` preserve the boundary/context witness; not proof of runtime delegation. |
| `AUTHENTICATES_WITH` | MCPServer / A2AAgent | Identity | Config / A2A | Entity uses this auth identity. A2A emits it only for conformant, active, scalar-unambiguous security requirements. |
| `USES_CREDENTIAL` | Identity | Credential | Config | Identity backed by this credential material |
| `RUNS_ON` | MCPServer / A2AAgent | Host | Config / A2A / MCP | Entity runs on this host. A2A requires a conformant preferred interface; later interfaces do not replace entry zero. |
| `CONFIGURED_IN` | MCPServer | ConfigFile | Config | Server defined in this config file |
| `HAS_ENV_VAR` | MCPServer | Credential | Config | Server has access to this env var |
| `LOADS_INSTRUCTIONS` | AgentInstance | InstructionFile | Future evidence-backed collectors | Agent loads this instruction file. Static path discovery does not emit this edge because path presence alone cannot prove client/scope applicability. |
| `SAME_AUTH_DOMAIN` | A2AAgent | A2AAgent | A2A | Agents share an authentication domain |
| `EXPOSES` | AIService | AIService | Fingerprinters / Looters | Service relationship. Open WebUI backend references carry `assertion_type=configured_reference` and `confidence_scope=configuration_presence`; they do not prove backend availability or authentication until a direct probe sets `probe_status=verified`. |
| `EXPOSES_CREDENTIAL` | AIService | Credential | LiteLLM Looter, Open WebUI Looter | Credential evidence relationship. Inspect `exposure_status`/`assertion_type`: masked provider references and returned hashes remain reference edges but are not usable secret exposure. |
| `PROVIDES_MODEL` | OllamaInstance | AIModel | Ollama Looter | Instance serves this model |
| `EXTRACTED_FROM` | AIModel | ExtractedTrainingSignal | Extractors | Extracted signal was derived from this model |
| `INGESTS_UNTRUSTED` | MCPTool | MCPResource | MCP | Tool with rule-derived `source_trust` (web/email/fileshare) ingests untrusted input that taints same-server resources. **Raw edge** — not swept by composite cleanup (see post-processors doc) |
| `CREDENTIAL_REACH_VERIFIED` | AgentInstance | MCPResource | scan (campaign runner) | Per-agent campaign evidence that a supplied credential enabled a read of the exact predicted resource. It means “campaign verification associated with this source agent,” **not** observed agent invocation. Carries witness-v2 identity/topology, staged status, and credential hash metadata; NEVER the endpoint or raw credential. On ingest the server validates the complete contract and upgrades only the matching source-agent `CAN_REACH` finding. **Raw edge.** |
| `PUBLIC_ACCESS_OBSERVED` | MCPServer | MCPResource | scan (campaign runner) | A campaign probe read this resource with no credential. A recorded fact, not an auto-finding (findings derive only from composite edges) — only a policy concern where authentication was expected. **Raw edge.** |

> The campaign runner's second scenario, `mcp-poison-roundtrip` (a STANDALONE reversible-mutation validation), deliberately emits **no** graph edge. Its oracle/cleanup evidence stays in the bounded CLI `campaign.RunReport` rather than a scored edge, so a finding-free validation never pollutes the graph. See [offensive-actions.md](../operator/offensive-actions.md#mcp-poison-roundtrip-standalone-target-mutation-validation).

Campaign artifacts are prevalidated against their bounded public envelope and
the current graph before normalization, scan lifecycle creation, canonical
`MERGE`, or coverage retirement. Invalid positives therefore cannot overwrite a
valid per-agent campaign edge, and invalid negatives cannot retire it.

### Composite Edges (12 post-processor computed)

| Edge | Source | Target | Depends On | Meaning |
|------|--------|--------|------------|---------|
| `HAS_ACCESS_TO` | MCPTool | MCPResource | Raw edges | Capability surface matches resource URI scheme |
| `CAN_EXECUTE` | MCPTool | Host | Raw edges | Tool metadata matched the narrow shell_access or code_execution classifier (80% confidence; confirm implementation) |
| `SHADOWS` | MCPTool | MCPTool | Raw edges | Tool on another server references this tool's name/description |
| `POISONED_DESCRIPTION` | MCPTool | MCPTool (self-edge) | Raw edges | Tool description contains injection patterns |
| `POISONED_INSTRUCTIONS` | InstructionFile | InstructionFile (self-edge) | Raw edges | Suspicious patterns: imperative overrides, exfiltration commands, hidden Unicode |
| `TAINTS` | MCPTool | MCPTool | INGESTS_UNTRUSTED + `schema_keys` | Untrusted-input tool shares ≥2 schema keys with a tool on another server, so attacker data can flow between them |
| `CAN_REACH` | AgentInstance / A2AAgent | MCPResource / Credential | HAS_ACCESS_TO and correlation joins | Inferred transitive access. Credential variants distinguish observed material from references; cross-protocol shared-host variants are 50%-confidence hypotheses, not proven invocation paths. Credential-path candidates for one `(agent, resource)` are reduced deterministically by the complete object-ID tuple `(agent, entry server, entry tool, resource server, credential, identity, resource tool, resource)`; relationship IDs never choose the witness path. When per-agent `CREDENTIAL_REACH_VERIFIED` evidence exactly re-correlates on ingest, only that source agent's credential-chain edge is upgraded in place (`reach_evidence_state=verified`, confidence 1.0), with structured verification metadata persisted on the finding. |
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

`Node` has the same required `observation_domains` field and an optional
`property_semantics` field. Omitted `property_semantics` is an authoritative
property observation. The only explicit alternative is `reference_only`,
which asserts node ID and kinds while requiring an empty `properties` object.
In wire version 3, collector artifacts preserve both the collector
host/private-network origin and the producing target/config
scope per fact using opaque canonical keys such as `mcp:target:sha256:...`,
`a2a:target:sha256:...`, and `config:path:sha256:...`. The server does not
infer ownership.

### Edge Properties (all edges carry these)

| Property | Type | Description |
|----------|------|-------------|
| `scan_id` | string | Most recent scan that wrote this edge; not ownership |
| `last_seen` | ISO 8601 | Timestamp of last observation |
| `confidence` | float64 | 0.0–1.0 confidence score |
| `risk_weight` | float64 | Lower = easier to exploit (used by weighted traversal) |
| `is_composite` | bool | True for post-processed edges |
| `evidence` | map[string]any | Structured evidence: `endpoint`, `source`, `engagement_id`, and edge-specific keys (e.g. `digest` for `PROVIDES_MODEL`, `backend_url` for `EXPOSES`, `model_name`/`model_version` for MLflow `PROVIDES_RESOURCE`, `collection`/`point_id` for Qdrant `PROVIDES_RESOURCE`) |

Composite edges additionally carry `source_collector` (`mcp`, `a2a`, `config`,
or a processor-owned source such as `cross_service_credential_chain`) as
detector provenance. It is neither raw-fact nor composite lifecycle ownership.

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
and truncated coverage is non-destructive.
Node reference owners are tracked internally as a subset of
`observation_tokens`. A `reference_only` write adds ownership without merging
properties or lowering a complete authoritative observation. If the last
authoritative owner retires while a reference owner remains, the writer removes
the stale managed properties and retains only truthful node identity,
ownership, and lifecycle metadata.
If an evidence-backed collector emits `LOADS_INSTRUCTIONS`, it must declare the
actual client and applicability scopes needed to reconcile that relationship;
the static config collector does not infer them.

A complete exact re-observation replaces stale managed properties. Observation
completeness considers only public collector-produced nodes and managed raw
relationships, so internal graph state such as `SchemaVersion` and derived
relationships cannot block publication. Internal ownership and completeness
properties are reserved and stripped from imported `properties` maps.
For a fact with multiple authoritative owners, the writer records an internal
semantic fingerprint under each stable observation domain. Each owner
contribution is fingerprinted before compatible properties are unioned into
the single stored node or relationship. Overlapping non-timestamp values that
disagree are rejected deterministically rather than being selected by input
order. An independently refreshed owner remains complete only when its
fingerprint is unchanged; observation timestamps (`scan_id`, `first_seen`,
`last_seen`, `last_verified_at`, and `extracted_at`) do not participate. The
latest timestamp is retained when simultaneous contributions are unioned. The
fingerprints rotate with ownership and are stripped from all public graph
responses. A changed or missing fingerprint cannot certify a shared union and
therefore fails closed as property-incomplete. An incompatible targeted write
does not mutate the last coherent public properties or labels; it removes the
incoming owner's prior fingerprint so an older retry also remains incomplete.
Completeness and replacement resume only after all active owners are observed
together, or after retirement leaves an exact remaining-owner refresh able to
replace the fact.
Relationships marked `all_dependencies` instead carry one indivisible owner
group for each logical `(source, edge kind, target)` fact. A complete incoming
group atomically supersedes the prior dependency tokens, fingerprints, and
semantic properties; unioning old and new groups could otherwise make the
relationship permanently incomplete or let reconciliation delete newly
observed evidence. When a prior coherent group exists, a partial replacement
keeps those semantic properties, records no fingerprint for an incomplete new
dependency, and marks the relationship property-incomplete until a complete
group replaces it.
This metadata is Neo4j graph schema 2. Startup rejects a schema-1 graph that
contains authoritative owner tokens without matching fingerprints instead of
silently accepting a projection that later cannot prove per-owner equality.
Empty schema-1 graphs and pre-release graphs with complete fingerprint coverage
advance automatically; older populated development graphs must be reset and
recollected as described in the deployment guide.
When a previously unseen complete domain adds only properties compatible with
an already complete fact, the union remains complete. Any overlapping conflict
still makes it incomplete. If one of those authoritative co-owner domains later
retires without replacement, the retained fact is downgraded to incomplete so
properties unique to the missing owner can never be published as current.
Public nodes with no observation token, and raw relationships incident to one,
are publication-unsafe even when their managed properties are otherwise
complete.
When a complete narrow observation cannot safely replace properties because
another active owner is not present, the writer remains additive and marks the
fact property-incomplete; publication stays withheld until all active owners
are re-observed together.

Composite edges are epoch-recomputed separately. When at least one complete raw
domain is promoted, the server retires the entire derived epoch and rebuilds
all processors from retained current raw facts in dependency order. Global
replacement prevents a narrow-domain change from preserving cross-domain
evidence merely because its `source_collector` names another detector.
Unknown, partial, and failed collection cannot publish. When no domain is
promotably complete, derived processing is skipped and the epoch is untouched.

---

## 4. Node ID Strategy

All node IDs are deterministic, content-based SHA-256 hashes. This ensures identical entities from different collectors merge on the same Neo4j node.

| Node Kind | ID Computation |
|-----------|----------------|
| `MCPServer` (HTTP) | `SHA-256("MCPServer:" + transport + ":" + endpoint)` |
| `MCPServer` (stdio) | SHA-256 over domain-separated, length-framed command plus the ordered domain-separated SHA-256 digest of each exact argv element (`mcp_stdio_v3_hashed_argv`) |
| `MCPTool` | `SHA-256("MCPTool:" + server_id + ":" + tool_name)` |
| `MCPResource` | `SHA-256("MCPResource:" + server_id + ":" + resource_uri)` |
| `MCPPrompt` | `SHA-256("MCPPrompt:" + server_id + ":" + prompt_name)` |
| `A2AAgent` | `SHA-256("A2AAgent:" + normalized_agent_base_url)` |
| `A2ASkill` | `SHA-256("A2ASkill:" + agent_id + ":" + skill_id)` |
| `AgentInstance` | `SHA-256("AgentInstance:" + config_file_id + ":" + client_name)` |
| `ConfigFile` | `SHA-256("ConfigFile:" + absolute_path)` |
| `Host` | `SHA-256("Host:" + hostname_or_ip)` |
| `Identity` | `SHA-256("Identity:" + parent_id + ":" + type)` |
| `Credential` (Config) | `SHA-256("Credential:" + coverage_key + ":" + server_id + ":" + source + ":" + location + ":" + name)`; cross-service correlation uses `value_hash`, not object-ID merging |
| `InstructionFile` | `SHA-256("InstructionFile:" + absolute_path)` |
| `AIModel` | `SHA-256("AIModel:" + instance_id + ":" + model_name)` |

**Critical invariant:** Config and MCP collectors use the same identity helper.
Stdio identity preserves argv order and exact bytes because process behavior can
depend on them, but raw argv never needs to leave collector memory. Each raw
argument is first hashed with the `mcp_stdio_argument_v1` domain and length
framing; the ordered digest strings are then framed into the v3 server ID. The
artifact publishes those `arg_hashes` and `arg_count`, allowing strict ingest to
recompute the parent ID while rejecting a raw `args` property. Argument hashes
are deterministic identifiers, not password hashing or encryption: a consumer
can guess low-entropy argv offline.

HTTP v1 identity still uses the untouched raw configured URL in collector
memory. Public `endpoint` removes user-info, query, and fragment; marker
properties disclose that components were removed without disclosing their
bytes. Consequently an HTTP ID whose input contained hidden components is not
recomputable from the public endpoint, and the validator deliberately does not
pretend otherwise. Strict ingest requires every present public endpoint to
already be the valid canonical sanitized display value, regardless of the
transport discriminator, and an HTTP server must publish one. Stdio servers use
`command` and omit `endpoint`. Authoritative MCP servers require canonical
string transport `http` or `stdio`; property-neutral `reference_only` nodes are
exempt. The fixed invalid placeholder is not accepted. Raw `args`, `env`,
`headers`, and `url` properties are rejected on every authoritative MCP server,
even when `transport` is missing or malformed.

Stdio v2 artifacts are not aliases for v3 and are rejected. Recollect with the
current collector after resetting an older pre-release projection; child MCP
tool/resource/prompt IDs also change because they include the parent ID.

---

## 5. Cross-Collector Merge via value_hash

The `value_hash` property on `Credential` nodes is the cross-collector merge primitive. It enables the `cross_service_credential_chain` post-processor to join credentials discovered independently by different collectors.

**How it works:**

1. Config Collector emits a Credential node via `HAS_ENV_VAR` (MCP server → credential)
2. LiteLLM Looter emits a Credential node via `EXPOSES_CREDENTIAL` (gateway → master/upstream/virtual keys)
3. Both compute `value_hash = SHA-256(credential_material)` via
   `sdk/common.HashCredentialValue`. For a recognized HTTP `Authorization`
   scheme, the material is the value after `Bearer`, `Basic`, or the other
   recognized scheme; protocol syntax is not part of the reusable secret.
4. Same secret value → same `value_hash` → nodes merge on `objectid` regardless of how each collector derives it

This enables evidence graphs like `AgentInstance → MCPServer → Credential ← LiteLLMGateway → upstream provider`. An observed `value_hash` match correlates the local and gateway credential records; the upstream target is classified separately as observed material or a reference.

**Requirement:** Every collector or looter MUST populate `value_hash` on every emitted Credential node.

**Exception:** when a producer cannot observe raw material, it may retain a stable identity while setting explicit evidence states. LiteLLM `/model/info` references use `merge_key=identity`, `identity_basis=provider_name`, `material_status=masked`, and `exposure_status=not_observed`. Returned one-way virtual-key digests use `material_status=hashed`. These nodes are excluded from exposure, entropy, rotation, and observed-material joins.

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

Lower weight = easier to exploit = higher risk. Used by bounded weighted-path queries.

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

**Agent:** `0.30 * credential + 0.25 * blast_radius + 0.20 * auth_risk + 0.15 * tool_surface + 0.10 * poisoning`

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

### Composite Epoch Replacement

Any promoted complete MCP, config, or A2A scope starts a fresh global composite
epoch. All `is_composite=true` relationships are retired before every
registered processor recomputes from the retained raw projection. This covers
transitive, cross-protocol, credential-chain, and other multi-domain evidence
without relying on the single-valued `source_collector` provenance field.
Attempts with no promotably complete domain perform no epoch retirement;
partial and failed collection never publishes.

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
    "version": 3,
    "type": "agenthound-ingest",
    "collector": "mcp|a2a|config|scan",
    "collector_version": "0.1.0",
    "timestamp": "2025-01-15T10:30:00Z",
    "scan_id": "scan-abc123",
    "origin": {
      "host_id": "security-laptop",
      "network_realm_id": "corp-lab"
    },
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
        "method": "enumerate",
        "state": "complete"
      }]
    },
    "ruleset": {
      "digest": "sha256:...",
      "load_state": "complete",
      "authenticity": "unverified",
      "entries": []
    },
    "identity_schemes": [{
      "entity_kind": "MCPServer",
      "transport": "stdio",
      "scheme": "mcp_stdio_v3_hashed_argv",
      "version": 3
    }]
  },
  "graph": {
    "nodes": [{"id": "sha256:...", "kinds": ["MCPServer"], "properties": {...}, "observation_domains": ["mcp:target:sha256:..."]}],
    "edges": [{"source": "sha256:...", "target": "sha256:...", "kind": "PROVIDES_TOOL", "source_kind": "MCPServer", "target_kind": "MCPTool", "properties": {...}, "observation_domains": ["mcp:target:sha256:..."]}]
  }
}
```

Wire version `3` is strict: collection origin, collection, ruleset, current
identity metadata, explicit edge endpoint kinds, and per-fact observation
domains are required. One database pair admits one exact host/realm origin;
these non-secret fields scope graph meaning and do not authenticate an artifact.
Ruleset digests identify effective text/fingerprint semantics but do not claim
cryptographic authenticity.

**Rules for module authors:**

1. Only emit node kinds in `AllowedNodeKinds` and edge kinds in `RawEdgeKinds`
2. Compute deterministic `id` values per the Node ID Strategy above
3. Populate `value_hash`, `merge_key`, `identity_basis`, `material_status`, and `exposure_status` on all `Credential` nodes
4. Set `source_kind` / `target_kind` on every edge
5. Tag every node and edge with one or more declared canonical `observation_domains`
6. Use snake_case and canonical properties only; v1 aliases are rejected
7. Valid collectors: `mcp`, `a2a`, `config`, `scan`
