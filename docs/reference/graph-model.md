# Graph Data Model

AgentHound builds a directed trust graph in Neo4j. The core principle: **edges represent exploitable relationships** and **direction follows the flow of access and control**.

The fundamental traversal pattern:

```
Agent → Server → Tool → Resource
```

An attacker (or a compromised agent) moves along edge direction to escalate access. Shortest-path and weighted-path queries over this graph surface attack paths that cross protocol boundaries — including A2A-to-MCP shared-host correlations that single-protocol scanners cannot see.

---

## 1. Node Types

### Collector-Produced (23 kinds)

These are the node kinds accepted in ingest input (`sdk/ingest.AllowedNodeKinds`).

| Label | Source | Key Properties |
|-------|--------|----------------|
| `MCPServer` | Config + MCP | deterministic safe `name`, live `server_name`, `transport` (stdio/http), configured `auth_method`/`auth_assurance`/`auth_evidence`, live `observed_auth_method`/`observed_auth_assurance`/`observed_auth_evidence`, derived paired `effective_auth_method`/`effective_auth_assurance`/`effective_auth_evidence`/`effective_auth_source`, `auth_strength` (numeric weakness only when known, post-processor), `protocol_version`, `instructions`, `instructions_hash` (SHA-256), `capabilities`, `pinning_status`, `is_pinned` (only when known), `id_scheme`; stdio `command`, ordered `arg_hashes`, `arg_count`; HTTP sanitized `endpoint`, `endpoint_userinfo_redacted`, `endpoint_query_redacted`, `endpoint_fragment_redacted` when applicable; MCP-discovery `configured_names`; `has_tasks_capability` (`true` for a non-null raw tasks object, `false` when the raw key is absent, omitted when raw presence is unavailable or ambiguous) |
| `MCPTool` | MCP | `name`, `description`, `input_schema`, `output_schema`, `annotations`, `description_hash` (SHA-256), `input_schema_hash` (SHA-256), `schema_keys[]`, `capability_surface[]`, `source_trust` (untrusted_web/email/fileshare), `has_injection_patterns`, `has_cross_references` |
| `MCPResource` | MCP | `uri`, `name`, `mime_type`, `size` (bytes; omitted when the SDK reports zero because its scalar model cannot distinguish an omitted size from an explicit zero), `uri_scheme`, `sensitivity` (`critical`/`high`/`medium`/`low`/`none`/`unknown`), `sensitivity_rule_id`, `sensitivity_evidence` |
| `MCPPrompt` | MCP | `name`, `description`, `arguments` |
| `A2AAgent` | A2A | `name`, `description`, `url`, `provider`, `version`, `card_schema_version`, `card_present_fields`, `card_conformant`, `card_conformance_errors`, ordered `interfaces`, `protocol_versions`, `capabilities`, `security_schemes`, OR-of-AND `security_requirements`, configured `auth_method`/`auth_assurance`/`auth_evidence`, bounded read-only `auth_probe_method`/`auth_probe_status`/`auth_probe_detail` diagnostics and exact-positive `observed_auth_method`/`observed_auth_assurance`/`observed_auth_evidence`, derived paired `effective_auth_method`/`effective_auth_assurance`/`effective_auth_evidence`/`effective_auth_source`, `auth_strength` (numeric only when known), `is_https`, `is_signed`, `signature_verification_status`, `signature_key_source`, `signature_key_trust`, `card_hash` |
| `A2ASkill` | A2A | `id`, `name`, `description`, `input_modes`, `output_modes`, `security_requirements`, `conformant`, `conformance_errors`, `description_hash`, `has_injection_patterns` |
| `AgentInstance` | Config | `name`, `framework`, `config_path` |
| `Identity` | Config + A2A | `type` (none/apiKey/oauth/bearer/mtls), server-identity `scope`, `is_static` |
| `Credential` | Config + LiteLLM/Open WebUI Looters | `type`, `name`, `source`, Config `location` (`env`, `header`, `arg:<index>`, or redacted URL component), required `merge_key` (`value_hash`/`identity`), `identity_basis` (`value_hash`/`provider_name`/`metadata`/`unknown`), `material_status` (`observed`/`masked`/`hashed`/`unobserved`/`unknown`), `exposure_status` (`exposed`/`not_observed`/`unknown`), `high_entropy`, `format`, `value_hash`, `blast_radius` |
| `Host` | Config + A2A + MCP | `hostname`, `ip`, `scope` (`local`/`private`/`public`/`unknown`) |
| `ConfigFile` | Config | `path`, sorted `clients`, singular `client` only for one applicable client, unique enabled `server_count` |
| `InstructionFile` | Config | `path`, `type` (agents.md/claude.md/cursorrules/copilot-instructions/memory.md/cursor-rule), `hash`, `is_suspicious` |
| `OllamaInstance` | Network scan + Ollama fingerprinter + Ollama Looter + Open WebUI config | `endpoint`, `version`, observed `auth_method`/`auth_assurance`/`auth_evidence`, active-probe `probe_status` (`verified`/`failed`/`unknown`), `last_verified_at`, `loot_observed`, `configuration_observed`, `configured_via`, `configured_auth_method`, `is_anonymous_loot`, active-discovery `discovered_via`. Direct loot sets `loot_observed` and does not overwrite discovery provenance; it adds verified anonymous evidence only after a credential-free `/api/tags` response contains the canonical `models` array. Open WebUI configuration references intentionally omit probe status and active-discovery provenance so a later direct Ollama observation can merge without being overwritten. |
| `VLLMInstance` | Network scan + vLLM fingerprinter | `endpoint`, upstream `version`, `auth_method` (`unknown` from fingerprinting) |
| `QdrantInstance` | Network scan + Qdrant fingerprinter + Qdrant Looter | `endpoint`, `version`, `loot_observed`, successful-inventory `auth_method`/`auth_assurance`/`auth_evidence`, `probe_status`, `last_verified_at`, `is_anonymous_loot`, `collection_count`, `collections` (sorted names), `total_points`, `anonymous_listing`. The Looter adds the anonymous and inventory properties only after a credential-free `status=ok` response with a `result.collections` array. |
| `MLflowServer` | Network scan + MLflow fingerprinter + MLflow Looter | `endpoint`, `version`, `loot_observed`, successful-inventory `auth_method`/`auth_assurance`/`auth_evidence`, `probe_status`, `last_verified_at`, `is_anonymous_loot`, `experiment_count`. The Looter adds the anonymous and inventory properties only after a credential-free experiments-search response with an `experiments` array. |
| `LiteLLMGateway` | Network scan + LiteLLM fingerprinter | `endpoint`, `auth_method`, `is_anonymous_loot`, `docs_enabled` |
| `JupyterServer` | Network scan + Jupyter fingerprinter + Jupyter Looter | `endpoint`, fingerprint-owned `version`, `status_access`, `status_anonymous_access`, `fingerprint_detector_id`, `fingerprint_detector_version`, `fingerprint_detector_source`; Looter-owned `sessions_access`, `contents_access`, `auth_required` (only when known), observed `auth_method`, `auth_assurance`, `auth_evidence`, `anonymous_access_observed`, `is_anonymous_loot` |
| `LangServeApp` | Network scan + LangServe fingerprinter | `endpoint`, `chains` |
| `OpenWebUIInstance` | Network scan + Open WebUI fingerprinter + Open WebUI Looter | `endpoint`, `version`, `loot_observed`, `signup_enabled`, `auth_required`, `ollama_backend_urls` (canonicalized list, Looter-enriched from admin `/ollama/config`). Public identity fingerprinting omits graph auth fields; only the looter's `/api/config` observation authors auth evidence. |
| `AIService` | Multi-label umbrella (see below) | _(no unique properties — carried as companion label)_ |
| `AIModel` | Ollama Looter + extractor reference endpoint | Looter observations: `name`, `size_bytes`, `digest`, `family`, `parameter_size`, `is_finetune`, `modified_at`, `value_hash` (when modelfile present), `has_system_prompt`, `modelfile_size_bytes`. Extractors may emit the canonical source `AIModel` ID as an empty `reference_only` endpoint so extraction edges remain closed without fabricating model properties. |
| `ExtractedTrainingSignal` | Embedding inversion extractor | `token_index`, `token_string`, `magnitude`, `z_score`, `confidence`, `source_model_id`, `engagement_id`, `method`, `extracted_at` |

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

MCP observed authentication is an all-or-nothing tuple. If any
`observed_auth_*` field is present, all three must be canonical and internally
consistent. `anonymous_probe_succeeded` is accepted only with an HTTP server
whose status is `reachable` and whose exact observed tuple is
`none/unauthenticated/anonymous_probe_succeeded`. Unreachable servers emit
`unknown/unknown/unknown`; successful stdio collection emits
`unknown/unknown/local_process`; a successful request carrying configured URL
query material or a non-empty configured header whose auth scheme cannot be
inferred emits
`unknown/unknown/configured_credential`. Configured method and assurance must
also agree (`none` → unauthenticated, basic/apiKey → weak, bearer →
moderate, oauth/oidc/mtls → strong, unknown/custom → unknown). Configured
evidence is validated as part of the same tuple: `anonymous_probe_succeeded`
is valid only with `none/unauthenticated`, and `local_process` only with
`unknown/unknown`; known authenticated methods and `custom` require either
`configured_credential` or `declared_security_scheme`. `unknown/unknown` may
pair with `unknown`, `declared_security_scheme`, `configured_credential`, or
`local_process` because those represent, respectively, no usable observation,
an ambiguous card declaration, potentially credential-bearing configured
request material whose scheme cannot be inferred, and a local stdio process.
`none/unauthenticated` may also pair with
`unknown` or `declared_security_scheme`, but those combinations remain
fail-closed: neither proves anonymous runtime access.

For HTTP MCP collection, every configured header is attached to Initialize on
the target origin. Recognized `Authorization` schemes and API-key-style header
names retain their canonical method. Any other non-empty configured header,
including `Cookie`, `X-Session`, and conventionally benign fields such as
`Accept` or `User-Agent`, prevents anonymous classification because an
arbitrary server may gate on its exact value. There is no non-empty benign
allowlist. Empty or whitespace-only values carry no credential material and
are ignored for this decision. AgentHound does not issue a second Initialize
without the header: that would add protocol/session side effects and still
would not prove that the first response was independent of the configured
value. Exact anonymous evidence therefore requires a successful HTTP
Initialize with no URL userinfo/query and no non-empty caller-configured
header; protocol headers generated by the MCP SDK are not caller credentials.

A2A observed authentication uses a narrower all-or-nothing contract. If any
`observed_auth_*` field is present, the tuple must be exactly
`none/unauthenticated/anonymous_probe_succeeded` and must be paired with
`auth_probe_method=get_task_nonexistent` plus
`auth_probe_status=anonymous_protocol_access` and bounded
`auth_probe_detail=task_not_found_v1|task_not_found_v0_3`. The bounded lookup
uses a random nonexistent task and accepts only the protocol's exact not-found
result. It targets only the preferred conformant HTTP(S) JSON-RPC interface,
requires an exact origin match with at least one requested discovery target,
rejects interface userinfo/query/fragment bytes, deduplicates aliases by
canonical protocol endpoint, sends no credential,
rejects redirects, reads at most 64 KiB, and runs for no more than five seconds
(or the shorter collector timeout). v1 uses `GetTask` plus the advertised
`A2A-Version` header; v0.3 uses `tasks/get`. Probe method, status, and detail are
an atomic canonical diagnostic
triple: `authentication_required` accepts only the fixed 401/403 details and
`unknown` only the documented fixed failure categories. Card retrieval,
HTTP 401/403, and inconclusive protocol/transport results must omit
`observed_auth_*`; they fall back to configured card provenance.

The canonical A2A probe-detail vocabulary is status-scoped:

- `anonymous_protocol_access`: `task_not_found_v1`, `task_not_found_v0_3`
- `authentication_required`: `http_unauthorized`, `http_forbidden`
- `unknown`: `no_preferred_interface`,
  `nonconformant_preferred_interface`, `unsupported_protocol_binding`,
  `unsupported_protocol_version`, `invalid_preferred_interface_url`,
  `query_interface_not_probeable`,
  `cross_origin_interface`, `random_id_generation_failed`,
  `request_encoding_failed`, `request_creation_failed`,
  `transport_unavailable`, `timeout`, `context_canceled`, `transport_error`,
  `redirect_response`, `unexpected_http_status`, `non_json_response`,
  `response_too_large`, `malformed_jsonrpc_response`,
  `unexpected_jsonrpc_response`, `response_id_mismatch`, and
  `non_task_not_found_error`

The post-processor selects effective fields as one tuple, never as independent
fallbacks. A valid protocol-specific MCP or A2A runtime tuple wins; an
unknown/unavailable runtime method falls back to the configured tuple. The
configured and observed fields remain visible for provenance. A raw configured
`none/unauthenticated/anonymous_probe_succeeded` tuple is retained as
provenance but is not assigned unauthenticated assurance or numeric weakness;
anonymous access requires `effective_auth_source=observed`. The bounded pre-v1
MCP normalization described in the ingest pipeline promotes only genuine old
direct-URL runtime observations before this selection.

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
| `TRUSTS_SERVER` | AgentInstance | MCPServer | Config | Agent trusts this server to provide tools; configured `risk_weight` / `auth_assessment_complete` remain raw provenance, while the auth-strength pre-pass adds derived `effective_risk_weight` / `effective_auth_assessment_complete` / `effective_auth_source`; `configured_names` preserves sorted same-identity aliases without making an alias a server identity property |
| `PROVIDES_TOOL` | MCPServer | MCPTool | MCP | Server exposes this tool |
| `PROVIDES_RESOURCE` | MCPServer / JupyterServer / MLflowServer / QdrantInstance | MCPResource | MCP / Jupyter Looter / MLflow Looter (Model Registry storage URIs) / Qdrant Looter (scrolled point payloads under `--include-points`) | Server exposes this resource. MLflow URIs are plain `storage_location or source` (s3://, gs://, dbfs:/, file:///), NOT presigned credentials. Qdrant point resources are per-collection payload samples. |
| `PROVIDES_PROMPT` | MCPServer | MCPPrompt | MCP | Server exposes this prompt template |
| `ADVERTISES_SKILL` | A2AAgent | A2ASkill | A2A | A conformant skill declaration advertises this skill; invalid skill observations do not emit the edge |
| `DELEGATES_TO` | A2AAgent | A2AAgent | A2A | Lexical possible-delegation hypothesis. `match_type`, `match_field`, and `matched_reference` preserve the boundary/context witness; not proof of runtime delegation. |
| `AUTHENTICATES_WITH` | MCPServer / A2AAgent | Identity | Config / A2A | Entity uses this auth identity. A2A emits it only for conformant, active, scalar-unambiguous security requirements. |
| `USES_CREDENTIAL` | Identity | Credential | Config | Identity backed by this credential material |
| `RUNS_ON` | MCPServer / A2AAgent | Host | Config / A2A / MCP | Entity runs on this host. A2A requires a conformant preferred interface; later interfaces do not replace entry zero. |
| `CONFIGURED_IN` | MCPServer | ConfigFile | Config | Server defined in this config file; `configured_names` is the sorted alias set for that file |
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
| `CAN_REACH` | AgentInstance / A2AAgent | MCPResource / Credential | HAS_ACCESS_TO and correlation joins | Inferred transitive access. Credential variants distinguish observed material from references; cross-protocol shared-host variants are 50%-confidence hypotheses, not proven invocation paths. Credential-path candidates for one `(agent, resource)` are reduced deterministically by the complete object-ID tuple `(agent, entry server, entry tool, resource server, identity, credential, resource tool, resource)`; relationship IDs never choose the witness path. When per-agent `CREDENTIAL_REACH_VERIFIED` evidence exactly re-correlates on ingest, only that source agent's credential-chain edge is upgraded in place (`reach_evidence_state=verified`, confidence 1.0), with structured verification metadata persisted on the finding. |
| `CAN_EXFILTRATE_VIA` | AgentInstance | MCPTool | CAN_REACH | Inferred sensitive-data access plus a matched output-channel capability (incl. `auto_fetch_render` / `allowlisted_proxy`); not observed exfiltration |
| `IFC_VIOLATION` | MCPTool | MCPTool | INGESTS_UNTRUSTED + HAS_ACCESS_TO (≤3 hops) | Untrusted source shares a resource with a high-impact sink (credential_access/file_write/email_send) |
| `CAN_IMPERSONATE` | A2AAgent | A2AAgent | Raw edges | TF-IDF cosine similarity > 0.8 on skill descriptions |
| `CONFUSED_DEPUTY` | A2AAgent | A2AAgent | auth_strength + can_reach | Agent with observed unauthenticated auth or configured/observed weak effective auth delegates to one with strong effective assurance |
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
In wire version 4, the server rewrites producer-local IDs into deterministic
scoped IDs before graph writes. The centralized policy is:

| Observation | Identity scope |
|---|---|
| Files, environment/config data, identities, credentials, stdio and loopback services | Collection point |
| Private/remote hosts, DNS names, and endpoint-derived service observations | Network context |
| Network-scoped facts when route/interface visibility is incomplete | Artifact-local, additive-only; collection-point facts remain strongly scoped |
| Authoritative facts from weak-identity artifacts | Artifact-local, additive-only |
| Unresolved property-neutral references | Reference-local until authoritative evidence resolves them |

Endpoint identity means continuity of an observation at a locator within one
network context. It does not prove that a service was not replaced behind the
same endpoint or that two SaaS tenants at one URL are the same instance.
Cross-context hard merging requires a separately approved immutable identity
scheme. Credential nodes are scoped, while `value_hash` remains the explicit
global correlation primitive for observed credential material.

### Common Edge Properties

Collector constructors and post-processors normally populate the following
base fields. The ingest edge model itself is extensible, and `evidence` is not a
universal property: emitters add structured evidence only where their edge
contract defines it.

| Property | Type | Description |
|----------|------|-------------|
| `scan_id` | string | Most recent scan that wrote this edge; not ownership |
| `last_seen` | ISO 8601 | Timestamp of last observation |
| `confidence` | float64 | 0.0–1.0 confidence score |
| `risk_weight` | float64 | Lower = easier to exploit (used by weighted traversal) |
| `is_composite` | bool | True for post-processed edges |

Raw edges that carry an `evidence` map define its keys per edge, for example
`endpoint`, `source`, or `engagement_id`. Do not assume the map exists on an
arbitrary relationship.

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
and truncated coverage is non-destructive. Coverage root and child keys use the
same applicable identity scope. Each child outcome serializes its
`parent_coverage_key`; PostgreSQL records that membership explicitly.
Lifecycle code never reconstructs parentage by parsing an opaque key, so one
vantage cannot retire another vantage's evidence.
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

1. Config Collector emits an MCP server's canonical credential topology via
   `AUTHENTICATES_WITH` and `USES_CREDENTIAL` (server → identity → credential),
   independent of whether the material came from an env var, header, argument,
   or URL component
2. LiteLLM Looter emits a Credential node via `EXPOSES_CREDENTIAL` (gateway → master/upstream/virtual keys)
3. Both compute `value_hash = SHA-256(credential_material)` via
   `sdk/common.HashCredentialValue`. For a recognized HTTP `Authorization`
   scheme, the material is the value after `Bearer`, `Basic`, or the other
   recognized scheme; protocol syntax is not part of the reusable secret.
   Empty and whitespace-only env, header, argument, URL userinfo, and URL query
   values are placeholders rather than credentials and are omitted. Every
   non-empty value otherwise preserves its exact bytes, including surrounding
   whitespace, for hashing and optional raw-value output.
4. Same secret value → same `value_hash` → the processor correlates the two
   distinct collector-owned nodes without pretending their object IDs are equal

This enables evidence graphs like `AgentInstance → MCPServer → Identity → Credential ← LiteLLMGateway → upstream provider`. An observed `value_hash` match correlates the local and gateway credential records; the upstream target is classified separately as observed material or a reference.

**Requirement:** Every collector or looter MUST populate `value_hash` on every emitted Credential node.

**Exception:** when a producer cannot observe raw material, it may retain a stable identity while setting explicit evidence states. LiteLLM `/model/info` references use `merge_key=identity`, `identity_basis=provider_name`, `material_status=masked`, and `exposure_status=not_observed`. Returned one-way virtual-key digests use `material_status=hashed`. These nodes are excluded from exposure, entropy, rotation, and observed-material joins.

---

## 6. Post-Processor Execution Order

Processors run in strict dependency order. A processor may only read edges produced by earlier processors.

| Order | Processor | Produces | Dependencies |
|-------|-----------|----------|--------------|
| 1 | auth_strength | paired `effective_auth_*`, `auth_strength`, and effective TRUSTS_SERVER assessment properties (pre-pass) | None |
| 2 | has_access_to | `HAS_ACCESS_TO` | Raw edges only |
| 3 | can_execute | `CAN_EXECUTE` | Raw edges only |
| 4 | shadows | `SHADOWS` + `POISONS_CONTEXT` | Raw edges only |
| 5 | poisoned_description | `POISONED_DESCRIPTION` | Raw edges only |
| 6 | poisoned_instructions | `POISONED_INSTRUCTIONS` | Raw edges only |
| 7 | taints | `TAINTS` | INGESTS_UNTRUSTED + `schema_keys` |
| 8 | can_reach | `CAN_REACH` | 1 (effective auth) + 2 (HAS_ACCESS_TO) |
| 9 | cross_service_credential_chain | `CAN_REACH` (credential variant) + `Credential.blast_radius` | 2, 8 (joins on `Credential.value_hash`) |
| 10 | ifc_violation | `IFC_VIOLATION` | 2 (HAS_ACCESS_TO) + INGESTS_UNTRUSTED |
| 11 | can_exfiltrate | `CAN_EXFILTRATE_VIA` | 8 (CAN_REACH) |
| 12 | can_impersonate | `CAN_IMPERSONATE` | Raw edges only |
| 13 | confused_deputy | `CONFUSED_DEPUTY` | 1 (auth_strength) + 8 (can_reach) |
| 14 | cross_protocol | `CAN_REACH` (cross-protocol) | 1 (effective auth) + 2 (HAS_ACCESS_TO) + DELEGATES_TO |
| 15 | risk_score | Node property updates | 1–14 (all prior processors) |

---

## 7. Risk Scoring

### Edge Risk Weights

Lower weight means easier traversal and therefore higher risk. The complete,
canonical table—including Basic, OIDC, unknown/custom authentication and
resource/prompt edges—is maintained in
[Risk Scoring](risk-scoring.md#edge-risk-weights).

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

- Each authoritative observation domain contributes properties independently.
  Equal or disjoint contributions are unioned deterministically; overlapping
  non-timestamp values that disagree are rejected before mutation rather than
  selected by collector or input order.
- A complete exact re-observation may replace stale managed properties only
  when the active-owner fingerprints prove that the replacement is coherent.
  Otherwise the fact remains property-incomplete and publication is withheld.
- `reference_only` observations contribute identity and ownership but never
  author managed properties.
- The node MERGE pivots the previous-hash trio (`previous_description_hash`, `previous_input_schema_hash`, `previous_instructions_hash`) on both `ON CREATE` (seeded from the incoming hashes) and `ON MATCH` (set to the prior values before `n += node.properties` overwrites them) for rug-pull detection
- Different edge types accumulate. Contributions to the same logical
  `(source, kind, target)` relationship follow the compatible-union and
  conflict-rejection rules above; `all_dependencies` relationships replace
  their complete owner group atomically.

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
    "version": 4,
    "type": "agenthound-ingest",
    "collector": "mcp|a2a|config|scan",
    "collector_version": "1.0.0",
    "timestamp": "2025-01-15T10:30:00Z",
    "scan_id": "scan-abc123",
    "identity": {
      "scheme": "agenthound_collection_v1",
      "version": 1,
      "collection_point_id": "sha256:...",
      "network_context_id": "sha256:...",
      "quality": "strong",
      "network_quality": "strong",
      "network_class": "private",
      "display": {"hostname": "target-01", "os": "linux", "architecture": "amd64"},
      "evidence": [
        {"kind": "os_instance", "digest": "hmac-sha256:..."},
        {"kind": "principal", "digest": "hmac-sha256:..."}
      ],
      "network_evidence": [
        {"kind": "route_private", "digest": "hmac-sha256:..."}
      ]
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

Wire version `4` is strict: derived collection identity, collection, ruleset, current
identity metadata, explicit edge endpoint kinds, and per-fact observation
domains are required. The server validates the identity schema, algorithm
version, digest consistency, and evidence classification rules; it cannot prove
that a collector ran on the claimed machine. Identity scopes graph meaning and
does not authenticate an artifact.
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
