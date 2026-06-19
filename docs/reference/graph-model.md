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
| `MCPServer` | Config + MCP | `name`, `endpoint`, `transport` (stdio/http), `auth_method`, `protocol_version`, `instructions`, `capabilities`, `is_pinned`, `has_tasks_capability` |
| `MCPTool` | MCP | `name`, `description`, `input_schema`, `output_schema`, `annotations`, `description_hash` (SHA-256), `capability_surface[]`, `has_injection_patterns`, `has_cross_references` |
| `MCPResource` | MCP | `uri`, `name`, `mime_type`, `size`, `uri_scheme`, `sensitivity` (auto-classified) |
| `MCPPrompt` | MCP | `name`, `description`, `arguments` |
| `A2AAgent` | A2A | `name`, `description`, `url`, `provider`, `version`, `protocol_versions`, `capabilities`, `security_schemes`, `auth_method`, `is_signed`, `signature_valid`, `card_hash` |
| `A2ASkill` | A2A | `id`, `name`, `description`, `input_modes`, `output_modes`, `description_hash`, `has_injection_patterns` |
| `AgentInstance` | Config | `name`, `framework`, `config_path` |
| `Identity` | Config + MCP | `type` (none/apiKey/oauth/bearer/mtls), `scope`, `is_static` |
| `Credential` | Config + LiteLLM Looter | `type` (envVar/hardcoded/vaultRef/inputPrompt/master_key/apiKey/virtual_key), `name`, `source`, `is_exposed`, `high_entropy`, `value_hash` (SHA-256) |
| `Host` | Config + A2A | `hostname`, `ip`, `is_local`, `is_private`, `is_public` |
| `ConfigFile` | Config | `path`, `client`, `server_count` |
| `InstructionFile` | Config | `path`, `type` (agents.md/claude.md/cursorrules/copilot-instructions/memory.md), `hash`, `is_suspicious` |
| `OllamaInstance` | Network scan + Ollama fingerprinter | `endpoint`, `version`, `auth_method`, `is_anonymous_loot`, `discovered_via` |
| `VLLMInstance` | Network scan + vLLM fingerprinter | `endpoint`, `version`, `auth_method`, `is_anonymous_loot` |
| `QdrantInstance` | Network scan + Qdrant fingerprinter | `endpoint`, `version`, `collection_count` |
| `MLflowServer` | Network scan + MLflow fingerprinter | `endpoint`, `version`, `experiment_count` |
| `LiteLLMGateway` | Network scan + LiteLLM fingerprinter | `endpoint`, `auth_method`, `is_anonymous_loot`, `docs_enabled` |
| `JupyterServer` | Network scan + Jupyter fingerprinter | `endpoint`, `version`, `token_required` |
| `LangServeApp` | Network scan + LangServe fingerprinter | `endpoint`, `chains` |
| `OpenWebUIInstance` | Network scan + Open WebUI fingerprinter | `endpoint`, `version`, `webui_auth_enabled` |
| `AIService` | Multi-label umbrella (see below) | _(no unique properties — carried as companion label)_ |
| `AIModel` | Ollama Looter | `name`, `size`, `digest`, `family`, `parameter_size`, `quantization` |
| `ExtractedTrainingSignal` | Extractors | `kind`, `source_model`, `sample_count`, `confidence` |

### Synthetic (2 kinds, post-processor created)

These labels exist in `AllNodeLabels` but NOT in `AllowedNodeKinds` — collectors cannot emit them.

| Label | Source | Key Properties |
|-------|--------|----------------|
| `ResourceGroup` | Post-processor | `type`, `sensitivity` |
| `TrustZone` | Post-processor | `name`, `level`, `node_count` |

### A2AAgent Signature Verification (`is_signed`, `signature_valid`)

`A2AAgent` carries two independent signature properties:

- **`is_signed`** — `true` when the agent card has a non-empty `signatures[]` array, regardless of cryptographic validity.
- **`signature_valid`** — `true` only when every signature in the card cryptographically verifies against a key in the card's inline `jwks`.

The collector accepts both JWS serializations a card may use:

- **Compact** — each `signatures[]` entry is a compact JWS string.
- **Flattened JSON (object form)** — each entry is `{ "protected": "<b64url>", "signature": "<b64url>" }`, the spec-conformant A2A shape. The signed payload is the agent card with the `signatures` member removed and JCS-canonicalized (RFC 8785 key ordering, no insignificant whitespace); it is embedded base64url-encoded as the JWS payload and verified per RFC 7515. Tampering with any other card field invalidates the signature.

`signature_valid` is `false` (card unverifiable, not a verification failure) when the card omits inline `jwks`. Remote `jwks_uri` fetching is not performed — a card whose keys live only behind `jwks_uri` reports `signature_valid=false`.

---

## 2. Umbrella Labels

The `AIService` label is a **multi-label companion**, not a standalone node kind. Every per-service node (`OllamaInstance`, `VLLMInstance`, `QdrantInstance`, `MLflowServer`, `LiteLLMGateway`, `JupyterServer`, `LangServeApp`, `OpenWebUIInstance`) also carries `:AIService` as a secondary Neo4j label.

This enables queries like `MATCH (n:AIService)` to find all AI infrastructure regardless of specific service type, while per-kind queries (`MATCH (n:OllamaInstance)`) still work.

**Schema constraint implication:** The schema-init loop skips labels in `UmbrellaLabels` when creating `objectid IS UNIQUE` constraints. A uniqueness constraint on `:AIService` would falsely collide between distinct service kinds.

---

## 3. Edge Types

### Raw Edges (17 collector-produced)

| Edge | Source | Target | Collector | Meaning |
|------|--------|--------|-----------|---------|
| `TRUSTS_SERVER` | AgentInstance | MCPServer | Config | Agent trusts this server to provide tools |
| `PROVIDES_TOOL` | MCPServer | MCPTool | MCP | Server exposes this tool |
| `PROVIDES_RESOURCE` | MCPServer / JupyterServer | MCPResource | MCP / Jupyter Looter | Server exposes this resource |
| `PROVIDES_PROMPT` | MCPServer | MCPPrompt | MCP | Server exposes this prompt template |
| `ADVERTISES_SKILL` | A2AAgent | A2ASkill | A2A | Agent advertises this skill |
| `DELEGATES_TO` | A2AAgent | A2AAgent | A2A | Agent delegates tasks to another agent |
| `AUTHENTICATES_WITH` | MCPServer / A2AAgent | Identity | Config / A2A | Entity uses this auth identity |
| `USES_CREDENTIAL` | Identity | Credential | Config | Identity backed by this credential material |
| `RUNS_ON` | MCPServer / A2AAgent | Host | Config / A2A | Entity runs on this host |
| `CONFIGURED_IN` | MCPServer | ConfigFile | Config | Server defined in this config file |
| `HAS_ENV_VAR` | MCPServer | Credential | Config | Server has access to this env var |
| `LOADS_INSTRUCTIONS` | AgentInstance | InstructionFile | Config | Agent loads this instruction file |
| `SAME_AUTH_DOMAIN` | A2AAgent | A2AAgent | A2A | Agents share an authentication domain |
| `EXPOSES` | AIService | AIService | Fingerprinters | Service exposes another service (e.g., Open WebUI → Ollama backend) |
| `EXPOSES_CREDENTIAL` | AIService | Credential | LiteLLM Looter | Service exposes credential material (master keys, upstream provider keys, virtual keys) |
| `PROVIDES_MODEL` | OllamaInstance | AIModel | Ollama Looter | Instance serves this model |
| `EXTRACTED_FROM` | AIModel | ExtractedTrainingSignal | Extractors | Extracted signal was derived from this model |

### Composite Edges (8 post-processor computed)

| Edge | Source | Target | Depends On | Meaning |
|------|--------|--------|------------|---------|
| `HAS_ACCESS_TO` | MCPTool | MCPResource | Raw edges | Capability surface matches resource URI scheme |
| `CAN_EXECUTE` | MCPTool | Host | Raw edges | Tool has shell_access or code_execution capability |
| `SHADOWS` | MCPTool | MCPTool | Raw edges | Tool on another server references this tool's name/description |
| `POISONED_DESCRIPTION` | MCPTool | MCPTool (self-edge) | Raw edges | Tool description contains injection patterns |
| `POISONED_INSTRUCTIONS` | InstructionFile | InstructionFile (self-edge) | Raw edges | Suspicious patterns: imperative overrides, exfiltration commands, hidden Unicode |
| `CAN_REACH` | AgentInstance / A2AAgent | MCPResource | HAS_ACCESS_TO | Transitive access through trust chain (includes cross-protocol and credential chain variants up to 6 hops) |
| `CAN_EXFILTRATE_VIA` | AgentInstance | MCPTool | CAN_REACH | Agent reaches sensitive data AND has outbound exfiltration channel |
| `CAN_IMPERSONATE` | A2AAgent | A2AAgent | Raw edges | TF-IDF cosine similarity > 0.8 on skill descriptions |

### Edge Struct (Go SDK)

```go
type Edge struct {
    Source     string         `json:"source"`
    Target     string         `json:"target"`
    Kind       string         `json:"kind"`
    SourceKind string         `json:"source_kind,omitempty"`
    TargetKind string         `json:"target_kind,omitempty"`
    Properties map[string]any `json:"properties"`
}
```

### Edge Properties (all edges carry these)

| Property | Type | Description |
|----------|------|-------------|
| `scan_id` | string | Scan that created/updated this edge |
| `last_seen` | ISO 8601 | Timestamp of last observation |
| `confidence` | float64 | 0.0–1.0 confidence score |
| `risk_weight` | float64 | Lower = easier to exploit (used by Dijkstra) |
| `is_composite` | bool | True for post-processed edges |
| `evidence` | string | Human-readable explanation |

Composite edges additionally carry `source_collector` (`mcp`, `a2a`, `config`, or a processor-owned source such as `cross_service_credential_chain`) for scoped stale-edge cleanup.

---

## 4. Node ID Strategy

All node IDs are deterministic, content-based SHA-256 hashes. This ensures identical entities from different collectors merge on the same Neo4j node.

| Node Kind | ID Computation |
|-----------|----------------|
| `MCPServer` | `SHA-256("MCPServer:" + transport + ":" + endpoint + ":" + sorted_args)` |
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

**Critical invariant:** The MCPServer ID MUST match between Config Collector and MCP Collector outputs. This is the merge point connecting trust relationships (who trusts what) to capabilities (what a server exposes). `ComputeMCPServerID` trims surrounding whitespace from the endpoint and each arg before hashing, so `"npx "` and `"npx"` produce the same ID regardless of which collector parsed the config.

---

## 5. Cross-Collector Merge via value_hash

The `value_hash` property on `Credential` nodes is the cross-collector merge primitive. It enables the `cross_service_credential_chain` post-processor to join credentials discovered independently by different collectors.

**How it works:**

1. Config Collector emits a Credential node via `HAS_ENV_VAR` (MCP server → credential)
2. LiteLLM Looter emits a Credential node via `EXPOSES_CREDENTIAL` (gateway → master/upstream/virtual keys)
3. Both compute `value_hash = SHA-256(credential_value)` via `sdk/common.HashCredentialValue`
4. Same secret value → same `value_hash` → nodes merge on `objectid` regardless of how each collector derives it

This is what enables attack paths like: `AgentInstance → MCPServer → Credential ← LiteLLMGateway → upstream provider` — proving that a local agent's environment variable is the same key that a LiteLLM gateway uses to reach an upstream LLM provider.

**Requirement:** Every collector or looter MUST populate `value_hash` on every emitted Credential node.

---

## 6. Post-Processor Execution Order

Processors run in strict dependency order. A processor may only read edges produced by earlier processors.

| Order | Processor | Produces | Dependencies |
|-------|-----------|----------|--------------|
| 1 | has_access_to | `HAS_ACCESS_TO` | Raw edges only |
| 2 | can_execute | `CAN_EXECUTE` | Raw edges only |
| 3 | shadows | `SHADOWS` | Raw edges only |
| 4 | poisoned_description | `POISONED_DESCRIPTION` | Raw edges only |
| 5 | poisoned_instructions | `POISONED_INSTRUCTIONS` | Raw edges only |
| 6 | can_reach | `CAN_REACH` | 1 (HAS_ACCESS_TO) |
| 7 | cross_service_credential_chain | `CAN_REACH` (credential variant) | 1, 6 (joins on `Credential.value_hash`) |
| 8 | can_exfiltrate_via | `CAN_EXFILTRATE_VIA` | 6 (CAN_REACH) |
| 9 | can_impersonate | `CAN_IMPERSONATE` | Raw edges only |
| 10 | cross_protocol | `CAN_REACH` (cross-protocol) | 1 (HAS_ACCESS_TO) + DELEGATES_TO |
| 11 | risk_score | Node property updates | 1–10 (all prior processors) |

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
- `ON MATCH SET n.previous_description_hash = n.description_hash` preserves old hash for rug-pull detection
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
    "scan_id": "scan-abc123"
  },
  "graph": {
    "nodes": [{"id": "sha256:...", "kinds": ["MCPServer"], "properties": {...}}],
    "edges": [{"source": "sha256:...", "target": "sha256:...", "kind": "PROVIDES_TOOL", "properties": {...}}]
  }
}
```

**Rules for module authors:**

1. Only emit node kinds in `AllowedNodeKinds` and edge kinds in `RawEdgeKinds`
2. Compute deterministic `id` values per the Node ID Strategy above
3. Populate `value_hash` on all `Credential` nodes
4. Set `source_kind` / `target_kind` on edges when the endpoint map has multiple valid sources/targets
5. Use snake_case for all property keys (the normalizer converts camelCase, but emit clean data)
6. Valid collectors: `mcp`, `a2a`, `config`, `scan`
