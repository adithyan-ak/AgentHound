# Graph model

AgentHound stores collector observations as raw nodes and edges, then builds composite analysis relationships on the server. Every public node uses a deterministic `objectid` and one identity-owning concrete kind.

## Nodes

| Group | Kinds |
|---|---|
| MCP | `MCPServer`, `MCPTool`, `MCPResource`, `MCPPrompt` |
| A2A | `A2AAgent`, `A2ASkill` |
| Local context | `AgentInstance`, `Host`, `ConfigFile`, `InstructionFile` |
| Authentication | `Identity`, `Credential` |
| AI services | `OllamaInstance`, `VLLMInstance`, `QdrantInstance`, `MLflowServer`, `LiteLLMGateway`, `JupyterServer`, `LangServeApp`, `OpenWebUIInstance` |
| Served models | `AIModel` |
| Typed resources | `VectorCollection`, `VectorPoint`, `WorkspaceFile`, `ModelArtifact`, `ArtifactStore` |
| Query umbrella | `AIService` |

Concrete AI-service nodes also carry the `AIService` label. The umbrella label is for queries and does not own identity.

`AIModel` is a model served by a runtime such as Ollama. A persisted MLflow model version is a `ModelArtifact`, not an `AIModel`. `VectorCollection` represents a Qdrant collection; bounded deep reads retain individual point references as `VectorPoint` without treating them as MCP resources. `WorkspaceFile` represents either a notebook or a regular file through its `entry_type` property.

### Credential material

| Property | Meaning |
|---|---|
| `value` | Concrete raw material observed by the collector. |
| `value_hash` | SHA-256 identity used for deduplication and evidence joins. |
| `material_status` | Whether the material is observed, masked, hashed, or otherwise unavailable. |
| `exposure_status` | Whether collection observed the credential as exposed. |
| `source`/`sources` and provenance fields | Where the material or reference came from; repeated observations retain sorted plural values. |

Only concrete `value` material becomes planner input. The normal dashboard property view masks it; explicit query output and JSON export remain literal.

Credential identity is role- and scope-aware:

| Observation | Identity rule | Result |
|---|---|---|
| Concrete material repeated across agent configurations | `value_hash` within the collection point | One Credential retains sorted plural provenance and every graph association. |
| Concrete material accepted for a service credential role | Service endpoint, role, and `value_hash` | Repeating the same secret is idempotent; different secrets remain different nodes. |
| Masked, hashed, or unresolved material | Source-specific identity with `merge_key=identity` | Reference evidence never merges with observed executable material. |
| The same material observed in different evidence roles | Distinct role-owned nodes correlated by `value_hash` | Topology and provenance remain intact without presenting the same value twice to one endpoint. |

Planner candidate identity includes the endpoint and `value_hash`, so duplicate observations of one concrete secret do not produce duplicate credential-bearing requests to the same surface.

### Instruction evidence

`InstructionFile` records the canonical `path`, source `type`, content `hash`, captured `size_bytes`, and `modified_at`. Its classification fields are:

| Property | Meaning |
|---|---|
| `instruction_verdict` | `clean`, `signal`, or `poisoning`. |
| `instruction_scope` | `exact_project`, `exact_user`, or recursive `deep`. |
| `instruction_signal_count` | Total classified signals before retention limits. |
| `instruction_signal_truncated` | Whether some signals were omitted from the bounded evidence. |
| `instruction_evidence_version` | Structured evidence contract version. |
| `instruction_evidence_json` | Up to 32 ordered signals and 64 KiB of source-exact matched excerpts, local context, positions, and optional decoded previews. Large encoded tokens retain the bounded raw excerpt that maps to the decisive decoded semantics. |

The evidence contains only bounded excerpts, not the complete instruction file.

## Raw edges

Raw edges come from collectors or same-scan proof actions.

| Area | Edge kinds |
|---|---|
| MCP topology | `TRUSTS_SERVER`, `PROVIDES_TOOL`, `PROVIDES_RESOURCE`, `PROVIDES_PROMPT` |
| A2A topology | `ADVERTISES_SKILL`, `DELEGATES_TO`, `SAME_AUTH_DOMAIN` |
| Authentication | `AUTHENTICATES_WITH`, `USES_CREDENTIAL`, `HAS_ENV_VAR`, `EXPOSES_CREDENTIAL` |
| Host and configuration | `RUNS_ON`, `CONFIGURED_IN`, `LOADS_INSTRUCTIONS` |
| Service inventory | `EXPOSES` (historical), `PROVIDES_MODEL`, `PROVIDES_RESOURCE`, `USES_BACKEND`, `STORED_IN` |
| Untrusted input | `INGESTS_UNTRUSTED` |
| Access observations | `CREDENTIAL_ACCESS_OBSERVED`, `PUBLIC_ACCESS_OBSERVED` |

`CREDENTIAL_ACCESS_OBSERVED` connects a Credential to the exact MCPResource read successfully after the anonymous control was denied. `PUBLIC_ACCESS_OBSERVED` connects the MCPServer to a resource read anonymously. Both are supporting evidence rather than general traversal shortcuts.

`PROVIDES_RESOURCE` retains historical service-to-`MCPResource` variants for V1 artifacts. New collection emits typed pairs: QdrantInstance→VectorCollection, VectorCollection→VectorPoint, JupyterServer→WorkspaceFile, and MLflowServer→ModelArtifact. `USES_BACKEND` records an explicit service dependency; `STORED_IN` records a model artifact's reported physical store.

New typed-resource and backend edges include `evidence_state`: `configured` proves only that the source contains the reference, `observed` means the source API reported it, and `verified` requires authoritative enumeration or a bounded request through the source. Probing a destination separately does not upgrade a configured backend relationship.

## Composite edges

| Edge | Source → target | Meaning |
|---|---|---|
| `HAS_ACCESS_TO` | MCPTool → MCPResource | Capability and resource evidence support access. |
| `CAN_EXECUTE` | MCPTool → Host | Tool capability supports shell or code execution. |
| `CAN_REACH` | AgentInstance/A2AAgent → MCPResource/Credential | A deterministic trust, capability, credential, or cross-protocol path exists. |
| `CAN_EXFILTRATE_VIA` | AgentInstance → MCPTool | Sensitive access combines with an outbound channel. |
| `SHADOWS` | MCPTool → MCPTool | A tool name or description can shadow another tool. |
| `POISONED_DESCRIPTION` | MCPTool → MCPTool | Description content contains an injection signal. |
| `INSTRUCTION_SIGNAL` | InstructionFile → InstructionFile | A standalone local signal, or strong evidence seen only in recursive deep scope, requires review. |
| `POISONED_INSTRUCTIONS` | InstructionFile → InstructionFile | Strong, locally correlated poisoning evidence occurs in an exact project or user instruction scope. |
| `POISONS_CONTEXT` | MCPTool → MCPTool | An injection-bearing tool shares agent context with a high-impact tool. |
| `TAINTS` | MCPTool → MCPTool | Untrusted input can flow between compatible tool schemas. |
| `IFC_VIOLATION` | MCPTool → MCPTool | Untrusted input can reach a high-impact sink through shared resources. |
| `CAN_IMPERSONATE` | A2AAgent → A2AAgent | Skill similarity exceeds the impersonation threshold. |
| `CONFUSED_DEPUTY` | A2AAgent → A2AAgent | A weaker caller can delegate into a stronger callee. |

Composite edges carry `source_collector`, confidence, risk weight, and processor-specific evidence. They are regenerated from the current raw projection rather than accepted from collector input.

## Identity and scope

Raw IDs are deterministic SHA-256 values derived from kind-specific identity fields. Ingest adds collection scope so unrelated environments cannot collide:

- Collection-point scope represents one collector installation or host context.
- Network-context scope represents shared reachable infrastructure.
- Global value identity is reserved for explicit merge primitives such as concrete credential hashes.

Display names, timestamps, and mutable descriptions do not define identity. Reference-only contributions follow the authoritative observation for the same raw ID.

## Coverage and lifecycle

Each collector reports outcomes such as `complete`, `partial`, `failed`, `truncated`, or `not_applicable`. Service resources belong to a stable service-instance inventory surface. Only a complete surface can reconcile its children; failed credential guesses, truncation, and partial traversal preserve earlier facts. The shared autonomous-scan root becomes complete only when every blocking inventory surface is complete.

Composite analysis is rebuilt as one epoch after raw reconciliation. Published scan metadata records both submitted counts and the resulting graph totals.

## Finding evidence

Findings classify evidence as observed, inferred, verified, hypothesis, reference-only, or unknown. A verified `CAN_REACH` finding contains `evidence.proof` with the action ID, verification time, differential control and credential stages, outcome, and cleanup status.

Finding detail returns the exact evidence subgraph captured at publication. Instruction finding detail additionally returns structured `instruction_evidence` extracted from that immutable snapshot. It does not rerun graph discovery when the detail page is opened.
