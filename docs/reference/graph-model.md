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
| Model inventory | `AIModel` |
| Query umbrella | `AIService` |

Concrete AI-service nodes also carry the `AIService` label. The umbrella label is for queries and does not own identity.

### Credential material

| Property | Meaning |
|---|---|
| `value` | Concrete raw material observed by the collector. |
| `value_hash` | SHA-256 identity used for deduplication and evidence joins. |
| `material_status` | Whether the material is observed, masked, hashed, or otherwise unavailable. |
| `exposure_status` | Whether collection observed the credential as exposed. |
| `source` and provenance fields | Where the material or reference came from. |

Only concrete `value` material becomes planner input. The normal dashboard property view masks it; explicit query output and JSON export remain literal.

## Raw edges

Raw edges come from collectors or same-scan proof actions.

| Area | Edge kinds |
|---|---|
| MCP topology | `TRUSTS_SERVER`, `PROVIDES_TOOL`, `PROVIDES_RESOURCE`, `PROVIDES_PROMPT` |
| A2A topology | `ADVERTISES_SKILL`, `DELEGATES_TO`, `SAME_AUTH_DOMAIN` |
| Authentication | `AUTHENTICATES_WITH`, `USES_CREDENTIAL`, `HAS_ENV_VAR`, `EXPOSES_CREDENTIAL` |
| Host and configuration | `RUNS_ON`, `CONFIGURED_IN`, `LOADS_INSTRUCTIONS` |
| Service inventory | `EXPOSES`, `PROVIDES_MODEL` |
| Untrusted input | `INGESTS_UNTRUSTED` |
| Access observations | `CREDENTIAL_ACCESS_OBSERVED`, `PUBLIC_ACCESS_OBSERVED` |

`CREDENTIAL_ACCESS_OBSERVED` connects a Credential to the exact MCPResource read successfully after the anonymous control was denied. `PUBLIC_ACCESS_OBSERVED` connects the MCPServer to a resource read anonymously. Both are supporting evidence rather than general traversal shortcuts.

## Composite edges

| Edge | Source → target | Meaning |
|---|---|---|
| `HAS_ACCESS_TO` | MCPTool → MCPResource | Capability and resource evidence support access. |
| `CAN_EXECUTE` | MCPTool → Host | Tool capability supports shell or code execution. |
| `CAN_REACH` | AgentInstance/A2AAgent → MCPResource/Credential | A deterministic trust, capability, credential, or cross-protocol path exists. |
| `CAN_EXFILTRATE_VIA` | AgentInstance → MCPTool | Sensitive access combines with an outbound channel. |
| `SHADOWS` | MCPTool → MCPTool | A tool name or description can shadow another tool. |
| `POISONED_DESCRIPTION` | MCPTool → MCPTool | Description content contains an injection signal. |
| `POISONED_INSTRUCTIONS` | InstructionFile → InstructionFile | Instruction content contains an injection signal. |
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

Each collector reports outcomes such as `complete`, `partial`, `failed`, `truncated`, or `not_applicable`. Complete authoritative roots can reconcile their current children. Other outcomes add evidence without asserting that omitted nodes or edges disappeared.

Composite analysis is rebuilt as one epoch after raw reconciliation. Published scan metadata records both submitted counts and the resulting graph totals.

## Finding evidence

Findings classify evidence as observed, inferred, verified, hypothesis, reference-only, or unknown. A verified `CAN_REACH` finding contains `evidence.proof` with the action ID, verification time, differential control and credential stages, outcome, and cleanup status.

Finding detail returns the exact evidence subgraph captured at publication. It does not rerun graph discovery when the detail page is opened.
