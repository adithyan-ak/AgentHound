# Detection Rules

AgentHound detects security issues in AI agent infrastructure through graph analysis and pattern matching. All detections are mapped to [OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and [OWASP Agentic Security Initiative Top 10](https://genai.owasp.org/), and confidently-mappable detections additionally carry a [MITRE ATLAS](https://atlas.mitre.org/) technique crosswalk (see [MITRE ATLAS crosswalk](#mitre-atlas-crosswalk)).

## Two layers of detection

AgentHound surfaces findings through two complementary layers:

| Layer | Where it runs | Count | Storage |
|---|---|---|---|
| **YAML rules engine** | Inside collectors at scan time. Drives capability classification, credential extraction, prompt-injection pattern matching, instruction-file poisoning, source-trust tagging, and resource-sensitivity classification. | **35 builtin rules** | `sdk/rules/builtin/*.yaml`. Inspect with `agenthound rules list`; test with `agenthound rules test`; query the running server via `GET /api/v1/rules`. |
| **Pre-built graph queries** | Inside `agenthound-server` against the post-processed Neo4j graph. Each query expresses a high-level finding as a Cypher path or pattern. | **19 queries** | `server/internal/analysis/prebuilt/`. Surface as findings via `GET /api/v1/analysis/findings`, runnable via `GET /api/v1/analysis/prebuilt/{id}` or `agenthound-server query --prebuilt <id>`. |

The two layers feed each other: the rules engine emits structured signals (`capability_surface`, `exposure_status`, `material_status`, `high_entropy`, `has_injection_patterns`, `source_trust`, sensitivity classifications) on collected nodes; the post-processors and pre-built queries consume those signals to compute composite edges (`HAS_ACCESS_TO`, `CAN_REACH`, `POISONED_DESCRIPTION`, `TAINTS`, `IFC_VIOLATION`, `CONFUSED_DEPUTY`, `POISONS_CONTEXT`, etc.) and enumerate attack paths.

The detections summarized below are the **pre-built-query** layer. The 35 underlying YAML rules are not enumerated here individually — read them directly in `sdk/rules/builtin/` for the canonical truth. Composite-edge detections (`TAINTS`, `IFC_VIOLATION`, `CONFUSED_DEPUTY`, `POISONS_CONTEXT`) surface through `GET /api/v1/analysis/findings` rather than a named pre-built query.

## Scan-specific ruleset provenance

Each scan artifact records the effective text and fingerprint rules that
actually ran. Every manifest entry includes the rule ID/version/source class,
a semantic SHA-256 content identifier, and a canonical
`effective_matcher` JSON definition. Text entries preserve the compiled matcher
shape; fingerprint entries preserve the effective probe and response-matcher
sequence, including same-ID bundle overrides.

Files that cannot be read, parsed, validated, or compiled are not silently
treated as loaded. Their failures are persisted in `ruleset.errors` and make
`ruleset.load_state` `partial` (or `failed` when no rule loaded). The Rules page
can load a requested scan directly by ID, including scans older than the first
history page, and displays these recorded definitions separately from the
server's current catalog.

`ruleset.digest` and each `semantic_sha256` are content identities only.
`authenticity: unverified` is explicit: no digest is a signature or a claim
that the rule source was trusted.

## Detection summary

| Detection | Severity | Pre-built query | OWASP mapping | MITRE ATLAS |
|-----------|----------|-----------------|---------------|-------------|
| Tool poisoning | high | `poisoned-tools` | MCP05, ASI03 | AML.T0051, AML.T0110 |
| Tool shadowing | high | `tool-shadowing` | MCP05, ASI03 | AML.T0110 |
| Tool name collision | high | `tool-name-collision` | MCP05, ASI03 | AML.T0110 |
| Tool description rug pull | high | `rug-pull` | MCP05, MCP09 | AML.T0110, AML.T0010 |
| Unauthenticated MCP servers | high | `no-auth-servers` | MCP03, ASI04 | — |
| Unauthenticated A2A agents | high | `no-auth-a2a` | MCP03, ASI04 | — |
| Instruction file poisoning | high | `instruction-poisoning` | MCP05, ASI03 | AML.T0051 |
| Hardcoded secrets | high | `high-entropy-secrets` | MCP03, ASI04 | — |
| Shell access paths | critical | `agents-shell-access` | MCP01, ASI06 | — |
| Database access paths | critical | `shortest-to-database` | MCP04, ASI08 | — |
| Data exfiltration routes | critical | `exfiltration-routes` | MCP04, ASI08, ASI10 | AML.T0086 |
| Cross-protocol host correlations | medium | `cross-protocol-paths` | MCP01, ASI01, ASI06 | — |
| Credential chain paths | critical | `credential-chain` | MCP03, ASI04 | — |
| Observed LiteLLM master-key exposure | critical | `litellm-credential-leak` | MCP03, ASI04 | — |
| Unpinned packages | medium | `unpinned-packages` | MCP09, ASI09 | — |
| Unsigned agent cards | medium | `unsigned-cards` | MCP09, ASI09 | — |
| Unpinned packages + shell access | critical | `unpinned-shell` | MCP01, MCP09, ASI06, ASI09 | — |
| Chokepoint servers | medium | `chokepoint-servers` | MCP01, ASI06 | — |
| Chokepoint tools | medium | `chokepoint-tools` | MCP01, ASI06 | — |

---

## MITRE ATLAS crosswalk

Alongside the OWASP mappings, AgentHound annotates findings and pre-built queries with a [MITRE ATLAS](https://atlas.mitre.org/) technique crosswalk via the `atlas_map` field (see [API reference](api.md)). ATLAS catalogues adversary tactics and techniques against AI-enabled systems, so the crosswalk lets findings line up with threat-intel and detection-engineering workflows that already speak ATLAS.

**Conservative, verified-only policy.** AgentHound only ships an ATLAS tag where the mapping is unambiguous. Detections whose technique assignment is uncertain carry **no** `atlas_map` (the field is omitted, not empty) and are left for analyst assignment rather than shipping a speculative tag. The canonical technique set lives in `server/internal/analysis/atlas.go` (`ATLASTechniques`) and is guarded by `atlas_test.go`, which fails the build if any finding or pre-built query references a technique ID not present in that map — preventing a typo or stale `AML.Txxxx` from shipping. The UI title map in `server/ui/src/features/findings/lib/owasp-titles.ts` mirrors the same set.

The per-edge crosswalk (composite-edge findings from `GET /api/v1/analysis/findings`):

| Composite edge | MITRE ATLAS | Technique |
|----------------|-------------|-----------|
| `POISONED_DESCRIPTION` | AML.T0051, AML.T0110 | LLM Prompt Injection; AI Agent Tool Poisoning |
| `POISONS_CONTEXT` | AML.T0051, AML.T0110 | LLM Prompt Injection; AI Agent Tool Poisoning |
| `SHADOWS` | AML.T0110 | AI Agent Tool Poisoning |
| `POISONED_INSTRUCTIONS` | AML.T0051 | LLM Prompt Injection |
| `TAINTS` | AML.T0051 | LLM Prompt Injection |
| `IFC_VIOLATION` | AML.T0057, AML.T0086 | LLM Data Leakage; Exfiltration via AI Agent Tool Invocation |
| `CAN_EXFILTRATE_VIA` | AML.T0086 | Exfiltration via AI Agent Tool Invocation |
| `CAN_REACH`, `HAS_ACCESS_TO`, `CAN_EXECUTE`, `CAN_IMPERSONATE`, `CONFUSED_DEPUTY` | — | Intentionally unmapped pending analyst assignment |

**Why `CAN_EXFILTRATE_VIA` maps to AML.T0086 but not AML.T0024.** ATLAS distinguishes *Exfiltration via AI Agent Tool Invocation* (AML.T0086) from *Exfiltration via AI Inference API* (AML.T0024). The `CAN_EXFILTRATE_VIA` edge models an agent reaching sensitive data and pushing it out through a **tool/channel it can invoke** — the AML.T0086 pattern. AML.T0024 describes extracting data *through the model's inference API itself* (e.g. prompting the model to regurgitate training data), which this edge does not represent, so it is deliberately excluded.

`AML.T0020` (Poison Training Data) and `AML.T0010` (AI Supply Chain Compromise) are seeded in the technique set for pre-built-query and future use; it is expected that not every seeded technique is referenced by a composite edge.

---

## Tool poisoning (MCP05)

**What:** MCP tool descriptions match configured suspicious-instruction patterns.

**How detected:** The MCP Collector scans tool descriptions for injection markers (imperative instructions, base64 blobs, hidden Unicode, references to ignoring safety instructions). Detected tools get a `POISONED_DESCRIPTION` self-edge.

**Risk:** A matched description may influence agent planning. The pattern match identifies content for review; it does not prove that an agent followed it.

**Example finding:**
```
MCPTool:dangerous-tool has injection pattern: "ignore all previous instructions"
```

## Tool shadowing (MCP05)

**What:** A tool on one server mimics or references a tool on another server, potentially hijacking agent actions.

**How detected:** The SHADOWS post-processor compares tool descriptions across servers. When a tool on server B references server A's tool by name or has a suspiciously similar description, a `SHADOWS` edge is created.

**Risk:** An attacker controlling a low-trust server can shadow a legitimate tool. When an agent calls the shadowed tool, the malicious server handles the request instead.

## Tool name collision (MCP05, ASI03)

**What:** Tools on different servers share a normalized (trimmed, lower-cased) name.

**How detected:** The `tool-name-collision` pre-built query matches `MCPTool` nodes across distinct servers whose names collide after normalization, with distinct `objectid`s.

**Risk:** A malicious server can register a tool with the same name as a trusted one. Depending on resolution order, the agent may invoke the attacker's tool instead — a name-based variant of tool shadowing.

## Rug pull detection (MCP05, MCP09)

**What:** A tool's pinned surface changes between scans, potentially indicating a supply chain attack.

**How detected:** Each tool carries `description_hash` and `input_schema_hash`; each server carries `instructions_hash`. The node MERGE pivots `previous_*_hash` on every scan. The `rug-pull` pre-built query fires when any of the three current hashes differs from its previous value, and returns a `change_kind` discriminator (`description`, `input_schema`, `instructions`, or a comma-joined combination) identifying which surface drifted.

**Risk:** An attacker who gains control of an MCP server package can change tool descriptions, input schemas, or server instructions to include injection patterns after the initial trust decision was made. Schema and instruction pinning catch rug pulls that leave the description untouched.

## Unauthenticated servers (MCP03)

**What:** Network MCP servers that accepted a probe without credentials.

**How detected:** Direct probes emit canonical auth evidence. A no-auth query
requires both `auth_method: none` and
`auth_evidence: anonymous_probe_succeeded`; configuration with no credential,
local stdio transport, missing evidence, and `unknown` posture do not match.

**Risk:** Confirmed anonymous network access removes an authentication boundary
for reachable clients. A local stdio child process is a separate process-local
trust path and is not classified as anonymous network access.

## Instruction file poisoning (MCP05, ASI03)

**What:** Agent instruction files (`.claude/CLAUDE.md`, `.cursorrules`, `agents.md`, etc.) contain suspicious patterns.

**How detected:** The Config Collector scans instruction files for imperative overrides ("you must", "ignore previous"), exfiltration commands (curl/wget to external URLs), hidden Unicode (zero-width characters, RTL overrides), and encoded payloads. Flagged files get a `POISONED_INSTRUCTIONS` self-edge.

**Risk:** Poisoned instructions can override agent safety behavior, cause data exfiltration, or grant unauthorized access.

## Hardcoded secrets (MCP03, ASI04)

**What:** High-entropy strings in MCP server configuration that are likely hardcoded API keys or secrets.

**How detected:** The Config Collector measures Shannon entropy of observed credential values. Base64 strings with entropy > 4.5 and hex strings with entropy > 3.0 are flagged as `high_entropy`. Masked, hashed, unobserved, and identity-only credential references are excluded.

**Risk:** Secrets in config files end up in version control, backups, and logs. Rotation is difficult because the secret is embedded in client configurations across machines.

## Unsigned agent cards (MCP09, ASI09)

**How detected:** The query requires
`signature_verification_status=unsigned`. Missing verification status is
unknown and does not match.

## Shell access paths (MCP01)

**What:** An agent can reach tools with shell execution or code execution capabilities.

**How detected:** The CAN_EXECUTE post-processor identifies tools with
`shell_access` or `code_execution` in their `capability_surface`. Built-in
execution matchers use token boundaries and require either an explicit
execution phrase or execution verb plus shell/language context. Database-only
names such as `execute_query`, Python documentation search, `terminally`, and
`command_reference` do not classify as shell/code execution. Inventory and
readiness prose such as "List available Python scripts ... to run later" and
"Show whether the Python data pipeline is ready to execute" is also excluded;
the classifier requires the execution action to directly govern code, a
language runtime, or a script. The
`agents-shell-access` query traces configured trust relationships to classified
tools. The metadata-derived edge carries 80% confidence and remains an
inference pending implementation and sandbox verification.

**Risk:** Confirmed shell access can become arbitrary command execution on the server host. The classifier and trust path identify a candidate route; confirm tool implementation, authorization, and sandboxing before treating it as RCE.

## Data exfiltration routes (MCP04, ASI08)

**What:** An agent can reach sensitive data (databases, credentials, files) AND has an outbound channel (network_outbound, email_send).

**How detected:** The CAN_EXFILTRATE_VIA post-processor combines CAN_REACH edges to sensitive resources with tools that have an outbound capability. The outbound capability set is `email_send`, `network_outbound`, `file_write`, plus two channel classes:

- **`auto_fetch_render`** — tools that return content the host may auto-fetch/render (markdown images, HTML previews). *Caveat:* this detects tools that **return** renderable content, not the host's render policy — host-side rendering behavior is not observable by the collector, so treat it as a candidate channel.
- **`allowlisted_proxy`** — tools that proxy requests through an allowlisted egress, which can slip exfiltration past naive egress controls.

**Risk:** The combined capabilities form a potential output route. The detector does not observe data transfer or prove that the agent can invoke every relationship at runtime.

## Untrusted input sources & taint (MCP05, ASI03)

**What:** Tools that ingest attacker-controllable content (open web, inbound email, external file shares) and the downstream flow of that taint into other tools and sensitive sinks.

**How detected:** The `source-untrusted-web`, `source-untrusted-email`, and `source-untrusted-fileshare` rules tag matching tools with a `source_trust` property. The MCP Collector then emits an `INGESTS_UNTRUSTED` raw edge from each tagged tool to the resources on its server. Two post-processors consume that signal:

- **`TAINTS`** — links an untrusted-input tool to a tool on **another** server when they share ≥2 input-schema keys, modeling data flow between tools with compatible inputs.
- **`IFC_VIOLATION`** — links an untrusted source to a high-impact sink (`credential_access` / `file_write` / `email_send`) that shares a resource within 3 `HAS_ACCESS_TO` hops, an information-flow-control violation.

Keyword sets are kept deliberately narrow — universal taint destroys signal.

**Risk:** Untrusted content reaching a privileged tool is the core indirect-prompt-injection primitive: an attacker who controls a fetched web page or inbound email can drive a credential- or file-writing tool.

## Confused deputy (ASI06, MCP04)

**What:** A weakly-authenticated A2A agent can drive a strongly-authenticated one through delegation, borrowing its privileges.

**How detected:** The `auth_strength` pre-pass materializes both canonical `auth_assurance` and a numeric weakness only for known methods. The `confused_deputy` post-processor requires an unauthenticated/weak caller and a strong callee. Unknown/custom methods have no numeric weakness and cannot satisfy either side.

**Risk:** The anonymous or low-trust caller effectively escalates to the callee's privilege level — a classic confused-deputy escalation across an agent trust boundary.

## Context poisoning (MCP05, ASI03)

**What:** An injection-bearing tool can poison the shared agent context that drives a high-capability tool, even without naming it.

**How detected:** The shadows processor emits a `POISONS_CONTEXT` edge from a tool with `has_injection_patterns=true` to a sibling tool carrying a high-blast capability (`shell_access`, `code_execution`, `credential_access`, `email_send`), where both tools are co-resident under a single agent — reachable via `(AgentInstance)-[:TRUSTS_SERVER]->(:MCPServer)-[:PROVIDES_TOOL]->(:MCPTool)`. The agent scope keeps the edge from becoming a cross-tenant cross product: a poisoner only poisons sinks the *same* agent loads into its context. Fan-out is truncated to 20 sinks per (agent, source) pair (the first 20 by `objectid`) to prevent a cartesian blow-up — over-cap sources are truncated, not suppressed, so the detector still fires in its highest-risk case; `scripts/perf-check.sh` enforces a ≤200 poisoned-pair-per-agent ceiling.

**Risk:** Unlike `SHADOWS` (which requires the poisoner to name its target), context poisoning models the broader case where injected text in one tool's description influences how the agent invokes a dangerous sibling tool.

## Cross-protocol host correlations (MCP01, ASI01)

**What:** An A2A delegation chain and an MCP resource path correlate through services recorded on the same host.

**How detected:** A2A delegation detection requires a boundary-delimited target
name or URL near delegation language and records `match_type`, `match_field`,
and `matched_reference` on the `DELEGATES_TO` edge. Plain compatibility mentions
and negated delegation are benign counterexamples. The lexical edge remains a
50%-confidence hypothesis. The cross-protocol post-processor additionally
requires explicit anonymous-probe evidence for the external A2A actor, then
correlates its possible delegation target with an MCP server recorded on the
same host. The correlation is represented as `CAN_REACH`, but carries
`cross_protocol=true`, 50% confidence,
`variant=cross_protocol_host_correlation`, and
`evidence.state=hypothesis`.

**Risk:** Host co-location is an investigation lead, not proof of an invocation bridge. Validate process isolation, identities, authorization, and an authorized end-to-end call before treating the correlation as reachability.

## Credential chain paths (MCP03, ASI04)

**What:** Multi-hop paths from agents to resources that traverse credential boundaries.

**How detected:** The `credential-chain` pre-built query traces paths up to 6 hops that pass through Identity and Credential nodes, identifying where credential reuse or sharing creates transitive access.

**Risk:** Shared credentials between services create implicit trust relationships. Compromising one credential grants access to all services that share it.

## Observed LiteLLM master-key exposure (MCP03, ASI04)

**What:** LiteLLM gateways where the first-party looter recorded an observed, exposed master key.

**How detected:** The `litellm-credential-leak` pre-built query requires the master-key `Credential` to have `material_status=observed`, `exposure_status=exposed`, and `merge_key=value_hash`, plus an `EXPOSES_CREDENTIAL` edge carrying `assertion_type=observed_credential_exposure`. Provider `apiKey` and virtual-key nodes are optional context and appear only when they are explicitly masked or hashed with `exposure_status=not_observed`; the output marks them as not containing usable material.

**Risk:** A LiteLLM master key is an administrative credential for the gateway. Its exposure can permit model, key, and spend-management operations, but masked or hashed upstream references do not prove that upstream provider secrets are usable.

## Unpinned packages (MCP09)

**What:** MCP servers using `npx -y @package` without a version pin.

**How detected:** The Config Collector parses server commands and flags `npx -y` without `@version` suffix on the package name.

**Risk:** Unpinned packages always fetch the latest version. A supply chain attack on the package registry replaces the server binary for all users.

## Unpinned + shell access (MCP01, MCP09)

**What:** The highest-risk supply chain scenario: an unpinned package that also has shell execution tools.

**How detected:** The `unpinned-shell` pre-built query combines unpinned package detection with shell access capability analysis.

**Risk:** A supply chain attacker gains not just tool manipulation but arbitrary code execution on the host through the shell access tools.

## Agent impersonation (ASI03)

**What:** A2A agents with highly similar skill descriptions, enabling one agent to impersonate another.

**How detected:** The CAN_IMPERSONATE post-processor computes TF-IDF cosine similarity on skill descriptions. Agent pairs with similarity > 0.8 get a `CAN_IMPERSONATE` edge.

**Risk:** In a multi-agent system, a malicious agent mimicking a trusted agent's skills can intercept task delegations.

## Chokepoint analysis (MCP01, ASI06)

**What:** Servers or tools that, if compromised, would impact a disproportionately large number of agents or resources.

**How detected:** The `chokepoint-servers` query finds MCP servers trusted by multiple agents. The `chokepoint-tools` query finds tools with access to many resources.

**Risk:** Chokepoints are high-value targets. Compromising one chokepoint server may grant access to every agent that trusts it.

## Campaign verification (evidence, not a new detection)

The v0.6 [campaign runner](../operator/offensive-actions.md#campaign-runner-verify-and-validate) does not add a detection layer. It **upgrades** or **records evidence** against existing detections:

- **`cred-reach`** verifies a *predicted* credential-gated `CAN_REACH` / credential-chain finding with observed evidence. On a `credential_gated_reach_verified` outcome the emitted `CREDENTIAL_REACH_VERIFIED` raw edge re-correlates on ingest and upgrades the **existing** finding's evidence state to `verified` — it does **not** create a second finding or double-count risk. An `anonymous_access_observed` outcome records a `PUBLIC_ACCESS_OBSERVED` fact; that becomes a finding only where authentication was expected.
- **`mcp-poison-roundtrip`** is a STANDALONE reversible-mutation validation. It produces **no** finding and **no** detection — it validates only that the mutation/rollback machinery works against the target, reporting its oracle and cleanup outcomes separately (see [offensive-actions.md](../operator/offensive-actions.md#mcp-poison-roundtrip-standalone-target-mutation-validation)).
