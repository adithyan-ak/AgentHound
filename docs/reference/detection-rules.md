# Detection Rules

AgentHound detects security issues in AI agent infrastructure through graph analysis and pattern matching. All detections are mapped to [OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and [OWASP Agentic Security Initiative Top 10](https://genai.owasp.org/).

## Two layers of detection

AgentHound surfaces findings through two complementary layers:

| Layer | Where it runs | Count | Storage |
|---|---|---|---|
| **YAML rules engine** | Inside collectors at scan time. Drives capability classification, credential extraction, prompt-injection pattern matching, instruction-file poisoning, and resource-sensitivity classification. | **30 builtin rules** | `sdk/rules/builtin/*.yaml`. Inspect with `agenthound rules list`; test with `agenthound rules test`; query the running server via `GET /api/v1/rules`. |
| **Pre-built graph queries** | Inside `agenthound-server` against the post-processed Neo4j graph. Each query expresses a high-level finding as a Cypher path or pattern. | **17 queries** | `server/internal/analysis/prebuilt/`. Surface as findings via `GET /api/v1/analysis/findings`, runnable via `GET /api/v1/analysis/prebuilt/{id}` or `agenthound-server query --prebuilt <id>`. |

The two layers feed each other: the rules engine emits structured signals (`capability_surface`, `is_exposed`, `has_injection_patterns`, sensitivity classifications) on collected nodes; the post-processors and pre-built queries consume those signals to compute composite edges (`HAS_ACCESS_TO`, `CAN_REACH`, `POISONED_DESCRIPTION`, etc.) and enumerate attack paths.

The 17 detections summarized below are the **pre-built-query** layer. The 30 underlying YAML rules are not enumerated here individually — read them directly in `sdk/rules/builtin/` for the canonical truth.

## Detection summary

| Detection | Severity | Pre-built query | OWASP mapping |
|-----------|----------|-----------------|---------------|
| Tool poisoning | high | `poisoned-tools` | MCP05, ASI03 |
| Tool shadowing | high | `tool-shadowing` | MCP05, ASI03 |
| Tool description rug pull | high | `rug-pull` | MCP05, MCP09 |
| Unauthenticated MCP servers | high | `no-auth-servers` | MCP03, ASI04 |
| Unauthenticated A2A agents | high | `no-auth-a2a` | MCP03, ASI04 |
| Instruction file poisoning | high | `instruction-poisoning` | MCP05, ASI03 |
| Hardcoded secrets | high | `high-entropy-secrets` | MCP03, ASI04 |
| Shell access paths | critical | `agents-shell-access` | MCP01, ASI06 |
| Database access paths | critical | `shortest-to-database` | MCP04, ASI08 |
| Data exfiltration routes | critical | `exfiltration-routes` | MCP04, ASI08, ASI10 |
| Cross-protocol attack paths | critical | `cross-protocol-paths` | MCP01, ASI01, ASI06 |
| Credential chain paths | critical | `credential-chain` | MCP03, ASI04 |
| Unpinned packages | medium | `unpinned-packages` | MCP09, ASI09 |
| Unsigned agent cards | medium | `unsigned-cards` | MCP09, ASI09 |
| Unpinned packages + shell access | critical | `unpinned-shell` | MCP01, MCP09, ASI06, ASI09 |
| Chokepoint servers | medium | `chokepoint-servers` | MCP01, ASI06 |
| Chokepoint tools | medium | `chokepoint-tools` | MCP01, ASI06 |

---

## Tool poisoning (MCP05)

**What:** MCP tool descriptions contain prompt injection patterns that manipulate agent behavior.

**How detected:** The MCP Collector scans tool descriptions for injection markers (imperative instructions, base64 blobs, hidden Unicode, references to ignoring safety instructions). Detected tools get a `POISONED_DESCRIPTION` self-edge.

**Risk:** A poisoned tool can cause an agent to execute unintended actions, leak data, or bypass safety controls when the agent reads the tool description during planning.

**Example finding:**
```
MCPTool:dangerous-tool has injection pattern: "ignore all previous instructions"
```

## Tool shadowing (MCP05)

**What:** A tool on one server mimics or references a tool on another server, potentially hijacking agent actions.

**How detected:** The SHADOWS post-processor compares tool descriptions across servers. When a tool on server B references server A's tool by name or has a suspiciously similar description, a `SHADOWS` edge is created.

**Risk:** An attacker controlling a low-trust server can shadow a legitimate tool. When an agent calls the shadowed tool, the malicious server handles the request instead.

## Rug pull detection (MCP05, MCP09)

**What:** A tool's description changes between scans, potentially indicating a supply chain attack.

**How detected:** Each tool gets a `description_hash` (SHA-256 of canonical description). On re-scan, the ingest pipeline compares hashes. The `rug-pull` pre-built query finds tools where `description_hash != previous_description_hash`.

**Risk:** An attacker who gains control of an MCP server package can change tool descriptions to include injection patterns after the initial trust decision was made.

## Unauthenticated servers (MCP03)

**What:** MCP servers with no authentication configured, meaning any client can connect and use all tools.

**How detected:** The Config Collector parses auth configuration for each server. Servers with `auth_method: none` or missing auth configuration are flagged via the `no-auth-servers` query.

**Risk:** No authentication means no access control. Any process on the same machine (stdio) or network (HTTP) can invoke all tools and access all resources.

## Instruction file poisoning (MCP05, ASI03)

**What:** Agent instruction files (`.claude/CLAUDE.md`, `.cursorrules`, `agents.md`, etc.) contain suspicious patterns.

**How detected:** The Config Collector scans instruction files for imperative overrides ("you must", "ignore previous"), exfiltration commands (curl/wget to external URLs), hidden Unicode (zero-width characters, RTL overrides), and encoded payloads. Flagged files get a `POISONED_INSTRUCTIONS` self-edge.

**Risk:** Poisoned instructions can override agent safety behavior, cause data exfiltration, or grant unauthorized access.

## Hardcoded secrets (MCP03, ASI04)

**What:** High-entropy strings in MCP server configuration that are likely hardcoded API keys or secrets.

**How detected:** The Config Collector measures Shannon entropy of credential values. Base64 strings with entropy > 4.5 and hex strings with entropy > 3.0 are flagged as `high_entropy`.

**Risk:** Secrets in config files end up in version control, backups, and logs. Rotation is difficult because the secret is embedded in client configurations across machines.

## Shell access paths (MCP01)

**What:** An agent can reach tools with shell execution or code execution capabilities.

**How detected:** The CAN_EXECUTE post-processor identifies tools with `shell_access` or `code_execution` in their `capability_surface`. The `agents-shell-access` query traces paths from agents through trust relationships to these tools.

**Risk:** Shell access from an agent means arbitrary command execution on the server host. Combined with no-auth or weak-auth servers, this is a critical RCE vector.

## Data exfiltration routes (MCP04, ASI08)

**What:** An agent can reach sensitive data (databases, credentials, files) AND has an outbound channel (network_outbound, email_send).

**How detected:** The CAN_EXFILTRATE_VIA post-processor combines CAN_REACH edges to sensitive resources with tools that have outbound capability. The pre-built query surfaces complete exfiltration paths.

**Risk:** This is the complete attack chain: access sensitive data, then send it somewhere. Two capabilities that are safe independently become critical when combined.

## Cross-protocol attack paths (MCP01, ASI01)

**What:** An A2A agent can reach MCP resources by traversing the A2A-MCP protocol boundary.

**How detected:** The cross-protocol post-processor correlates A2A agents with MCP servers running on the same host. When an A2A agent delegates to another agent that shares a host with an MCP server, a cross-protocol `CAN_REACH` edge is created from the A2A agent to MCP resources.

**Risk:** Cross-protocol paths are invisible to single-protocol analysis tools. An attacker exploiting an A2A agent can pivot through host co-location to access MCP resources that were never explicitly trusted by any A2A agent.

## Credential chain paths (MCP03, ASI04)

**What:** Multi-hop paths from agents to resources that traverse credential boundaries.

**How detected:** The `credential-chain` pre-built query traces paths up to 6 hops that pass through Identity and Credential nodes, identifying where credential reuse or sharing creates transitive access.

**Risk:** Shared credentials between services create implicit trust relationships. Compromising one credential grants access to all services that share it.

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
