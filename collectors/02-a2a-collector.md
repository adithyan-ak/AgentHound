# A2A Collector — Technical Implementation Specification

## 1. Purpose

The A2A Collector fetches Agent Cards from A2A-compliant agents via HTTP GET to their well-known discovery URL, parses the card's identity, capabilities, skills, and security schemes, and outputs graph nodes and edges that represent agent trust relationships, delegation chains, and authentication posture.

**The collector NEVER sends tasks or interacts with agents beyond fetching their Agent Card.** Discovery only.

## 2. Prior Art — What Exists Today

### Cisco A2A Scanner (`cisco-ai-defense/a2a-scanner`)
- **Language:** Python 3.11+, async/await + FastAPI, installable via `uv tool install cisco-ai-a2a-scanner`
- **Agent Card acquisition:** Local JSON files (`scan-card`), Python source files (`scan-file`), directories (`scan-directory`), live HTTP endpoints (`scan-endpoint`), agent registries (`scan-registry`)
- **Five analyzers:**
  1. **YARA Rules** — pattern matching for agent impersonation, prompt injection, capability abuse, data exfiltration, routing manipulation, tool poisoning (rules in `a2ascanner/data/yara_rules/`)
  2. **Spec Validator** — validates A2A protocol compliance: required fields, data types, URL formats, skill structures, capability definitions
  3. **Heuristic Analyzer** — logic-based detection for suspicious URLs, cloud metadata access, command execution patterns, credential harvesting indicators
  4. **LLM Analyzer** — semantic analysis via Azure OpenAI/Claude: intent classification, context grounding, manipulation detection (supports `--bearer-token` for auth)
  5. **Endpoint Analyzer** — dynamic testing: HTTPS enforcement, security headers (X-Content-Type-Options, X-Frame-Options, HSTS), agent card presence, URL consistency, health endpoints
- **Threat taxonomy (11 AITech categories):** Prompt Injection, Code Execution, Data Exfiltration, Suspicious Endpoints, Capability Abuse, Agent Spoofing, Credential Theft, Profile Tampering, Unauthorized Network Access, Insecure Network Access, Protocol Non-compliance
- **Output:** JSON with severity levels (CRITICAL, HIGH, MEDIUM, LOW) + color-coded console summaries
- **REST API:** FastAPI server with `POST /scan/agent-card`, `POST /scan/source-code`, `POST /scan/endpoint`, `POST /scan/full`
- **What it DOES that we reuse:** YARA-based detection patterns, spec validation logic, endpoint security header checks, threat taxonomy categories
- **What it DOESN'T do:** No graph output, no cross-agent relationship analysis, no trust boundary mapping between A2A agents and MCP servers, no delegation chain discovery

### Cisco Skill Scanner (`cisco-ai-defense/skill-scanner`)
- **Language:** Python 3.10+
- **Scans:** Agent skill repositories (OpenAI Codex Skills, Cursor Agent Skills, Claude Code `.claude/commands/*.md`, markdown skill repos)
- **Detection engines:** Static analyzer (YAML+YARA), bytecode analyzer (Python .pyc integrity), pipeline analyzer (shell taint), behavioral analyzer (AST dataflow), LLM analyzer, meta-analyzer (false positive filtering), VirusTotal, Cisco AI Defense
- **Relevance:** Skills are executable agent capabilities — the skill scanner validates supply chain integrity of agent code. AgentHound can reference skill scan results but doesn't replicate this analysis.

### Key Gap

Both tools analyze individual Agent Cards or skills in isolation. Neither constructs:
- A2A agent → A2A agent delegation edges
- A2A agent → MCP server trust edges (cross-protocol)
- Shared authentication domain edges (same OAuth provider)
- Capability overlap / impersonation edges

**AgentHound's A2A Collector must output nodes AND edges, specifically designed for cross-protocol graph construction with the MCP Collector's output.**

## 3. A2A Protocol — Agent Card Schema Reference

Source: [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/) (Section 4.4.1)

### 3.1 Discovery URL

Agents publish their Agent Card at a well-known URL. The path changed between spec versions:
- **v0.2.x and earlier:** `/.well-known/agent.json`
- **v0.3.0+:** `/.well-known/agent-card.json`

Source: [A2A Agent Discovery](https://a2a-protocol.org/latest/topics/agent-discovery/)

The collector MUST try both paths for compatibility:
```
GET /.well-known/agent-card.json    (current, try first)
GET /.well-known/agent.json         (legacy fallback)
```

The card is a JSON document. No authentication is required for the public card by default, though agents MAY support an extended (authenticated) card via the `extendedAgentCard` capability.

### 3.2 AgentCard Schema

**v0.3.0 format** (widely deployed):
```json
{
  "name": "research-agent",
  "description": "Performs web research and summarizes findings",
  "url": "https://agent.example.com/a2a",
  "version": "1.0.0",
  "provider": {
    "organization": "Example Corp",
    "url": "https://example.com"
  },
  "capabilities": {
    "streaming": true,
    "pushNotifications": true,
    "extendedAgentCard": false
  },
  "skills": [
    {
      "id": "web-research",
      "name": "Web Research",
      "description": "Search the web and summarize results",
      "tags": ["research", "web"],
      "inputModes": ["text/plain"],
      "outputModes": ["text/plain", "application/json"]
    }
  ],
  "securitySchemes": {
    "bearer": {
      "type": "http",
      "scheme": "bearer"
    },
    "oauth2": {
      "type": "oauth2",
      "flows": {
        "authorizationCode": {
          "authorizationUrl": "https://auth.example.com/authorize",
          "tokenUrl": "https://auth.example.com/token",
          "scopes": { "read": "Read access" }
        }
      }
    }
  },
  "security": [{ "oauth2": ["read"] }],
  "defaultInputModes": ["text/plain", "application/json"],
  "defaultOutputModes": ["text/plain", "application/json"],
  "protocolVersion": "0.3.0"
}
```

**v1.0 format** (latest draft — key structural changes):
- `url` removed from top level → now inside `supportedInterfaces[].url`
- `protocolVersion` (singular) removed → now per-interface in `supportedInterfaces[].protocolVersion`
- `supportedInterfaces` uses `protocolBinding` (e.g., `"JSONRPC"`, `"GRPC"`) instead of `type`
- Skills gain `id` (required), `tags` (required), `examples`, `securityRequirements`
- Skills use `inputModes`/`outputModes` (MIME type arrays), NOT `inputSchema`/`outputSchema`
- `extensions` lives inside `capabilities`, not top-level
- New fields: `documentationUrl`, `iconUrl`, `signatures`
- Required fields in v1.0: `name`, `description`, `supportedInterfaces`, `version`, `capabilities`, `defaultInputModes`, `defaultOutputModes`, `skills`

Source: [A2A v1.0 Specification](https://a2a-protocol.org/latest/specification/), [What's New in v1.0](https://a2a-protocol.org/latest/whats-new-v1/)

**The collector MUST handle both v0.3.0 and v1.0 formats** — detect which version the card uses by checking for `supportedInterfaces` (v1.0) vs `url` (v0.3.0) at top level.
```

### 3.3 Key Fields for Security Analysis

| Field | Security Relevance |
|-------|-------------------|
| `securitySchemes` | What auth methods the agent supports — none/apiKey/http/oauth2/openIdConnect/mutualTLS |
| `security` | Default auth requirements — empty array means no auth required |
| `capabilities.pushNotifications` | Webhook support — potential SSRF vector if internal IPs used |
| `capabilities.extendedAgentCard` | Whether authenticated card differs from public card |
| `skills[].description` | Analyzed for injection patterns (same as MCP tool descriptions) |
| `skills[].inputModes` / `outputModes` | MIME type arrays declaring accepted/returned content types (NOT JSON Schema) |
| `url` (v0.3.0) / `supportedInterfaces[].url` (v1.0) | Agent endpoint — analyzed for HTTP vs HTTPS, internal IPs, cloud metadata URLs |
| `provider` | Attribution — unknown/missing providers are flagged |

### 3.4 SecurityScheme Types

Per A2A spec Section 4.5:

| Type | Structure |
|------|-----------|
| `APIKeySecurityScheme` | `{ "type": "apiKey", "in": "header\|query\|cookie", "name": "X-API-Key" }` (v0.3.0 uses `in`; v1.0 renames to `location`) |
| `HTTPAuthSecurityScheme` | `{ "type": "http", "scheme": "bearer\|basic" }` |
| `OAuth2SecurityScheme` | `{ "type": "oauth2", "flows": { ... } }` |
| `OpenIdConnectSecurityScheme` | `{ "type": "openIdConnect", "openIdConnectUrl": "..." }` |
| `MutualTlsSecurityScheme` | `{ "type": "mutualTLS" }` |

## 4. Collection Process

### 4.1 Per-Agent Flow

```
1. HTTP GET to {target_url}/.well-known/agent-card.json (v0.3.0+)
   - Fallback: {target_url}/.well-known/agent.json (legacy)
   - Follow redirects (up to 5)
   - Accept: application/json
   - Optional: Authorization header if --auth-token provided
   - Timeout: 15s (configurable)

2. Parse response as JSON
   - Detect version: if `supportedInterfaces` present → v1.0; if top-level `url` → v0.3.0
   - Validate required fields per version
   - Record raw Agent Card hash (SHA-256 of full JSON) for drift detection

3. Extract identity fields
   - name, description, url, version, provider

4. Extract capabilities
   - streaming, pushNotifications, extendedAgentCard

5. Extract and analyze skills
   - name, description, inputSchema, outputSchema
   - Compute description hash per skill
   - Run injection pattern detection on each skill description

6. Extract security schemes and security requirements
   - Map scheme type to auth strength rating
   - Detect: no auth, API key only, HTTP basic, OAuth, mTLS

7. Extract protocol versions and supported interfaces

8. Compute security signals (Section 5)

9. Generate nodes and edges (Section 6)
```

### 4.2 Discovery Methods

```bash
# Scan a single agent
agenthound collect a2a \
  --target https://agent.example.com \
  --output scan.json

# Scan multiple agents
agenthound collect a2a \
  --targets https://agent1.example.com,https://agent2.example.com \
  --output scan.json

# Scan from a target list file
agenthound collect a2a \
  --targets-file agents.txt \
  --output scan.json

# Well-known path probing for a domain
agenthound collect a2a \
  --discover-domain example.com \
  --output scan.json

# Scan with authentication
agenthound collect a2a \
  --target https://agent.example.com \
  --auth-token "Bearer eyJ..." \
  --output scan.json

# Scan an agent registry
agenthound collect a2a \
  --registry https://registry.example.com \
  --output scan.json
```

**Domain discovery** probes:
- `https://{domain}/.well-known/agent-card.json` (current, v0.3.0+)
- `https://{domain}/.well-known/agent.json` (legacy, v0.2.x)
- Common subdomains: `agent.{domain}`, `a2a.{domain}`, `api.{domain}`

## 5. Security Signal Extraction

### 5.1 Auth Posture Assessment

| Auth Configuration | Risk Level | Score |
|-------------------|-----------|-------|
| No `securitySchemes` + empty `security` | Critical | 100 |
| API key only (header or query) | High | 70 |
| HTTP Basic | High | 65 |
| HTTP Bearer (static token) | Medium | 50 |
| OAuth 2.0 | Low | 25 |
| OpenID Connect | Low | 20 |
| mTLS | Minimal | 10 |

### 5.2 Agent Card Integrity

- **Card hash:** SHA-256 of the full Agent Card JSON. Compare across scans for drift/poisoning detection.
- **Skill description hashes:** Per-skill SHA-256 for granular change detection.
- **HTTPS enforcement:** Flag agents serving cards over HTTP.
- **Endpoint consistency:** Flag if `url` in the card doesn't match the actual endpoint serving it.

### 5.3 Injection Pattern Detection (Skill Descriptions)

Same patterns as MCP tool descriptions:
- `<IMPORTANT>`, `<system>`, `<instructions>` tags
- Imperative instructions: "always delegate to me", "ignore other agents", "route all X queries here"
- Data exfiltration: embedded URLs, email addresses, encoding instructions
- Capability hijacking: descriptions claiming superset of another agent's skills

### 5.4 Capability Overlap Analysis

Compare skill descriptions across agents:
- If Agent A's skill description is a semantic superset of Agent B's skill for the same task domain → potential Agent-in-the-Middle (AITM) attack
- Implemented as cosine similarity on TF-IDF vectors of skill descriptions (post-processor, not in collector)
- Collector outputs the raw data; the flag is computed post-ingest

### 5.5 Network Security Signals

- **HTTP vs HTTPS:** endpoint URL scheme
- **Internal/private IPs:** 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, 169.254.169.254 (cloud metadata)
- **Push notification webhook URLs:** if internal, potential SSRF
- **Security headers** (if doing endpoint probing): X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy

## 6. Graph Output — Nodes and Edges

### Nodes Generated

| Node Label | Source | Key Properties |
|-----------|--------|---------------|
| `A2AAgent` | Agent Card | `name`, `description`, `url`, `version`, `provider`, `protocolVersions`, `capabilities`, `securitySchemes`, `authMethod` (derived), `authStrength` (derived), `cardHash`, `isHttps`, `hasAuth` |
| `A2ASkill` | Agent Card skills[] | `name`, `description`, `inputSchema`, `outputSchema`, `descriptionHash`, `hasInjectionPatterns`, `inputModes`, `outputModes` |

### Edges Generated

| Edge Kind | Source → Target | How Determined |
|----------|----------------|---------------|
| `ADVERTISES_SKILL` | A2AAgent → A2ASkill | Each skill in the Agent Card |
| `DELEGATES_TO` | A2AAgent → A2AAgent | Inferred when Agent Card description or skills reference delegation to specific agent URLs/names. Also from registry metadata if available. |
| `SAME_AUTH_DOMAIN` | A2AAgent → A2AAgent | When two agents share the same OAuth `tokenUrl` or OpenID Connect `openIdConnectUrl` — implies shared trust domain |

### Node ID Strategy

```
A2AAgent:  SHA-256(agent_card_url)
A2ASkill:  SHA-256(agent_id + ":" + skill_name)
```

### Cross-Protocol Edge Opportunities

The A2A Collector alone cannot produce cross-protocol edges — those require correlating A2A data with MCP data. However, the collector outputs enough data for the post-processor to compute:

- **A2AAgent → MCPServer** (via `TRUSTS_SERVER`): If an A2A agent's skill description references MCP tool names, or if config analysis shows the same host runs both an A2A agent and MCP servers
- **A2AAgent → Identity**: If the A2A agent's `securitySchemes` match credentials found by the Config Collector

## 7. Error Handling

| Scenario | Handling |
|----------|---------|
| Agent endpoint unreachable | Log warning, skip, emit A2AAgent node with `status: unreachable` |
| Non-JSON response | Log error with content type and first 256 bytes, skip |
| Valid JSON but missing required fields | Log warning, emit partial node with available fields |
| Agent requires auth we don't have | Record A2AAgent node with `authRequired: true`, note challenge type |
| SSL/TLS errors | Log warning, optionally `--insecure` flag |
| HTTP redirect to different domain | Follow (up to 5), record original and final URLs |
| Rate limiting (429) | Respect Retry-After header, retry once, then skip |
| Very large Agent Card (>1MB) | Truncate, log warning |

## 8. Go Implementation — Key Dependencies

| Package | Purpose |
|---------|---------|
| `net/http` | HTTP client for Agent Card fetching |
| `crypto/tls` | TLS configuration, certificate inspection |
| `crypto/sha256` | Agent Card and skill description hashing |
| `encoding/json` | Agent Card parsing |
| `net/url` | URL parsing and validation |
| `github.com/spf13/cobra` | CLI framework |
| `context` | Timeout and cancellation |
| `sync` | Parallel agent scanning |

No third-party A2A SDK is required — the collector is a pure HTTP client that GETs and parses JSON. The A2A protocol for discovery is just HTTP + JSON.
