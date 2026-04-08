# Config Collector — Technical Implementation Specification

## 1. Purpose

The Config Collector parses MCP client configuration files from the local filesystem, extracting server definitions, credential references, transport configurations, and host bindings. It produces the **trust relationship edges** that connect AgentInstance nodes to MCPServer nodes — the `TRUSTS_SERVER` edges that are foundational to every attack path in the graph.

Without the Config Collector, the MCP Collector knows what each server exposes, but not **which agents trust which servers**. The Config Collector provides this binding.

## 2. Prior Art — What Exists Today

### Config Discovery in Existing Tools

Both Cisco MCP Scanner and Snyk agent-scan implement config file discovery, but only to find servers to scan — they don't model the trust relationship between client and server as a graph edge.

**Cisco MCP Scanner** (`known-configs` subcommand):
- Discovers configs at well-known paths for Windsurf, Cursor, Claude Desktop, VS Code
- Parses `mcpServers` / `servers` objects to extract command, args, env, URL
- Uses the parsed configs to connect to servers for scanning
- Does NOT output the config→server binding as structured data

**Snyk agent-scan** (auto-discovery):
- Broadest discovery: Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Gemini CLI, OpenClaw, Kiro, Antigravity, Codex, Amazon Q
- Platform-aware (macOS, Linux, Windows paths)
- Parses configs to establish stdio connections
- Stores scan state in `~/.mcp-scan`
- Does NOT output trust relationships

### Key Gap

Both tools use config files as **input** (to find servers to scan). AgentHound uses config files as **data** (to model trust relationships).

The Config Collector outputs:
- `ConfigFile` nodes (representing each config file found)
- `AgentInstance` nodes (representing each MCP client/agent)
- `MCPServer` nodes (with transport details, matching MCP Collector output via deterministic IDs)
- `Identity` nodes (auth methods per server)
- `Credential` nodes (env vars, tokens, API keys)
- `Host` nodes (where servers run)
- Trust edges: `TRUSTS_SERVER`, `CONFIGURED_IN`, `AUTHENTICATES_WITH`, `USES_CREDENTIAL`, `RUNS_ON`, `HAS_ENV_VAR`

## 3. Supported Configuration Formats

### 3.1 Claude Desktop

**Paths:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Format:**
```json
{
  "mcpServers": {
    "postgres-mcp": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": {
        "POSTGRES_URL": "postgresql://user:pass@localhost:5432/mydb"
      }
    },
    "remote-server": {
      "url": "https://mcp.example.com/sse",
      "headers": {
        "Authorization": "Bearer sk-abc123..."
      }
    }
  }
}
```

**Key:** `mcpServers` (object, not array). Each key is the server name. Values contain either `command`+`args`+`env` (stdio) or `url`+`headers` (HTTP/SSE).

### 3.2 Claude Code

**Project-level:** `.mcp.json` in project root

**User-level:** `~/.claude.json`

**Format (project-level `.mcp.json`):**
```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_xxxxxxxxxxxx"
      }
    }
  }
}
```

Claude Code also supports adding servers via CLI: `claude mcp add <name> --transport stdio|http|sse -- <command> [args]`

### 3.3 Cursor

**Paths:**
- Global: `~/.cursor/mcp.json`
- Project-scoped: `.cursor/mcp.json` in project root

**Format:**
```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "@some/mcp-server"],
      "env": {
        "API_KEY": "sk-..."
      }
    }
  }
}
```

Same `mcpServers` schema as Claude Desktop.

### 3.4 VS Code

**Paths:**
- Workspace: `.vscode/mcp.json`
- User: Via "MCP: Open User Configuration" command (stored in VS Code settings)

**Format — IMPORTANT: uses `servers` key, NOT `mcpServers`:**
```json
{
  "servers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "@microsoft/mcp-server-playwright"]
    },
    "remote-server": {
      "type": "http",
      "url": "https://api.example.com/mcp"
    }
  }
}
```

**Key difference:** VS Code uses `"servers"` instead of `"mcpServers"`. Also supports `"type": "http"` for HTTP servers and `"sandboxEnabled"` for sandboxing.

### 3.5 Windsurf / Codeium

**Paths:**
- macOS: `~/.codeium/windsurf/mcp_config.json`
- Linux: `~/.codeium/windsurf/mcp_config.json`
- Windows: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`

**Format:**
```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "some-mcp-server"],
      "env": { "API_KEY": "value" }
    },
    "sse-server": {
      "serverUrl": "http://localhost:3001/sse"
    }
  }
}
```

**Key difference:** Windsurf uses `"serverUrl"` (not `"url"`) for remote/SSE servers. Some versions also support `"transportType": "sse"` as an explicit discriminator.

### 3.6 Continue

**Path:** `~/.continue/config.yaml` (current) — `config.json` is deprecated.

Source: [Continue YAML Migration](https://docs.continue.dev/reference/yaml-migration)

**Format (config.yaml) — mcpServers block:**
```yaml
mcpServers:
  - name: github
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-github"
    env:
      GITHUB_TOKEN: "..."
```

Also supports workspace-based config via `.continue/mcpServers/*.yaml` directory with individual YAML files per server.

### 3.7 Zed

**Paths:**
- macOS/Linux: `~/.config/zed/settings.json`
- Project-level: `.zed/settings.json`

**Format — uses `context_servers` key with flattened command/args:**
```json
{
  "context_servers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "some-mcp-server"],
      "env": { "API_KEY": "value" }
    }
  }
}
```

Source: [Zed MCP Docs](https://zed.dev/docs/ai/mcp), [PR #33539](https://github.com/zed-industries/zed/pull/33539)

**Key difference:** Uses `context_servers` key (not `mcpServers`). As of 2025, Zed standardized to the flattened `command`/`args`/`env` format matching other editors. The older nested `command.path` format is legacy. Also supports remote servers via `url` and `headers`.

### 3.8 Cline (VS Code Extension)

**Paths:**
- macOS: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- Linux: `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- Windows: `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

**Format:**
```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "some-mcp-server"],
      "env": {},
      "disabled": false,
      "autoApprove": ["tool1", "tool2"]
    }
  }
}
```

**Key difference:** Cline-specific fields `disabled` (boolean) and `autoApprove` (array of tool names that skip confirmation — also referred to as "Always Allow" in the UI). The `autoApprove` field is security-relevant — auto-approved tools bypass the human-in-the-loop safeguard.

Source: [Cline Auto Approve Docs](https://docs.cline.bot/features/auto-approve)

### 3.9 JetBrains IDEs (IntelliJ, WebStorm, PyCharm)

**Paths:**
- Project-level: `.junie/mcp/mcp.json` in project root
- User-level: `~/.junie/mcp/mcp.json`

Source: [Junie MCP Settings](https://www.jetbrains.com/help/junie/mcp-settings.html)

**Format:** Same `mcpServers` schema as Claude Desktop. Available in JetBrains 2025.1+ via the Junie plugin.

### 3.10 Other Clients (Discovery)

| Client | Config Path | Format | Source |
|--------|-----------|--------|--------|
| Amazon Q CLI | `~/.aws/amazonq/mcp.json` (global), `.amazonq/mcp.json` (workspace) | Standard `mcpServers` object | [AWS Docs](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line-mcp-configuration.html) |
| Amazon Q IDE | `~/.aws/amazonq/agents/default.json` | `mcpServers` object | [GitHub Issue](https://github.com/aws/aws-toolkit-vscode/issues/7938) |
| Kiro | `.kiro/settings/mcp.json` (workspace), `~/.kiro/settings/mcp.json` (user) | Standard `mcpServers` object | [Kiro Docs](https://kiro.dev/docs/mcp/configuration/) |
| Augment Code | VS Code `settings.json` under `augment.advanced.mcpServers` | Both object and array formats reported | — |
| Gemini CLI | `~/.gemini/settings.json` | TBD — needs verification | — |
| OpenClaw | Platform-specific | TBD | — |

The collector should be designed with a pluggable parser architecture — one parser per client format, registered with the discovery engine.

### 3.11 Agent Instruction Files (Behavior Poisoning Surface)

The Config Collector also discovers agent instruction/behavior files that are loaded into agent context at session start. These files are analogous to tool descriptions — they contain directives that the agent treats as authoritative instructions, making them a poisoning vector.

**Discovered files:**

| File | Convention | Used By | Security Relevance |
|------|-----------|---------|-------------------|
| `AGENTS.md` | Open standard (agents.md) | Google Gemini/Android Studio, community tools | Agent behavior instructions; can contain malicious directives |
| `CLAUDE.md` | Anthropic convention | Claude Code | Loaded into system prompt; CVE-2025-59536 (CVSS 8.7) demonstrated RCE via poisoned project files |
| `MEMORY.md` | Anthropic convention | Claude Code | Persistent memory loaded into system prompt; Cisco research demonstrated behavioral manipulation via npm postinstall poisoning |
| `.cursorrules` | Cursor convention | Cursor | Project-level agent instructions; Pillar Security "Rules File Backdoor" attack uses hidden Unicode |
| `.copilot-instructions.md` | GitHub convention | GitHub Copilot | Copilot behavioral instructions; same Rules File Backdoor attack class |
| `.github/copilot-instructions.md` | GitHub convention | GitHub Copilot | Repository-level Copilot instructions |
| `.continue/config.yaml` | Continue convention | Continue | Already parsed for MCP servers; instruction blocks also relevant |

**Discovery paths:**
- Project root: `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.copilot-instructions.md`
- User-level: `~/.claude/CLAUDE.md`, `~/.claude/projects/*/memory/MEMORY.md`
- Repository: `.github/copilot-instructions.md`

**Analysis:**
- SHA-256 hash of file content for drift detection across scans
- Pattern matching for suspicious directives: imperative overrides ("always", "never", "ignore previous"), exfiltration commands (`curl`, `wget`, encoded URLs), hidden content (zero-width Unicode, excessive whitespace)
- File produces an `InstructionFile` node with `LOADS_INSTRUCTIONS` edge to the `AgentInstance`

**Grounding research:**
- CVE-2025-59536 (CVSS 8.7): RCE via `.claude/settings.json` hooks (Check Point Research)
- CVE-2026-21852 (CVSS 5.3): API key exfiltration via `ANTHROPIC_BASE_URL` override
- Cisco AI Security: MEMORY.md poisoning via npm postinstall hooks
- Adversa AI: CLAUDE.md deny-rule bypass via 50-subcommand threshold
- Pillar Security: Rules File Backdoor with hidden Unicode in `.cursorrules`
- NVIDIA (Jan 2026): Explicitly names CLAUDE.md as an attack surface
- arXiv:2604.03081: Supply-chain poisoning of LLM coding agent skill ecosystems
- arXiv:2509.22040: Prompt injection via external development resources

## 4. Data Extraction Per Config File

For each config file discovered, extract:

### 4.1 Server Definitions

Per server entry in the config:

| Field | Source | Graph Usage |
|-------|--------|------------|
| Server name | Config key (e.g., `"postgres-mcp"`) | MCPServer node `name` property |
| Transport type | Presence of `command` (stdio) vs `url` (HTTP) | MCPServer `transport` property |
| Command | `command` field | MCPServer `endpoint` property (for stdio) |
| Arguments | `args` array | MCPServer property, also used for ID computation |
| Environment variables | `env` object | Credential extraction, HAS_ENV_VAR edges |
| URL | `url` field | MCPServer `endpoint` property (for HTTP) |
| Headers | `headers` object | Identity/Credential extraction |

### 4.2 Unpinned Package Detection

For stdio MCP servers using `npx`, `uvx`, or similar package runners, detect whether the package version is pinned:

| Pattern | Classification | Risk |
|---------|---------------|------|
| `npx -y @pkg` or `npx -y @scope/pkg` | Unpinned (pulls `@latest` every execution) | High |
| `npx @pkg@1.2.3` or `npx -y @scope/pkg@^1.0.0` | Pinned (version constraint) | Low |
| `uvx some-pkg` | Unpinned (pulls latest from PyPI) | High |
| `uvx some-pkg==1.2.3` | Pinned | Low |

Unpinned packages are the #1 MCP supply chain vector. Every execution fetches the latest version from the registry — if the package is compromised (typosquatting, maintainer account takeover, dependency confusion), the malicious version runs with full host access.

**Grounding:**
- Docker "MCP Horror Stories" (Aug 2025): `npx -y @untrusted/mcp-server` executes arbitrary code with full host access
- postmark-mcp incident (Sep 2025): Cloned npm package trusted for 15 versions, then v1.0.16 silently exfiltrated emails
- JFrog "Supply Chain Attackers Are Coming for Your Agents" (Mar 2026): LiteLLM attack exploited unpinned dependencies
- CVE-2025-6514 (CVSS 9.6): RCE in mcp-remote affecting 437,000+ environments (JFrog Security Research)
- Stacklok (Jan 2026): Explicit recommendation to "pin package versions instead of defaulting to `@latest`"

The Config Collector sets `isPinned: false` on MCPServer nodes when the version is not pinned, and the post-processor generates an `UNPINNED_PACKAGE` finding.

### 4.3 Credential Extraction

Scan `env` values and `headers` values for credential patterns:

| Pattern | Credential Type | Examples |
|---------|---------------|----------|
| Variable name contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `CREDENTIAL`, `AUTH` | API key / token | `POSTGRES_API_KEY`, `GITHUB_PERSONAL_ACCESS_TOKEN` |
| Value starts with `sk-`, `xoxb-`, `xoxp-`, `ghp_`, `gho_`, `Bearer ` | Known token format | Slack tokens, GitHub PATs, OpenAI keys |
| Value references env var (`${env:VAR}`, `$VAR`) | Environment reference | Not directly exposed but references external credential |
| Value is a connection string with embedded credentials | Database credential | `postgresql://user:pass@host/db` |
| Value matches `${input:...}` | User-prompted input | Claude Code input variables — not static credentials |
| Value has high Shannon entropy (>4.5 base64, >3.0 hex) | Probable secret (entropy-based) | Catches secrets with non-standard env var names |

**Entropy-based secret detection** supplements pattern matching by computing Shannon entropy of env var values. This catches secrets even when variable names are obfuscated or non-standard (e.g., `DATA_SOURCE=sk-proj-abc123...` where the name doesn't match credential patterns). Implementation follows the approach used by detect-secrets (`HighEntropyStringsPlugin`), TruffleHog, and Gitleaks. Thresholds: >4.5 bits/char for base64 charset, >3.0 bits/char for hex charset. See: Trend Micro finding that 48% of MCP servers store credentials in plaintext config.

**Security classification of credential storage:**

| Storage Method | Risk Level | Score |
|---------------|-----------|-------|
| Hardcoded in config JSON | Critical | 100 |
| High-entropy value (detected by entropy analysis) | Critical | 90 |
| Environment variable reference (`${env:VAR}`) | Medium | 50 |
| User input prompt (`${input:...}`) | Low | 20 |
| Vault reference | Minimal | 10 |

### 4.4 Host Binding Analysis

For stdio servers:
- Command is local executable → Host: localhost
- If command includes SSH or remote execution → extract remote host

For HTTP servers:
- Parse URL → extract hostname/IP
- `localhost` / `127.0.0.1` → local
- `0.0.0.0` → all interfaces (higher exposure)
- Private IPs → internal network
- Public IPs / DNS names → external (highest exposure)

## 5. Graph Output — Nodes and Edges

### Nodes Generated

| Node Label | Source | Key Properties |
|-----------|--------|---------------|
| `ConfigFile` | Discovered config file | `path`, `client` (claude-desktop/cursor/vscode/windsurf/claude-code/continue), `serverCount`, `lastModified` |
| `AgentInstance` | Derived from config file (one per client) | `name` (client name), `framework`, `configPath` |
| `MCPServer` | Server entry in config | `name`, `transport`, `endpoint` (command or URL), `args`, `protocolVersion` (unknown until MCP Collector runs) |
| `Identity` | Auth config per server | `type` (none/apiKey/oauth/bearer/basic/mtls), `scope`, `isStatic` |
| `Credential` | Env var or header with credential pattern | `type` (envVar/hardcoded/vaultRef/inputPrompt), `name` (variable name), `source` (config path), `isExposed` (true if hardcoded), `format` (if detectable: slack/github/openai/etc) |
| `Host` | Derived from server endpoint | `hostname`, `ip` (if resolvable), `isLocal`, `isPrivate`, `isPublic` |
| `InstructionFile` | Discovered instruction file | `path`, `type` (agents.md/claude.md/cursorrules/copilot-instructions/memory.md), `hash` (SHA-256), `isSuspicious` (boolean, pattern match result) |

### Edges Generated

| Edge Kind | Source → Target | How Determined |
|----------|----------------|---------------|
| `TRUSTS_SERVER` | AgentInstance → MCPServer | Each server in the config is trusted by the agent that loads that config |
| `CONFIGURED_IN` | MCPServer → ConfigFile | Server is defined in this config file |
| `AUTHENTICATES_WITH` | MCPServer → Identity | Server has auth configured (derived from env vars, headers, URL credentials) |
| `USES_CREDENTIAL` | Identity → Credential | Identity is backed by this specific credential |
| `RUNS_ON` | MCPServer → Host | Server process runs on this host (localhost for stdio, parsed from URL for HTTP) |
| `HAS_ENV_VAR` | MCPServer → Credential | Server config includes this environment variable (all env vars, not just credentials) |
| `LOADS_INSTRUCTIONS` | AgentInstance → InstructionFile | Agent loads this instruction file at session start (e.g., Claude Code loads `CLAUDE.md`) |

### Node ID Strategy

IDs must be deterministic and match across collectors:

```
ConfigFile:    SHA-256(absolute_path)
AgentInstance: SHA-256(config_file_id + ":" + client_name)
MCPServer:     SHA-256(transport + ":" + endpoint_or_command + ":" + sorted_args_hash)
               ← MUST match the MCP Collector's ID for the same server
Identity:      SHA-256(type + ":" + scope + ":" + source_hash)
Credential:    SHA-256(type + ":" + name + ":" + config_file_path)
Host:          SHA-256(hostname_or_ip)
```

**Critical:** The MCPServer ID from the Config Collector MUST match the MCPServer ID from the MCP Collector for the same server. This is what allows the graph engine to merge data from both collectors — the Config Collector provides trust edges (which agent trusts this server), and the MCP Collector provides capability edges (what this server exposes).

The matching key is: `SHA-256(transport + ":" + endpoint_or_command + ":" + sorted_args_hash)`. Both collectors compute this the same way:
- For stdio: transport="stdio", endpoint=command, args=sorted args joined
- For HTTP: transport="http", endpoint=URL

## 6. The Trust Boundary Problem

This is what makes AgentHound unique. An example:

```
Config: ~/.claude/claude_desktop_config.json
  → Server: postgres-mcp (command: npx -y @modelcontextprotocol/server-postgres)
  → Server: slack-mcp (command: npx -y @modelcontextprotocol/server-slack)
  → Server: filesystem-mcp (command: npx -y @modelcontextprotocol/server-filesystem)
```

The Config Collector produces:

```
AgentInstance("claude-desktop") --TRUSTS_SERVER--> MCPServer("postgres-mcp")
AgentInstance("claude-desktop") --TRUSTS_SERVER--> MCPServer("slack-mcp")
AgentInstance("claude-desktop") --TRUSTS_SERVER--> MCPServer("filesystem-mcp")

MCPServer("postgres-mcp") --AUTHENTICATES_WITH--> Identity("static-key")
Identity("static-key") --USES_CREDENTIAL--> Credential("POSTGRES_URL" envVar, contains password)

MCPServer("postgres-mcp") --CONFIGURED_IN--> ConfigFile("~/.claude/claude_desktop_config.json")
MCPServer("slack-mcp") --CONFIGURED_IN--> ConfigFile("~/.claude/claude_desktop_config.json")
MCPServer("filesystem-mcp") --CONFIGURED_IN--> ConfigFile("~/.claude/claude_desktop_config.json")
```

The MCP Collector then adds:

```
MCPServer("postgres-mcp") --PROVIDES_TOOL--> MCPTool("execute_sql")
MCPTool("execute_sql") --HAS_ACCESS_TO--> MCPResource("production-db")  [post-processed]

MCPServer("slack-mcp") --PROVIDES_TOOL--> MCPTool("send_message")

MCPServer("filesystem-mcp") --PROVIDES_TOOL--> MCPTool("read_file")
MCPServer("filesystem-mcp") --PROVIDES_TOOL--> MCPTool("write_file")
```

The post-processor computes:

```
AgentInstance("claude-desktop") --CAN_REACH--> MCPResource("production-db")
  Path: claude-desktop → postgres-mcp → execute_sql → production-db (3 hops)

AgentInstance("claude-desktop") --CAN_EXFILTRATE_VIA--> MCPTool("send_message")
  Because: agent can reach production-db AND can reach send_message (outbound channel)
```

**This is the attack path that no individual MCP scanner can find** — it requires combining the trust bindings from config with the capability data from MCP enumeration.

## 7. Cross-Client Analysis

When the same MCP server appears in multiple client configs:

```
ConfigFile("~/.claude/claude_desktop_config.json")
  → MCPServer("postgres-mcp")  [same server ID]

ConfigFile("~/.cursor/mcp.json")
  → MCPServer("postgres-mcp")  [same server ID]
```

This means two different agents trust the same server. If that server is compromised, both agents are affected. The graph naturally represents this because both `TRUSTS_SERVER` edges point to the same MCPServer node.

**Shadow server detection:** A server in one config but not in an approved inventory is a "shadow server." The Config Collector doesn't define the inventory — it discovers all configs. The inventory is a post-processing concern.

## 8. CLI Interface

```bash
# Discover all known configs on this machine
agenthound collect config \
  --discover \
  --output scan.json

# Scan a specific config file
agenthound collect config \
  --path ~/.claude/claude_desktop_config.json \
  --output scan.json

# Scan multiple config files
agenthound collect config \
  --paths "~/.claude/claude_desktop_config.json,~/.cursor/mcp.json,.vscode/mcp.json" \
  --output scan.json

# Scan with credential redaction (default: credentials are SHA-256 hashed, not stored in cleartext)
agenthound collect config \
  --discover \
  --redact-credentials \
  --output scan.json
```

**Credential handling:** By default, the collector stores credential metadata (type, name, source) but NOT the actual credential values. Credential values are SHA-256 hashed for deduplication. The `--include-credential-values` flag can be used for authorized audits, but the default is safe.

## 9. Error Handling

| Scenario | Handling |
|----------|---------|
| Config file not found at expected path | Silent skip (normal — not all clients are installed) |
| Config file exists but is not valid JSON | Log error with path and parse error, skip |
| Config file exists but empty | Log info, skip |
| Config uses unknown schema (no mcpServers/servers key) | Log warning with actual keys found, skip |
| Env var in config references undefined variable | Record Credential with `isResolvable: false` |
| Permission denied reading config file | Log warning, skip |
| Connection string with embedded credentials | Extract credential, mark as `isExposed: true` |
| Very large config file (>10MB) | Log warning, process anyway (shouldn't happen in practice) |

## 10. Go Implementation — Key Dependencies

| Package | Purpose |
|---------|---------|
| `os` | File system access, environment variable resolution |
| `path/filepath` | Platform-aware path construction |
| `runtime` | OS detection for platform-specific paths |
| `encoding/json` | Config file parsing |
| `crypto/sha256` | Node ID computation, credential hashing |
| `regexp` | Credential pattern matching |
| `net/url` | URL parsing for HTTP server configs |
| `github.com/spf13/cobra` | CLI framework |

### Parser Architecture

```go
// Each client format has a parser
type ConfigParser interface {
    // ClientName returns the client identifier
    ClientName() string
    // ConfigPaths returns platform-specific config paths to check
    ConfigPaths() []string
    // Parse reads a config file and returns server definitions
    Parse(path string, data []byte) (*ConfigData, error)
}

// Implementations:
// - ClaudeDesktopParser (mcpServers object)
// - ClaudeCodeParser (mcpServers object, project + user level)
// - CursorParser (mcpServers object, supports "disabled" field)
// - VSCodeParser (servers object — different key!)
// - WindsurfParser (mcpServers object, uses "serverUrl" not "url")
// - ContinueParser (config.yaml with mcpServers list, or .continue/mcpServers/*.yaml)
// - ZedParser (context_servers key, flattened command/args/env)
// - ClineParser (mcpServers object, has "autoApprove" — security relevant!)
// - JetBrainsParser (.junie/mcp/mcp.json, standard mcpServers)
// - KiroParser (.kiro/settings/mcp.json, standard mcpServers)
// - AmazonQParser (~/.aws/amazonq/mcp.json, standard mcpServers)
// - AugmentCodeParser (VS Code settings, mcpServers as array with "name" field)
```

Adding support for a new MCP client = implementing one `ConfigParser`. The discovery engine iterates all registered parsers, checks their paths, and calls `Parse` on any files found.
