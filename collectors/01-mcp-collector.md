# MCP Collector — Technical Implementation Specification

## 1. Purpose

The MCP Collector enumerates MCP servers by establishing JSON-RPC 2.0 connections, performing the standard initialization handshake, and calling read-only enumeration endpoints (`tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`). It extracts all server metadata, tool definitions, resource descriptors, and prompt templates — plus security-relevant signals needed to construct trust graph edges.

**The collector NEVER calls `tools/call` or `resources/read`.** Enumeration only.

## 2. Prior Art — What Exists Today

### Cisco MCP Scanner (`cisco-ai-defense/mcp-scanner`)
- **Language:** Python 3.11+, installable via `uv tool install cisco-ai-mcp-scanner`
- **Connection methods:** stdio (subprocess), Streamable HTTP, SSE, OAuth-authenticated HTTP
- **Config discovery:** Reads well-known config paths for Windsurf, Cursor, Claude Desktop, VS Code
- **Enumeration:** Calls `initialize`, `tools/list`, `prompts/list`, `resources/list`, `resources/read`; extracts server `instructions` from `InitializeResult`
- **Analysis engines:** YARA pattern matching, LLM-as-judge (OpenAI/Bedrock/Azure/Ollama), Cisco AI Defense cloud API, VirusTotal hash lookup, behavioral code analyzer (AST-based dataflow for supply chain)
- **Output formats:** `summary`, `detailed`, `by_tool`, `table`, `raw` (JSON)
- **CLI subcommands:** `remote`, `stdio`, `config`, `known-configs`, `prompts`, `resources`, `instructions`, `virustotal`, `behavioral`, `static`
- **What it DOES that we reuse:** Multi-transport connection logic, config file discovery paths, YARA-based pattern detection concepts
- **What it DOESN'T do:** No graph output, no node/edge generation, no cross-server relationship analysis, no trust boundary mapping

### Snyk Agent Scan (`snyk/agent-scan`, formerly Invariant `mcp-scan`)
- **Language:** Python (90.1%), acquired from Invariant Labs (ETH Zurich spinout)
- **Connection:** stdio only (spawns MCP server subprocesses)
- **Enumeration:** Connects to servers, retrieves tool descriptions via MCP introspection
- **Detection:** 15+ security risks — E001 (Prompt Injection/Tool Poisoning), E002 (Tool Shadowing), Toxic Flows, E004 (Skill Prompt Injection), E006 (Malware), W007 (Credential Handling), W008 (Hardcoded Secrets), W011 (Untrusted Content)
- **Scanning engine:** Combination of deterministic rules + LLM-based judges + remote API verification
- **Tool pinning:** SHA-based hashing of tool definitions stored in `~/.mcp-scan`; detects rug pulls (description changes between scans)
- **Config discovery:** Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Gemini CLI, OpenClaw, Kiro, Antigravity, Codex, Amazon Q
- **What it DOES that we reuse:** Tool hashing for rug pull detection, tool shadowing detection (name collision), toxic flow analysis concepts, broadest config discovery list
- **What it DOESN'T do:** No graph output, no cross-server analysis, no trust boundary mapping

### Key Gap Both Tools Share

Both tools analyze MCP servers **individually**. Neither constructs relationships between:
- Agent → Server (which agent trusts which server)
- Server → Tool → Resource (what a tool can access)
- Tool → Tool (cross-server shadowing as a directed graph edge)
- Credential → Identity → Server (credential chain escalation)

**AgentHound's MCP Collector must output nodes AND edges in a standardized graph format.**

## 3. MCP Protocol — Enumeration API Reference

All messages use JSON-RPC 2.0 over either stdio (newline-delimited) or Streamable HTTP.

### 3.1 Initialize Handshake

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-11-25",
    "capabilities": {
      "roots": { "listChanged": true }
    },
    "clientInfo": {
      "name": "AgentHound",
      "version": "0.1.0"
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2025-11-25",
    "capabilities": {
      "tools": { "listChanged": true },
      "resources": { "subscribe": true, "listChanged": true },
      "prompts": { "listChanged": true },
      "logging": {},
      "tasks": {}
    },
    "serverInfo": {
      "name": "example-server",
      "version": "1.0.0"
    },
    "instructions": "Optional instructions for the client"
  }
}
```

**Then send initialized notification:**
```json
{
  "jsonrpc": "2.0",
  "method": "notifications/initialized"
}
```

**Data extracted for graph:**
- `serverInfo.name`, `serverInfo.version` → MCPServer node properties
- `capabilities` → which enumeration methods to call (tools, resources, prompts)
- `instructions` → stored as node property; analyzed for injection patterns
- `protocolVersion` → node property

### 3.2 tools/list (Paginated)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": { "cursor": "optional-cursor-value" }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "execute_sql",
        "title": "SQL Query Executor",
        "description": "Execute a SQL query against the database",
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": { "type": "string" }
          },
          "required": ["query"]
        },
        "outputSchema": { ... },
        "annotations": {
          "readOnlyHint": false,
          "destructiveHint": true,
          "idempotentHint": false,
          "openWorldHint": false
        }
      }
    ],
    "nextCursor": "next-page-cursor"
  }
}
```

**Data extracted for graph per tool:**
- `name`, `title`, `description` → MCPTool node properties
- `inputSchema`, `outputSchema` → node properties (for input validation analysis)
- `annotations.readOnlyHint` (default: false), `annotations.destructiveHint` (default: true), `annotations.idempotentHint`, `annotations.openWorldHint` (default: true) → security-relevant hints
- SHA-256 of canonical JSON of entire tool definition → `descriptionHash` for rug pull detection
- **PROVIDES_TOOL** edge: MCPServer → MCPTool

**Pagination:** Continue calling with `nextCursor` until response has no `nextCursor`. Break after 100 pages as safety valve.

### 3.3 resources/list (Paginated)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "resources/list",
  "params": { "cursor": "optional-cursor-value" }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "resources": [
      {
        "uri": "file:///project/src/main.rs",
        "name": "main.rs",
        "title": "Rust Application Main File",
        "description": "Primary application entry point",
        "mimeType": "text/x-rust",
        "size": 4096
      }
    ],
    "nextCursor": "next-page-cursor"
  }
}
```

**Data extracted for graph per resource:**
- `uri`, `name`, `description`, `mimeType`, `size` → MCPResource node properties
- URI scheme (`file://`, `https://`, `git://`, custom) → `uriScheme` property
- **PROVIDES_RESOURCE** edge: MCPServer → MCPResource

### 3.4 resources/templates/list (Paginated)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "resources/templates/list",
  "params": { "cursor": "optional-cursor-value" }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "resourceTemplates": [
      {
        "uriTemplate": "file:///{path}",
        "name": "Project Files",
        "description": "Access files in the project directory",
        "mimeType": "application/octet-stream"
      }
    ]
  }
}
```

Resource templates indicate parameterized access patterns. A template like `postgres:///{table}` reveals database access surface even without specific resources listed.

### 3.5 prompts/list (Paginated)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "prompts/list",
  "params": { "cursor": "optional-cursor-value" }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "prompts": [
      {
        "name": "code_review",
        "title": "Request Code Review",
        "description": "Asks the LLM to analyze code quality",
        "arguments": [
          {
            "name": "code",
            "description": "The code to review",
            "required": true
          }
        ]
      }
    ]
  }
}
```

**Data extracted for graph per prompt:**
- `name`, `description`, `arguments` → MCPPrompt node properties
- **PROVIDES_PROMPT** edge: MCPServer → MCPPrompt

## 4. Transport Implementation

### 4.1 stdio Transport

The client launches the MCP server as a subprocess. JSON-RPC messages are sent over stdin/stdout, one message per line (newline-delimited, no embedded newlines).

**Implementation (Go):**
```go
// Using the official Go MCP SDK
import "github.com/modelcontextprotocol/go-sdk/mcp"

cmd := exec.Command(command, args...)
cmd.Env = append(os.Environ(), envVarsFromConfig...) // env vars set on exec.Cmd directly
transport := &mcp.CommandTransport{
    Command: cmd,
}
session, err := client.Connect(ctx, transport, nil)
```

**Note:** The Go SDK's `CommandTransport` has two fields: `Command *exec.Cmd` and `TerminateDuration time.Duration`. Environment variables must be set on the `exec.Cmd` struct directly (via `cmd.Env`), not on the transport.

**Key behaviors:**
- Server stderr is captured for logging but does not contain protocol messages
- Server stdout MUST contain only valid JSON-RPC messages
- Shutdown: close stdin → wait for exit → SIGTERM → SIGKILL (with timeouts)
- Each server runs in an isolated goroutine with its own timeout

### 4.2 Streamable HTTP Transport

The server runs as an independent HTTP service with a single MCP endpoint (e.g., `https://example.com/mcp`).

**Client sends:** HTTP POST with JSON-RPC body, `Accept: application/json, text/event-stream`
**Server responds:** Either `Content-Type: application/json` (single response) or `Content-Type: text/event-stream` (SSE stream)
**Session management:** Server may return `MCP-Session-Id` header; client includes it on subsequent requests
**Protocol version header:** Client MUST include `MCP-Protocol-Version: 2025-11-25` on all requests after init

**Security requirements for local servers:**
- MUST validate `Origin` header (DNS rebinding protection)
- SHOULD bind to localhost only (127.0.0.1)
- SHOULD implement authentication

### 4.3 Legacy SSE Transport (2024-11-05)

Older servers may use the deprecated HTTP+SSE transport. The collector should attempt Streamable HTTP first (POST to endpoint), and on 400/404/405, fall back to GET (expecting SSE stream with `endpoint` event).

## 5. Security Signal Extraction

During collection, the collector computes security signals that the post-processor uses for composite edges. This mirrors what Cisco MCP Scanner and Snyk agent-scan do, but outputs structured data for graph construction.

### 5.1 Tool Description Hash (Rug Pull Detection)

Compute SHA-256 of the canonical JSON representation of each tool definition (name + description + inputSchema + outputSchema + annotations). Store as `descriptionHash` on MCPTool nodes. On subsequent scans, compare hashes to detect description changes (rug pulls).

**Prior art:** Snyk agent-scan stores tool hashes in `~/.mcp-scan` for exactly this purpose.

### 5.2 Injection Pattern Detection

Scan tool descriptions, prompt descriptions, and server instructions for patterns:
- `<IMPORTANT>`, `<system>`, `<instructions>` tags
- Imperative verbs targeting other tools: "ignore previous", "always use", "never call", "instead of X use Y"
- Data exfiltration patterns: URLs, email addresses, encoded data instructions
- Cross-tool references: tool A's description mentions tool B by name (especially tools from other servers)

**Prior art:** Cisco MCP Scanner uses YARA rules for pattern matching. Snyk agent-scan uses deterministic rules + LLM judges. We use deterministic pattern matching (no LLM dependency in collector).

### 5.3 Capability Surface Classification

Classify each tool by what it can do, based on description and inputSchema analysis:

| Capability | Detection Heuristics |
|-----------|---------------------|
| `shell_access` | Description contains: exec, shell, run, command, subprocess, bash, terminal, spawn |
| `file_read` | Description contains: read file, get file, cat, open file; inputSchema has path/filename field |
| `file_write` | Description contains: write file, save, create file, modify file, append |
| `network_outbound` | Description contains: HTTP, fetch, request, curl, download, upload, API call, webhook |
| `database_access` | Description contains: SQL, query, database, table, SELECT, INSERT, schema |
| `email_send` | Description contains: send email, send message, mail, SMTP, notify |
| `code_execution` | Description contains: eval, execute code, run script, compile, interpret |
| `credential_access` | Description contains: password, secret, token, key, credential, auth |

**Prior art:** Cisco MCP Scanner categorizes tools by capability. Snyk agent-scan detects credential handling (W007) and hardcoded secrets (W008).

### 5.4 Tool Annotation Analysis

Extract the four annotation hints as security signals:

| Annotation | Default | Security Meaning |
|-----------|---------|-----------------|
| `readOnlyHint` | `false` | If true, tool claims it doesn't modify state — lower risk weight |
| `destructiveHint` | `true` | If true, tool may perform destructive operations — higher risk weight |
| `idempotentHint` | `false` | If true, repeated calls are safe — relevant for replay attack analysis |
| `openWorldHint` | `true` | If true, tool interacts with external systems — exfiltration risk |

**Important:** Annotations are hints only. The MCP spec explicitly states clients MUST consider tool annotations untrusted unless from trusted servers. The collector records them but the post-processor should not solely rely on them.

## 6. Connection Lifecycle Per Server

```
1. Resolve transport type (stdio or HTTP) from config
2. For stdio: spawn subprocess with command, args, env from config
   For HTTP: establish HTTP connection to URL
3. Send: initialize { protocolVersion: "2025-11-25", capabilities, clientInfo }
4. Receive: InitializeResult { protocolVersion, capabilities, serverInfo, instructions }
5. Send: notifications/initialized
6. If capabilities.tools: call tools/list (paginate until complete)
7. If capabilities.resources: call resources/list (paginate until complete)
8. If capabilities.resources: call resources/templates/list (paginate until complete)
9. If capabilities.prompts: call prompts/list (paginate until complete)
10. Compute security signals per tool/resource/prompt
11. Generate nodes and edges
12. Gracefully close connection
```

Timeouts:
- Initialize: 30s (configurable)
- Each enumeration call: 15s
- Total per server: 120s
- Pagination safety valve: 100 pages max

## 7. Graph Output — Nodes and Edges

### Nodes Generated

| Node Label | Source | Key Properties |
|-----------|--------|---------------|
| `MCPServer` | InitializeResult + config | `name`, `version`, `transport`, `endpoint`, `protocolVersion`, `capabilities`, `instructions`, `instructionsHash` |
| `MCPTool` | tools/list | `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, `descriptionHash`, `capabilitySurface[]`, `hasInjectionPatterns`, `hasCrossReferences` |
| `MCPResource` | resources/list | `uri`, `name`, `description`, `mimeType`, `size`, `uriScheme` |
| `MCPPrompt` | prompts/list | `name`, `description`, `arguments` |

### Edges Generated

| Edge Kind | Source → Target | How Determined |
|----------|----------------|---------------|
| `PROVIDES_TOOL` | MCPServer → MCPTool | Each tool from `tools/list` gets an edge from its server |
| `PROVIDES_RESOURCE` | MCPServer → MCPResource | Each resource from `resources/list` |
| `PROVIDES_PROMPT` | MCPServer → MCPPrompt | Each prompt from `prompts/list` |

### Node ID Strategy

Deterministic, content-based IDs for deduplication across scans:

```
MCPServer:   SHA-256(transport + ":" + endpoint_or_command + ":" + sorted_args_hash)
MCPTool:     SHA-256(server_id + ":" + tool_name)
MCPResource: SHA-256(server_id + ":" + resource_uri)
MCPPrompt:   SHA-256(server_id + ":" + prompt_name)
```

## 8. CLI Interface

```bash
# Scan a single stdio server
agenthound collect mcp \
  --command "npx" \
  --args "-y,@modelcontextprotocol/server-postgres" \
  --env "POSTGRES_URL=postgresql://..." \
  --output scan.json

# Scan a single HTTP server
agenthound collect mcp \
  --url "https://mcp.example.com/mcp" \
  --output scan.json

# Scan all servers from a specific config file
agenthound collect mcp \
  --config ~/.claude/claude_desktop_config.json \
  --output scan.json

# Auto-discover all MCP client configs on this machine
agenthound collect mcp \
  --discover \
  --output scan.json

# Parallel scan with tuning
agenthound collect mcp \
  --discover \
  --threads 10 \
  --timeout 30s \
  --output scan.json
```

## 9. Error Handling

| Scenario | Handling |
|----------|---------|
| Server subprocess fails to start | Log error with command/args, skip, emit MCPServer node with `status: unreachable` |
| Server hangs on initialize | Timeout (default 30s), kill process, skip |
| Server returns unsupported protocol version | Log warning, attempt anyway, record actual version |
| Malformed JSON-RPC response | Log raw response, skip that call, continue with other methods |
| Pagination infinite loop (same cursor) | Detect duplicate cursor, break, log warning |
| Tools list > 1000 tools | Paginate fully, log info about scale |
| Server requires auth we don't have | Log auth challenge details, record MCPServer node with `authRequired: true` but no tool data |
| SSL/TLS errors | Log warning, optionally `--insecure` flag |
| stdio server crashes mid-collection | Capture stderr, log crash details, emit partial data collected so far |

## 10. Go Implementation — Key Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/modelcontextprotocol/go-sdk/mcp` | Official MCP client SDK — handles initialize handshake, JSON-RPC framing, stdio/HTTP transport |
| `github.com/spf13/cobra` | CLI framework |
| `crypto/sha256` | Tool description hashing |
| `encoding/json` | JSON-RPC message construction, canonical JSON for hashing |
| `os/exec` | Subprocess spawning for stdio transport |
| `context` | Timeout and cancellation |
| `sync` | WaitGroup/Mutex for parallel server enumeration |

The official Go MCP SDK (`github.com/modelcontextprotocol/go-sdk`) provides `mcp.NewClient()`, `mcp.CommandTransport` (stdio), and `mcp.StdioTransport`. It handles the full initialize handshake, version negotiation, and JSON-RPC framing. AgentHound's collector wraps this SDK to add enumeration logic, security signal extraction, and graph output generation.
