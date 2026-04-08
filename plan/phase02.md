# Phase 2: Collectors

**Timeline:** Weeks 3–5
**Goal:** All three collectors (Config, MCP, A2A) working, producing valid ingest JSON, with security signal extraction and full integration with the ingest pipeline from Phase 1.

**Depends on:** Phase 1 (project structure, ingest pipeline, Neo4j schema, Docker infrastructure)

---

## 1. Implementation Order

Build collectors in this order — each one is independently testable and the order matches dependency flow:

1. **Config Collector** (Week 3) — parses config files, produces trust edges. No network calls. Easiest to test.
2. **MCP Collector** (Week 4) — spawns MCP servers, enumerates tools/resources. Requires Config Collector output to know which servers to connect to.
3. **A2A Collector** (Week 5) — fetches Agent Cards via HTTP. Independent of MCP but benefits from having both others for end-to-end testing.

---

## 2. Shared Collector Infrastructure

### 2.1 Collector Interface (`pkg/collector/collector.go`)

Already defined in Phase 1. All collectors implement:

```go
type Collector interface {
    Name() string
    Collect(ctx context.Context, config CollectorConfig) (*model.IngestData, error)
}
```

### 2.2 Shared Utilities (`internal/collector/common/`)

```
internal/collector/common/
├── hasher.go          # SHA-256 ID computation
├── patterns.go        # Injection pattern detection
├── capability.go      # Tool capability surface classification
├── entropy.go         # Shannon entropy calculator for secret detection
└── output.go          # IngestData builder helper
```

**`hasher.go` — Deterministic Node ID Generation:**

```go
func NodeID(components ...string) string {
    h := sha256.New()
    for _, c := range components {
        h.Write([]byte(c))
        h.Write([]byte(":"))
    }
    return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Pre-built ID generators per node type
func MCPServerID(transport, endpoint string, args []string) string {
    sort.Strings(args)
    return NodeID("MCPServer", transport, endpoint, strings.Join(args, ","))
}

func MCPToolID(serverID, toolName string) string {
    return NodeID("MCPTool", serverID, toolName)
}

func A2AAgentID(cardURL string) string {
    return NodeID("A2AAgent", cardURL)
}
// ... etc for all node types
```

**Critical:** `MCPServerID` must produce identical output in both Config Collector and MCP Collector for the same server. This is the merge point. Both collectors compute: `SHA-256("MCPServer:" + transport + ":" + endpoint + ":" + sorted_args)`.

**`patterns.go` — Injection Pattern Detection:**

Deterministic pattern matching (no LLM dependency). Patterns derived from:
- OWASP MCP Top 10 MCP03 (Tool Poisoning)
- Invariant Labs tool poisoning research
- Cisco MCP Scanner YARA rules
- MCPTox benchmark (AAAI 2026)

```go
var injectionPatterns = []InjectionPattern{
    {Name: "important_tag", Pattern: `(?i)<important>`, Severity: "high"},
    {Name: "system_tag", Pattern: `(?i)<system>`, Severity: "high"},
    {Name: "instructions_tag", Pattern: `(?i)<instructions>`, Severity: "high"},
    {Name: "ignore_previous", Pattern: `(?i)(ignore|disregard|forget)\s+(previous|prior|above|other)`, Severity: "high"},
    {Name: "always_use", Pattern: `(?i)always\s+(use|call|invoke|run)\s+this`, Severity: "medium"},
    {Name: "never_use_other", Pattern: `(?i)never\s+(use|call|invoke)\s+`, Severity: "medium"},
    {Name: "instead_of", Pattern: `(?i)instead\s+of\s+(using|calling)`, Severity: "medium"},
    {Name: "exfil_url", Pattern: `https?://[^\s]+\.(evil|attacker|exfil)`, Severity: "critical"},
    {Name: "embedded_url", Pattern: `(?i)(send|forward|post|upload)\s+(to|at)\s+https?://`, Severity: "high"},
    {Name: "base64_instruction", Pattern: `(?i)(encode|base64|hex)\s+(and\s+)?(send|post|forward)`, Severity: "high"},
}

func DetectInjectionPatterns(text string) []PatternMatch {
    // Returns list of matched patterns with positions
}

func HasInjectionPatterns(text string) bool {
    return len(DetectInjectionPatterns(text)) > 0
}
```

**`capability.go` — Tool Capability Classification:**

```go
type Capability string
const (
    CapShellAccess     Capability = "shell_access"
    CapFileRead        Capability = "file_read"
    CapFileWrite       Capability = "file_write"
    CapNetworkOutbound Capability = "network_outbound"
    CapDatabaseAccess  Capability = "database_access"
    CapEmailSend       Capability = "email_send"
    CapCodeExecution   Capability = "code_execution"
    CapCredentialAccess Capability = "credential_access"
)

func ClassifyCapabilities(toolName, description string, inputSchema map[string]interface{}) []Capability {
    // Pattern matching on description + inputSchema field names
    // Returns sorted, deduplicated list of capabilities
}
```

Heuristics per capability documented in PRD `collectors/01-mcp-collector.md` Section 5.3.

**`entropy.go` — Shannon Entropy for Secret Detection:**

```go
func ShannonEntropy(s string) float64 {
    if len(s) == 0 {
        return 0
    }
    freq := make(map[rune]float64)
    for _, c := range s {
        freq[c]++
    }
    length := float64(utf8.RuneCountInString(s))
    entropy := 0.0
    for _, count := range freq {
        p := count / length
        if p > 0 {
            entropy -= p * math.Log2(p)
        }
    }
    return entropy
}

func IsLikelySecret(value string) bool {
    if len(value) < 8 { return false }
    entropy := ShannonEntropy(value)
    // Thresholds from detect-secrets, TruffleHog, Gitleaks
    if isBase64Charset(value) && entropy > 4.5 { return true }
    if isHexCharset(value) && entropy > 3.0 { return true }
    return false
}
```

Reference: detect-secrets `HighEntropyStringsPlugin`, Trend Micro finding that 48% of MCP servers store credentials in plaintext.

---

## 3. Config Collector (`internal/collector/config/`)

### 3.1 Files

```
internal/collector/config/
├── collector.go           # Main ConfigCollector implementing Collector interface
├── discovery.go           # Discover config file paths on current machine
├── parsers/
│   ├── parser.go          # ConfigParser interface
│   ├── claude_desktop.go  # Claude Desktop parser (mcpServers key)
│   ├── claude_code.go     # Claude Code parser (.mcp.json, ~/.claude.json)
│   ├── cursor.go          # Cursor parser (mcpServers key, + disabled flag)
│   ├── vscode.go          # VS Code parser (servers key — different!)
│   ├── windsurf.go        # Windsurf parser (mcpServers, serverUrl not url)
│   ├── continue_parser.go # Continue parser (config.yaml, YAML format)
│   ├── zed.go             # Zed parser (context_servers key)
│   ├── cline.go           # Cline parser (mcpServers + autoApprove field)
│   ├── jetbrains.go       # JetBrains parser (.junie/mcp/mcp.json)
│   ├── kiro.go            # Kiro parser (.kiro/settings/mcp.json)
│   └── amazon_q.go        # Amazon Q parser (~/.aws/amazonq/mcp.json)
├── credential.go          # Credential pattern matching and extraction
├── instruction.go         # Instruction file discovery and analysis
├── pincheck.go            # Unpinned package version detection
└── config_test.go         # Unit tests
```

### 3.2 ConfigParser Interface

```go
type ConfigParser interface {
    ClientName() string
    ConfigPaths() []string  // Platform-aware paths to check
    Parse(path string, data []byte) (*ParsedConfig, error)
}

type ParsedConfig struct {
    Client  string
    Path    string
    Servers []ServerDef
}

type ServerDef struct {
    Name      string
    Transport string            // "stdio" or "http"
    Command   string            // For stdio
    Args      []string          // For stdio
    Env       map[string]string // For stdio
    URL       string            // For HTTP
    Headers   map[string]string // For HTTP
}
```

### 3.3 Config File Discovery Paths

All paths per PRD `collectors/03-config-collector.md` Section 3:

| Client | macOS | Linux | Windows |
|--------|-------|-------|---------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Code (project) | `.mcp.json` | `.mcp.json` | `.mcp.json` |
| Claude Code (user) | `~/.claude.json` | `~/.claude.json` | `~/.claude.json` |
| Cursor (global) | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` |
| Cursor (project) | `.cursor/mcp.json` | `.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code (workspace) | `.vscode/mcp.json` | `.vscode/mcp.json` | `.vscode/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` | `%USERPROFILE%\.codeium\windsurf\mcp_config.json` |
| Continue | `~/.continue/config.yaml` | `~/.continue/config.yaml` | `~/.continue/config.yaml` |
| Zed | `~/.config/zed/settings.json` | `~/.config/zed/settings.json` | — |
| Cline | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json` |
| JetBrains | `.junie/mcp/mcp.json`, `~/.junie/mcp/mcp.json` | same | same |
| Kiro | `.kiro/settings/mcp.json`, `~/.kiro/settings/mcp.json` | same | same |
| Amazon Q | `~/.aws/amazonq/mcp.json`, `.amazonq/mcp.json` | same | same |

Use `runtime.GOOS` for platform detection. Use `os.UserHomeDir()` for `~`.

### 3.4 Key Format Differences

| Client | Root Key | HTTP URL Key | Notes |
|--------|----------|-------------|-------|
| Claude Desktop | `mcpServers` | `url` | Standard format |
| Cursor | `mcpServers` | `url` | Has `disabled` field |
| VS Code | **`servers`** | `url` | Different root key! Has `type: "http"` |
| Windsurf | `mcpServers` | **`serverUrl`** | Different URL key! |
| Zed | **`context_servers`** | `url` | Different root key! |
| Cline | `mcpServers` | `url` | Has `autoApprove` array |
| Continue | `mcpServers` | `url` | **YAML format**, array not object |

### 3.5 Unpinned Package Detection (`pincheck.go`)

```go
func IsUnpinned(command string, args []string) bool {
    fullCmd := strings.Join(append([]string{command}, args...), " ")
    // npx patterns
    if strings.Contains(fullCmd, "npx") {
        // Check for version pin: @scope/pkg@1.2.3, pkg@^1.0, etc.
        // Matches both scoped (@scope/pkg@ver) and non-scoped (pkg@ver) packages
        if !regexp.MustCompile(`(?:@[\w\-./]+|[\w\-./]+)@[\d^~]`).MatchString(fullCmd) {
            return true // npx without version pin
        }
    }
    // uvx patterns
    if strings.Contains(fullCmd, "uvx") {
        if !regexp.MustCompile(`==[\d.]`).MatchString(fullCmd) {
            return true // uvx without version pin
        }
    }
    return false
}
```

### 3.6 Instruction File Discovery (`instruction.go`)

Discover and analyze agent instruction files:

| File | Search Paths |
|------|-------------|
| `AGENTS.md` | Project root, `./` |
| `CLAUDE.md` | Project root, `~/.claude/CLAUDE.md` |
| `MEMORY.md` | `~/.claude/projects/*/memory/MEMORY.md` |
| `.cursorrules` | Project root |
| `.copilot-instructions.md` | Project root, `.github/` |

Analysis:
- SHA-256 hash of content for drift detection
- Pattern matching for suspicious directives (imperative overrides, exfiltration commands, hidden Unicode)
- Produces `InstructionFile` node + `LOADS_INSTRUCTIONS` edge to `AgentInstance`

### 3.7 Nodes and Edges Produced

**Nodes:** ConfigFile, AgentInstance, MCPServer, Identity, Credential, Host, InstructionFile
**Edges:** TRUSTS_SERVER, CONFIGURED_IN, AUTHENTICATES_WITH, USES_CREDENTIAL, RUNS_ON (MCPServer → Host), HAS_ENV_VAR (MCPServer → Credential), LOADS_INSTRUCTIONS

**Important:** The Config Collector produces `RUNS_ON` edges from `MCPServer → Host`. For stdio servers, Host is always localhost. For HTTP servers, Host is parsed from the URL. This edge is critical for Phase 3's `CAN_EXECUTE` post-processor and cross-protocol correlation.

### 3.8 CLI Command

```go
// internal/cli/collect_config.go
var collectConfigCmd = &cobra.Command{
    Use:   "config",
    Short: "Discover and parse MCP client configuration files",
    RunE: func(cmd *cobra.Command, args []string) error {
        cfg := collectorConfig(cmd)
        collector := config.NewConfigCollector()
        result, err := collector.Collect(cmd.Context(), cfg)
        // Write to --output file
    },
}

// Flags:
// --discover            Auto-discover all known config paths
// --path <path>         Scan a specific config file
// --paths <p1,p2,...>   Scan multiple config files
// --output <file>       Output JSON file (default: stdout)
// --redact-credentials  Hash credential values (default: true)
// --include-credential-values  Store actual credential values (audit mode)
// --project-dir <dir>   Project directory for project-level configs (default: cwd)
```

---

## 4. MCP Collector (`internal/collector/mcp/`)

### 4.1 Files

```
internal/collector/mcp/
├── collector.go           # Main MCPCollector implementing Collector interface
├── client.go              # MCP protocol client (wraps official Go SDK)
├── enumerate.go           # Enumeration logic (tools/list, resources/list, etc.)
├── stdio.go               # Stdio transport: spawn subprocess
├── http.go                # Streamable HTTP transport
├── signals.go             # Security signal extraction per tool/resource
├── mcp_test.go            # Unit tests
└── integration_test.go    # Integration tests with real MCP servers
```

### 4.2 MCP Go SDK Usage

**Package:** `github.com/modelcontextprotocol/go-sdk` **v1.5.0** (latest as of 2026-04-07)

**Requires Go 1.25+** (uses `iter.Seq2` for auto-paginating iterators).

```go
import "github.com/modelcontextprotocol/go-sdk/mcp"

// Create client
client := mcp.NewClient(
    &mcp.Implementation{Name: "AgentHound", Version: "0.1.0"},
    &mcp.ClientOptions{},  // nil for defaults
)

// For stdio transport:
cmd := exec.CommandContext(ctx, command, args...)
cmd.Env = append(os.Environ(), envVars...)
transport := &mcp.CommandTransport{
    Command:           cmd,
    TerminateDuration: 5 * time.Second,
}

// Connect (automatically performs initialize + notifications/initialized)
session, err := client.Connect(ctx, transport, nil)

// Enumerate tools — auto-paginating iterator (handles NextCursor automatically)
for tool, err := range session.Tools(ctx, nil) {
    if err != nil { break }
    // tool is *mcp.Tool with Name, Description, InputSchema, Annotations, etc.
}

// Or single-page call if you need cursor control:
toolsResult, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: ""})

// Same pattern for resources, prompts, templates:
for resource, err := range session.Resources(ctx, nil) { ... }
for prompt, err := range session.Prompts(ctx, nil) { ... }
for tmpl, err := range session.ResourceTemplates(ctx, nil) { ... }

// Get server capabilities from handshake
initResult := session.InitializeResult()
// initResult.Capabilities, initResult.ServerInfo, initResult.Instructions

// Close
session.Close()
```

**Important SDK details:**
- `mcp.CommandTransport` wraps `exec.Cmd` for stdio — env vars set via `cmd.Env`
- `mcp.StreamableClientTransport{Endpoint: url}` for HTTP servers (auto-retry, SSE support)
- `client.Connect()` handles the full `initialize` → `notifications/initialized` handshake automatically
- Auto-paginating iterators (`session.Tools`, `session.Resources`, etc.) handle `NextCursor` transparently
- Error handling: check `errors.Is(err, mcp.ErrConnectionClosed)` or `errors.As(err, &jsonrpc.Error{})`
- The SDK returns typed structs (`mcp.Tool`, `mcp.Resource`, `mcp.Prompt`, etc.)

### 4.3 Connection Lifecycle Per Server

```
1. Resolve transport type from config (command = stdio, url = HTTP)
2. For stdio: spawn subprocess via exec.Cmd
   For HTTP: create HTTP transport with URL
3. Connect via SDK (handles initialize handshake)
4. Extract server info: protocolVersion, capabilities, serverInfo, instructions
5. If capabilities include tools: call ListTools (paginate until no NextCursor)
6. If capabilities include resources: call ListResources (paginate)
7. Call ListResourceTemplates (paginate)
8. If capabilities include prompts: call ListPrompts (paginate)
9. Compute security signals per tool/resource/prompt
10. Generate nodes and edges
11. Close session gracefully
```

**Timeouts:**
- Initialize: 30s (configurable via `--timeout`)
- Each enumeration call: 15s
- Total per server: 120s
- Pagination safety: max 100 pages per method

### 4.4 Security Signal Extraction (`signals.go`)

For each tool:
1. **Description hash:** `SHA-256(canonical JSON of tool definition)` → `description_hash` property
2. **Injection patterns:** `HasInjectionPatterns(tool.Description)` → `has_injection_patterns` boolean
3. **Cross-references:** Check if description mentions any tool name from OTHER servers → `has_cross_references` boolean
4. **Capability surface:** `ClassifyCapabilities(tool.Name, tool.Description, tool.InputSchema)` → `capability_surface` string array
5. **Annotation analysis:** Extract `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` → properties

For server instructions:
- Run `HasInjectionPatterns(instructions)` → `instructions_has_injection` boolean
- Hash instructions content → `instructions_hash` property

### 4.5 Nodes and Edges Produced

**Nodes:** MCPServer (enriched with protocol data), MCPTool, MCPResource, MCPPrompt
**Edges:** PROVIDES_TOOL, PROVIDES_RESOURCE, PROVIDES_PROMPT

### 4.6 Parallel Server Enumeration

```go
func (c *MCPCollector) Collect(ctx context.Context, cfg CollectorConfig) (*model.IngestData, error) {
    sem := make(chan struct{}, cfg.Threads) // concurrency limiter
    var wg sync.WaitGroup
    var mu sync.Mutex
    var allNodes []model.Node
    var allEdges []model.Edge

    for _, serverDef := range cfg.Servers {
        wg.Add(1)
        sem <- struct{}{} // acquire
        go func(s ServerDef) {
            defer wg.Done()
            defer func() { <-sem }() // release

            serverCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
            defer cancel()

            nodes, edges, err := c.enumerateServer(serverCtx, s)
            if err != nil {
                slog.Warn("server enumeration failed", "server", s.Name, "error", err)
                // Still emit MCPServer node with status: unreachable
                nodes = []model.Node{c.unreachableServerNode(s, err)}
            }

            mu.Lock()
            allNodes = append(allNodes, nodes...)
            allEdges = append(allEdges, edges...)
            mu.Unlock()
        }(serverDef)
    }
    wg.Wait()

    return buildIngestData("mcp", allNodes, allEdges), nil
}
```

### 4.7 Error Handling

Per PRD `collectors/01-mcp-collector.md` Section 9:

| Scenario | Handling |
|----------|---------|
| Server subprocess fails to start | Log error, emit MCPServer node with `status: unreachable` |
| Server hangs on initialize | Timeout (30s), kill process, skip |
| Server returns unsupported protocol version | Log warning, attempt anyway, record actual version |
| Malformed JSON-RPC response | Log error, skip that method, continue |
| Pagination infinite loop (duplicate cursor) | Detect, break, log warning |
| Server requires auth | Log auth challenge, emit node with `auth_required: true`, no tool data |
| TLS errors | Log warning, `--insecure` flag to proceed |
| Stdio server crashes mid-collection | Capture stderr, emit partial data |

### 4.8 CLI Command

```bash
agenthound collect mcp \
  --discover                    # Scan all known client configs
  --config <path>               # Scan servers from specific config
  --command <cmd> --args <a1,a2> --env <K=V> # Scan single stdio server
  --url <url>                   # Scan single HTTP server
  --threads 10                  # Parallel server enumeration
  --timeout 30s                 # Per-server timeout
  --output scan.json            # Output file
```

### 4.9 Legacy SSE Transport Fallback

Per MCP spec, servers may use the deprecated HTTP+SSE transport (2024-11-05). The collector should:
1. Try Streamable HTTP first (POST to endpoint)
2. On 400/404/405, fall back to SSE transport (GET expecting SSE stream)
3. Log which transport was successfully used

---

## 5. A2A Collector (`internal/collector/a2a/`)

### 5.1 Files

```
internal/collector/a2a/
├── collector.go           # Main A2ACollector implementing Collector interface
├── fetch.go               # HTTP GET Agent Card fetching
├── parse.go               # Agent Card JSON parsing (v0.3.0 + v1.0)
├── signals.go             # Security signal extraction
├── jws.go                 # JWS signature verification (RFC 7515)
├── a2a_test.go            # Unit tests
└── integration_test.go    # Integration tests with mock A2A endpoints
```

### 5.2 Agent Card Fetching (`fetch.go`)

```go
func FetchAgentCard(ctx context.Context, targetURL string, authToken string) (*RawAgentCard, error) {
    // Try canonical path (all versions use agent-card.json per IANA registration)
    urls := []string{
        targetURL + "/.well-known/agent-card.json",  // canonical (RFC 8615, all versions)
        targetURL + "/.well-known/agent.json",       // non-standard fallback (some early implementations)
    }

    client := &http.Client{
        Timeout: 15 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= 5 { return fmt.Errorf("too many redirects") }
            return nil
        },
    }

    for _, url := range urls {
        req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
        req.Header.Set("Accept", "application/json")
        if authToken != "" {
            req.Header.Set("Authorization", authToken)
        }

        resp, err := client.Do(req)
        if err != nil { continue }
        if resp.StatusCode == 200 {
            // Parse and return
        }
    }
    return nil, fmt.Errorf("agent card not found at %s", targetURL)
}
```

### 5.3 Agent Card Parsing — Version Detection (`parse.go`)

```go
func DetectVersion(raw map[string]interface{}) string {
    if _, ok := raw["supportedInterfaces"]; ok {
        return "v1.0"
    }
    if _, ok := raw["url"]; ok {
        return "v0.3.0"
    }
    return "unknown"
}
```

**v0.3.0 parsing:** Top-level `url`, `protocolVersion`, skills in `skills[]`
**v1.0 parsing:** `supportedInterfaces[]` with per-interface `url` and `protocolVersion`, skills with required `id` and `tags`

Both versions share: `name`, `description`, `version`, `provider`, `capabilities`, `securitySchemes`, `security`, `skills`

### 5.4 JWS Signature Verification (`jws.go`)

A2A v0.3.0+ supports optional `signatures` field per RFC 7515 (Flattened JSON Serialization).

```go
func VerifyJWSSignature(cardJSON []byte, signatures []JWSSignature) (bool, error) {
    // For each signature:
    // 1. Decode protected header (base64url)
    // 2. Extract algorithm (RS256, ES256, etc.)
    // 3. Construct signing input: base64url(header) + "." + base64url(payload)
    // 4. Verify signature against signing input
    // Note: We verify integrity, not identity (per A2A spec acknowledgment)
}
```

If `signatures` field is absent → flag as `is_signed: false` (UNSIGNED_CARD finding).
If present and valid → `is_signed: true, signature_valid: true`.
If present but invalid → `is_signed: true, signature_valid: false` (critical finding).

### 5.5 Security Signals

1. **Auth posture:** Score from securitySchemes (none=100, apiKey=70, bearer=50, oauth=25, oidc=20, mTLS=10)
2. **Card hash:** SHA-256 of full Agent Card JSON
3. **Skill description hashes:** Per-skill SHA-256
4. **Injection patterns:** Same patterns as MCP tools, applied to skill descriptions
5. **HTTPS enforcement:** Flag HTTP-only endpoints
6. **Endpoint consistency:** Flag if card URL doesn't match fetch URL
7. **Internal IP detection:** Flag 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.169.254
8. **Push notification webhook analysis:** If capabilities.pushNotifications and internal IPs → SSRF risk

### 5.6 Nodes and Edges Produced

**Nodes:** A2AAgent, A2ASkill, Host (derived from agent URL)
**Edges:** ADVERTISES_SKILL, DELEGATES_TO (inferred from descriptions), SAME_AUTH_DOMAIN (shared OAuth tokenUrl), RUNS_ON (A2AAgent → Host, derived from agent URL hostname)

**Important:** The A2A Collector produces `RUNS_ON` edges from `A2AAgent → Host` by parsing the hostname from the agent's URL (v0.3.0: top-level `url`, v1.0: `supportedInterfaces[].url`). This edge is critical for Phase 3's cross-protocol correlation — it allows the post-processor to link A2A agents to MCP servers running on the same host.

### 5.7 CLI Command

```bash
agenthound collect a2a \
  --target <url>                  # Scan single agent
  --targets <url1,url2>           # Scan multiple agents
  --targets-file agents.txt       # Scan from file
  --discover-domain example.com   # Probe well-known paths
  --auth-token "Bearer eyJ..."    # Auth for protected cards
  --threads 10                    # Parallel fetching
  --timeout 15s                   # Per-agent timeout
  --insecure                      # Skip TLS verification
  --output scan.json
```

---

## 6. Integration Testing Strategy

### 6.1 Config Collector Tests

| Test | Input | Expected Output |
|------|-------|-----------------|
| `TestDiscoverClaudeDesktop` | Mock config at expected path | ConfigFile + AgentInstance + MCPServer nodes |
| `TestParseClaudeDesktopConfig` | Fixture JSON with 3 servers | 3 MCPServer nodes, 3 TRUSTS_SERVER edges |
| `TestParseVSCodeConfig` | VS Code format (`servers` key) | Correct parsing despite different key |
| `TestParseWindsurfConfig` | Windsurf format (`serverUrl`) | Correct HTTP URL extraction |
| `TestParseClineAutoApprove` | Cline config with `autoApprove` | autoApprove captured in properties |
| `TestUnpinnedPackageDetection` | `npx -y @pkg` vs `npx @pkg@1.0` | Correct isPinned boolean |
| `TestCredentialExtraction` | Env vars with `GITHUB_TOKEN=ghp_xxx` | Credential node with correct type |
| `TestEntropySecretDetection` | High-entropy value with non-standard name | Detected as likely secret |
| `TestInstructionFileDiscovery` | CLAUDE.md + .cursorrules in project | InstructionFile nodes + LOADS_INSTRUCTIONS edges |
| `TestMCPServerIDConsistency` | Same server config | ID matches between Config and MCP collectors |

### 6.2 MCP Collector Tests

| Test | Setup | Expected Output |
|------|-------|-----------------|
| `TestStdioConnectionLifecycle` | Mock MCP server (Go test binary) | Successful init + enumeration |
| `TestToolsListPagination` | Server returns 3 pages of tools | All tools collected |
| `TestPaginationSafetyValve` | Server returns same cursor forever | Breaks after 100 pages |
| `TestServerTimeout` | Server that hangs on init | Timeout after 30s, MCPServer node with status=unreachable |
| `TestServerCrash` | Server that crashes after tools/list | Partial data collected |
| `TestToolDescriptionHash` | Known tool definition | Correct SHA-256 hash |
| `TestInjectionPatternDetection` | Tool with `<IMPORTANT>` in description | `has_injection_patterns: true` |
| `TestCapabilitySurface` | Tool named "execute_sql" with SQL description | `capability_surface: ["database_access"]` |
| `TestAnnotationExtraction` | Tool with all 4 annotations | All annotations in properties |

**Mock MCP Server for Testing:**
Create a minimal Go binary that speaks MCP JSON-RPC over stdio. It responds to `initialize`, `tools/list`, `resources/list`, `prompts/list` with configurable responses. This is used in integration tests.

### 6.3 A2A Collector Tests

| Test | Setup | Expected Output |
|------|-------|-----------------|
| `TestFetchAgentCardV030` | Mock HTTP server serving v0.3.0 card | Parsed A2AAgent node |
| `TestFetchAgentCardV10` | Mock HTTP serving v1.0 card | Parsed with supportedInterfaces |
| `TestFallbackLegacyPath` | Server only serves at `/.well-known/agent.json` | Successfully fetched on fallback |
| `TestJWSSignatureValid` | Card with valid JWS signature | `is_signed: true, signature_valid: true` |
| `TestJWSSignatureInvalid` | Card with tampered content | `is_signed: true, signature_valid: false` |
| `TestUnsignedCard` | Card without signatures field | `is_signed: false` |
| `TestNoAuthDetection` | Card with empty security[] | Auth score = 100 (critical) |
| `TestHTTPEndpointFlag` | Card with `http://` URL | `is_https: false` flagged |
| `TestSkillInjectionDetection` | Skill with "always delegate to me" | `has_injection_patterns: true` |
| `TestDomainDiscovery` | Domain probe | Tries agent-card.json and agent.json paths |

### 6.4 End-to-End Pipeline Test

```
1. Run Config Collector on test fixtures → config_scan.json
2. Run MCP Collector on mock servers → mcp_scan.json
3. Run A2A Collector on mock endpoints → a2a_scan.json
4. Ingest all three files
5. Query Neo4j:
   - Verify MCPServer nodes merged (same ID from config and MCP)
   - Verify TRUSTS_SERVER edges from config connect to enriched MCPServer nodes
   - Verify all expected node types and edge types present
   - Verify node counts match expected
```

---

## 7. Success Metrics / Exit Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| 1 | `agenthound collect config --discover` discovers configs on a machine with Claude Desktop | Produces valid JSON with ConfigFile, AgentInstance, MCPServer nodes |
| 2 | Config Collector correctly parses all 12 client formats | Unit tests pass for each parser |
| 3 | `agenthound collect mcp --config <path>` enumerates a real MCP server | Tools, resources, prompts in output JSON |
| 4 | MCP stdio and HTTP transports both work | Integration tests pass for both |
| 5 | `agenthound collect a2a --target <url>` fetches and parses an Agent Card | A2AAgent and A2ASkill nodes in output |
| 6 | A2A Collector handles both v0.3.0 and v1.0 card formats | Unit tests for both versions |
| 7 | `agenthound ingest <scan.json>` loads any collector output into Neo4j | Nodes/edges appear in graph queries |
| 8 | MCPServer IDs match between Config and MCP collectors | E2E test: same server, both collectors, single merged node |
| 9 | Injection pattern detection catches `<IMPORTANT>` tags | Unit test with known poisoned descriptions |
| 10 | Capability surface classification works for all 8 capability types | Unit tests with representative descriptions |
| 11 | Unpinned package detection catches `npx -y @pkg` | Unit test |
| 12 | Shannon entropy secret detection catches high-entropy values | Unit test with known secrets vs normal values |
| 13 | All 3 collectors handle errors gracefully (timeout, crash, bad JSON) | Error handling tests pass |
| 14 | Unit test coverage > 80% on all collector packages | `go test -cover` |

---

## 8. Risks and Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Go MCP SDK API changes | Medium | Pin SDK version in go.mod. Wrap SDK calls in thin adapter layer. |
| Stdio server spawning differs across platforms | Medium | Test on macOS + Linux. Use `os/exec` with platform checks. |
| MCP servers with non-standard behavior | High | Robust error handling per server. Never let one server failure crash the collector. |
| A2A Agent Cards with unexpected fields | Medium | Use `map[string]interface{}` parsing first, then extract known fields. Ignore unknown. |
| Continue YAML format vs JSON | Low | Use `gopkg.in/yaml.v3` for Continue parser only. All others are JSON. |
| Config paths change across client versions | Medium | Discovery is best-effort. Log discovered vs not-found paths. |

---

## 9. External References

| Resource | URL | Relevance |
|----------|-----|-----------|
| MCP Spec (2025-11-25) | https://spec.modelcontextprotocol.io | Protocol messages, transport, auth |
| Go MCP SDK | https://github.com/modelcontextprotocol/go-sdk | Official client library |
| A2A Spec | https://a2a-protocol.org/latest/specification/ | Agent Card schema, security schemes |
| A2A What's New v1.0 | https://a2a-protocol.org/latest/whats-new-v1/ | v0.3.0 → v1.0 breaking changes |
| RFC 7515 (JWS) | https://tools.ietf.org/html/rfc7515 | Signature verification |
| OWASP MCP Top 10 | https://owasp.org/www-project-mcp-top-10/ | Detection taxonomy |
| Cisco MCP Scanner | https://github.com/cisco-ai-defense/mcp-scanner | Prior art for enumeration |
| Snyk agent-scan | https://github.com/snyk/agent-scan | Prior art for tool hashing |
| Cisco A2A Scanner | https://github.com/cisco-ai-defense/a2a-scanner | Prior art for card analysis |
| detect-secrets | https://github.com/Yelp/detect-secrets | Entropy-based secret detection |
