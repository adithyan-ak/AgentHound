# AgentHound — Project Context for Implementation

AgentHound is an open-source security tool for AI agent infrastructure. It enumerates MCP servers, A2A agents, and AI-agent client configs, builds a directed trust graph in Neo4j, and uses shortest-path algorithms to discover attack paths across protocol boundaries — including cross-protocol paths spanning MCP and A2A that single-protocol scanners cannot see.

The codebase ships as **two binaries** in the BloodHound/SharpHound style:

- **`agenthound`** — lean field collector. ~9 MiB stripped on linux/amd64. No DB clients, no UI, no auth, no outbound HTTP to a server. Drops on a target host, enumerates, writes JSON to a file or stdout. Operators move the scan to the analysis box via file copy, an SSH pipe, or the UI's drag-drop import.
- **`agenthound-server`** — single-user analysis server. Neo4j-backed graph, Postgres-backed scan history, post-processors, REST API, embedded React UI. Binds 127.0.0.1:8080 by default. **No application-layer authentication** — protect with the network layer (VPN / SSH tunnel).

See `docs/adr/0001-two-binary-split.md` for the rationale and `docs/security.md` for the threat model.

## Pre-Commit Checks (MANDATORY)

Before every commit, run these checks locally and fix all issues:

```bash
gofmt -l .                  # Must produce no output
go build ./...              # Must pass with zero errors
go vet ./...                # Must pass with zero warnings
go test ./... -race         # All tests pass with race detector
```

The CI runs `golangci-lint` (enforces `errcheck` — use `_, _ =` for intentionally discarded errors like `fmt.Fprintf` to stderr — and `gofmt`). It also runs:

- `govulncheck ./...` — blocking. Vulns surface as CI failures.
- `go-licenses check` — blocking. Allow-list: `Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, Unlicense, Zlib`.
- `scripts/deps-check.sh` — blocking. Verifies that the collector binary does not link `chi`, `pgx`, `neo4j-go-driver`, or any `server/internal/` code.
- `scripts/size-check.sh` — blocking. Collector linux/amd64 stripped binary must stay within baseline + 10%.

## Tech Stack

| Component | Choice | Key Details |
|-----------|--------|-------------|
| Backend | **Go 1.25.9** | Pinned in `go.mod`; required by MCP Go SDK v1.5.0 and to clear stdlib vulns. |
| CLI | **cobra** | `agenthound scan/rules/...`; `agenthound-server serve/ingest/query` |
| HTTP router | **chi/v5** | REST API at `/api/v1/*` (server only) |
| Graph DB | **Neo4j 4.4+ Community** | Cypher pathfinding, APOC for Dijkstra. Dual syntax: 4.4 uses `ON...ASSERT`, 5.x uses `FOR...REQUIRE`. |
| App DB | **PostgreSQL 16** | `scans` table only. Driver: `pgx/v5`. Auth/users/audit tables have been removed. |
| MCP SDK | `github.com/modelcontextprotocol/go-sdk` **v1.5.0** | `mcp.NewClient()`, `mcp.CommandTransport`, auto-paginating iterators (`session.Tools(ctx, nil)`) |
| Neo4j driver | `neo4j-go-driver/v5` v5.28+ | v5 for 4.4 compat. Batch writes with `UNWIND` + `MERGE`. |
| Frontend | **React 18 + TypeScript + Vite 6** | SPA embedded in `agenthound-server` via `go:embed` |
| Graph viz | **React Flow (`@xyflow/react`) + ELK (`elkjs`)** | DOM-based, suitable for the small-to-medium graphs typical in attack-path views. |
| UI | **shadcn/ui (Radix + Tailwind 3) + Zustand 5 + TanStack Query 5 + Recharts 2** | |
| Deployment | **Docker Compose** | 3 containers: `graph-db` (neo4j:4.4-community), `app-db` (postgres:16-alpine), `agenthound-server` |
| Release | **GoReleaser v2 + cosign keyless + syft** | Two builds, two Homebrew formulas, multi-arch Docker images, SBOMs, signed checksums. |
| License | Apache 2.0 | |

## Project Structure

```
agenthound/
├── collector/                          # `agenthound` binary
│   ├── cmd/agenthound/main.go          # Entry point; blank-imports modules to register them
│   ├── cli/                            # cobra subcommands: root, scan, rules, stubs, unknown
│   ├── internal/clientcfg/             # Per-host config (log level, output, concurrency)
│   └── scanner/                        # Network scanner stub for future fingerprint modules
├── server/                             # `agenthound-server` binary
│   ├── cmd/agenthound-server/main.go   # Entry point
│   ├── cli/                            # cobra subcommands: serve, ingest, query, version
│   ├── internal/
│   │   ├── api/                        # chi router, handlers, middleware (logging, cors). go:embed UI dist
│   │   ├── graph/                      # Neo4j driver, schema, batch writer, reader
│   │   ├── ingest/                     # validate → normalize → deduplicate → write → post-process
│   │   ├── analysis/                   # Post-processing
│   │   │   ├── postprocessor.go        # Runner with dependency ordering
│   │   │   ├── processors/             # has_access_to, can_execute, shadows, poisoned_description,
│   │   │   │                           # poisoned_instructions, can_reach, can_exfiltrate,
│   │   │   │                           # can_impersonate, cross_protocol, risk_score
│   │   │   ├── prebuilt/               # 17 pre-built queries
│   │   │   ├── riskscore/              # agent.go, server.go, tool.go, weights.go
│   │   │   └── similarity/tfidf.go     # For CAN_IMPERSONATE cosine similarity
│   │   ├── appdb/                      # Postgres: driver, migrations, scans CRUD
│   │   └── servercfg/                  # Env-based server config
│   ├── model/                          # Server-only response types (e.g. for findings handler)
│   └── ui/                             # React SPA (Vite 6 + React Flow + ELK)
│       └── src/
│           ├── api/                    # client.ts (ky), graph.ts, analysis.ts, scans.ts
│           ├── store/                  # Zustand: graph.ts, search.ts, ui.ts
│           ├── components/
│           │   ├── dashboard/          # Dashboard, StatCards, RiskChart, AuthCoverage, TopFindings
│           │   ├── explorer/           # Graph explorer (React Flow + ELK)
│           │   ├── findings/           # Findings list + detail with attack path
│           │   ├── inspector/          # Node properties, connections, evidence
│           │   ├── scans/              # Scan history, new scan
│           │   ├── queries/            # 17 pre-built queries
│           │   └── rules/              # Detection rules viewer
│           ├── hooks/                  # useGraph, useNodeSearch, useGraphEvents
│           └── lib/                    # graph-builder.ts, node-styles.ts, edge-styles.ts, layout.ts
├── sdk/                                # Public Go SDK (unstable until 1.0)
│   ├── ingest/                         # Node, Edge, IngestData, IngestMeta, GraphData (the wire contract)
│   ├── action/                         # Fingerprinter, Enumerator, Looter, Extractor, Poisoner, Implanter, Reverter
│   ├── module/                         # Register / Get / List for self-registering modules
│   ├── collector/                      # Legacy Collector interface (kept for module compat)
│   ├── common/                         # hasher, patterns, capability, entropy, ingest helpers
│   └── rules/                          # YAML rules engine + MatcherSpec (keyword/prefix/regex/entropy/composite)
├── modules/                            # Self-registering enumeration modules
│   ├── mcp/                            # MCP Collector (wraps Go SDK). register.go calls sdk/module.Register()
│   ├── a2a/                            # A2A Collector (HTTP GET + JSON parse + JWS verify)
│   ├── config/                         # Config Collector + parsers/ (12 client formats)
│   └── README.md                       # How to add a new module
├── docker/
│   ├── Dockerfile.agenthound           # Collector image (no UI, no DB clients)
│   ├── Dockerfile.agenthound-server    # Server image (UI builder + go binary)
│   ├── Dockerfile.standard             # Legacy single-binary image (being phased out)
│   ├── docker-compose.yml              # neo4j:4.4 + postgres:16 + agenthound-server
│   ├── neo4j.conf                      # APOC plugins enabled
│   └── init-db.sh                      # Postgres init
├── testdata/                           # valid_*_scan.json fixtures + a2a/ subdir for fetch tests
├── scripts/
│   ├── deps-check.sh                   # CI gate: collector deps must NOT include server-only libs
│   ├── size-check.sh                   # CI gate: collector binary stays within baseline +10%
│   ├── collector-allowlist.txt         # Reference list of acceptable collector deps
│   ├── seed-demo.sh
│   └── seed-test-data.sh
├── docs/
│   ├── adr/0001-two-binary-split.md    # ADR for the collector/server split
│   ├── future-modules.md               # Deferred surface and planning notes
│   ├── security.md                     # Threat model and operator OPSEC
│   ├── quickstart.md, cli-reference.md, api-reference.md, graph-model.md, architecture.md, detection-rules.md
├── install.sh                          # Collector installer; checksum + cosign verify; atomic install
├── .goreleaser.yml                     # Two builds, brews, dockers + manifests, cosign, syft
├── .github/
│   ├── workflows/ci.yml                # lint, test, build, docker, deps-check, size-check, xplatform-build
│   ├── workflows/release.yml           # cosign + syft, then goreleaser
│   └── dependabot.yml                  # gomod daily, github-actions weekly, npm weekly
├── Makefile                            # build, test, lint, docker, up, down, ui-build
└── .golangci.yml
```

The schema and ingest contract live in **`sdk/ingest/`** — `Node`, `Edge`, `IngestData`, `IngestMeta`, `GraphData`. There is no `internal/model/` anymore.

## Module registration

Modules under `modules/` self-register via `init()`. To add a new one:

1. Create `modules/<name>/`.
2. Implement `Enumerator` (or a future action interface) from `sdk/action/`.
3. Add `register.go` calling `sdk/module.Register(...)`.
4. Blank-import `_ "github.com/adithyan-ak/agenthound/modules/<name>"` in `collector/cmd/agenthound/main.go`.

See `modules/README.md` for the cleanest existing example.

## Graph Data Model

**Core principle:** Edges = exploitable relationships. Direction = access flow. `Agent → Server → Tool → Resource`.

### Node Types (22 collector-produced + 2 synthetic)

The first 12 are the v0.1 set; the next 8 are per-service AI-service kinds added in v0.2 (`OllamaInstance`, `VLLMInstance`, `QdrantInstance`, `MLflowServer`, `LiteLLMGateway`, `JupyterServer`, `LangServeApp`, `OpenWebUIInstance`); `AIService` is the multi-label umbrella every per-service node also carries; `AIModel` is the v0.3 model-artifact kind emitted by the Ollama Looter.

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
| `Credential` | Config + LiteLLM Looter | `type` (envVar/hardcoded/vaultRef/inputPrompt/master_key/apiKey/virtual_key), `name`, `source`, `is_exposed`, `high_entropy`, **`value_hash`** (SHA-256, cross-collector merge primitive) |
| `Host` | Config + A2A | `hostname`, `ip`, `is_local`, `is_private`, `is_public` |
| `ConfigFile` | Config | `path`, `client`, `server_count` |
| `InstructionFile` | Config | `path`, `type` (agents.md/claude.md/cursorrules/copilot-instructions/memory.md), `hash`, `is_suspicious` |
| `OllamaInstance` | Network scan + Ollama fingerprinter | `endpoint`, `version`, `auth_method=none`, `is_anonymous_loot=true`, `discovered_via` |
| `VLLMInstance` | Network scan + vLLM fingerprinter (v0.3) | `endpoint`, `version`, `auth_method`, `is_anonymous_loot` |
| `QdrantInstance` | Network scan + Qdrant fingerprinter (v0.4) | `endpoint`, `version`, `collection_count` |
| `MLflowServer` | Network scan + MLflow fingerprinter (v0.4) | `endpoint`, `version`, `experiment_count` |
| `LiteLLMGateway` | Network scan + LiteLLM fingerprinter | `endpoint`, `auth_method=master_key`, `is_anonymous_loot=false`, `docs_enabled` |
| `JupyterServer` | Network scan + Jupyter fingerprinter (v0.3) | `endpoint`, `version`, `token_required` |
| `LangServeApp` | Network scan + LangServe fingerprinter (v0.4) | `endpoint`, `chains` |
| `OpenWebUIInstance` | Network scan + Open WebUI fingerprinter (v0.3) | `endpoint`, `version`, `webui_auth_enabled` |
| `AIService` | Multi-label umbrella on every per-service node | (no unique constraint — see `sdk/ingest/UmbrellaLabels`) |
| `AIModel` | Ollama Looter (v0.3) — one per `/api/tags` entry | `name`, `digest`, `family`, `parameters`, `is_finetune`, `value_hash` (modelfile content), `modelfile_size_bytes`, `has_system_prompt`, optional `weight_artifact_path` (with `--include-weights`) |

**The `value_hash` property on `Credential` is load-bearing** — it's the cross-collector merge primitive that lets the `cross_service_credential_chain` post-processor join Config Collector emissions (`HAS_ENV_VAR` from MCP server to a credential) with LiteLLM Looter emissions (`EXPOSES_CREDENTIAL` from a LiteLLM gateway to its master + upstream provider keys). Same secret value → same `value_hash` → joined node, regardless of how each collector derives the `objectid`. Computed via `sdk/common.HashCredentialValue`. Every v0.3+ Looter MUST populate it on every emitted Credential.

The 2 synthetic labels (`ResourceGroup`, `TrustZone`) are populated by post-processors and live in `AllNodeLabels` but not `AllowedNodeKinds`.

### Node ID Strategy (deterministic, content-based SHA-256)

```
MCPServer:       SHA-256("MCPServer:" + transport + ":" + endpoint + ":" + sorted_args)
MCPTool:         SHA-256("MCPTool:" + server_id + ":" + tool_name)
MCPResource:     SHA-256("MCPResource:" + server_id + ":" + resource_uri)
A2AAgent:        SHA-256("A2AAgent:" + agent_card_url)
A2ASkill:        SHA-256("A2ASkill:" + agent_id + ":" + skill_id)
AgentInstance:   SHA-256("AgentInstance:" + config_file_id + ":" + client_name)
ConfigFile:      SHA-256("ConfigFile:" + absolute_path)
Host:            SHA-256("Host:" + hostname_or_ip)
```

**CRITICAL:** MCPServer ID MUST match between Config Collector and MCP Collector — this is the merge point that connects trust (who trusts what) to capabilities (what it exposes).

### Edge Types

**Directly collected (from collectors):**

| Edge | Source → Target | Collector |
|------|----------------|-----------|
| `TRUSTS_SERVER` | AgentInstance → MCPServer | Config |
| `PROVIDES_TOOL` | MCPServer → MCPTool | MCP |
| `PROVIDES_RESOURCE` | MCPServer → MCPResource | MCP |
| `PROVIDES_PROMPT` | MCPServer → MCPPrompt | MCP |
| `ADVERTISES_SKILL` | A2AAgent → A2ASkill | A2A |
| `DELEGATES_TO` | A2AAgent → A2AAgent | A2A |
| `AUTHENTICATES_WITH` | MCPServer/A2AAgent → Identity | Config/A2A |
| `USES_CREDENTIAL` | Identity → Credential | Config |
| `RUNS_ON` | MCPServer/A2AAgent → Host | Config/A2A |
| `CONFIGURED_IN` | MCPServer → ConfigFile | Config |
| `HAS_ENV_VAR` | MCPServer → Credential | Config |
| `LOADS_INSTRUCTIONS` | AgentInstance → InstructionFile | Config |
| `SAME_AUTH_DOMAIN` | A2AAgent → A2AAgent | A2A |
| `EXPOSES` | AIService → AIService | v0.3 fingerprinters (Open WebUI → Ollama backend) |
| `EXPOSES_CREDENTIAL` | AIService → Credential | LiteLLM Looter (gateway → master + upstream provider keys + virtual keys) |
| `PROVIDES_MODEL` | OllamaInstance → AIModel | v0.3 Ollama Looter (one edge per `/api/tags` entry) |

**Post-processed composite edges (computed from graph state):**

| Edge | Source → Target | Depends On | Key Detail |
|------|----------------|------------|------------|
| `HAS_ACCESS_TO` | MCPTool → MCPResource | Raw edges | Capability surface + URI scheme match |
| `CAN_EXECUTE` | MCPTool → Host | Raw edges | shell_access/code_execution capability |
| `SHADOWS` | MCPTool → MCPTool | Raw edges | Cross-server description reference |
| `POISONED_DESCRIPTION` | MCPTool → MCPTool (self) | Raw edges | Injection patterns detected |
| `CAN_REACH` | AgentInstance → MCPResource | HAS_ACCESS_TO | **THE critical edge** — transitive access. Also: credential chain variant (6 hops). |
| `CAN_EXFILTRATE_VIA` | AgentInstance → MCPTool | CAN_REACH | Agent reaches sensitive data AND outbound channel |
| `CAN_IMPERSONATE` | A2AAgent → A2AAgent | Raw edges | TF-IDF cosine similarity > 0.8 on skill descriptions |
| `POISONED_INSTRUCTIONS` | InstructionFile → InstructionFile (self) | Raw edges | Suspicious patterns in instruction files (imperative overrides, exfiltration commands, hidden Unicode) |
| Cross-protocol `CAN_REACH` | A2AAgent → MCPResource | HAS_ACCESS_TO + DELEGATES_TO | A2A→MCP boundary via host correlation. **What no other tool does.** |

**All edges carry:** `scan_id`, `last_seen`, `confidence` (0.0-1.0), `risk_weight`, `is_composite`, `evidence`. Composite edges also carry: `source_collector` (`'mcp'` or `'a2a'`) — used by stale edge cleanup to scope partial scan deletions.

**Post-processor execution order (dependencies):**
1. HAS_ACCESS_TO → 2. CAN_EXECUTE → 3. SHADOWS → 4. POISONED_DESCRIPTION → 5. POISONED_INSTRUCTIONS → 6. CAN_REACH (depends on 1) → 7. **cross_service_credential_chain** (depends on 1, 6 — joins on `Credential.value_hash` across Config Collector and LiteLLM Looter emissions) → 8. CAN_EXFILTRATE_VIA (depends on 6) → 9. CAN_IMPERSONATE → 10. Cross-protocol CAN_REACH (depends on 1) → 11. RiskScore (depends on 1-10)

## Three Collectors (now under `modules/`)

### Config Collector (`modules/config/`)
- **Parses** 12+ MCP client config formats (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Continue, Zed, Cline, JetBrains, Kiro, Amazon Q, Augment)
- **Key format differences:** VS Code uses `servers` key (not `mcpServers`). Windsurf uses `serverUrl` (not `url`). Zed uses `context_servers`. Cline has `autoApprove` array. Continue uses YAML.
- **Produces:** ConfigFile, AgentInstance, MCPServer, Identity, Credential, Host, InstructionFile nodes + all trust/auth edges
- **Detects:** Unpinned packages (`npx -y @pkg` without `@version`), high-entropy secrets (Shannon entropy >4.5 base64, >3.0 hex), credential patterns, instruction file poisoning
- **Parser architecture:** `ConfigParser` interface per client — `ClientName()`, `ConfigPaths()`, `Parse(path, data)`

### MCP Collector (`modules/mcp/`)
- **Wraps** official Go MCP SDK. Connection: `mcp.NewClient()` → `client.Connect(ctx, transport, nil)` → auto-paginating `session.Tools(ctx, nil)`
- **Enumerates:** tools/list, resources/list, resources/templates/list, prompts/list. NEVER calls tools/call or resources/read.
- **Transports:** stdio (`mcp.CommandTransport{Command: cmd}`, env via `cmd.Env`) and Streamable HTTP (`mcp.StreamableClientTransport{Endpoint: url}`). Falls back to legacy SSE on 400/404/405.
- **Security signals per tool:** description_hash (SHA-256 canonical JSON), injection patterns, cross-references, capability_surface classification (8 categories: shell_access, file_read, file_write, network_outbound, database_access, email_send, code_execution, credential_access), annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint — all untrusted hints)
- **Parallel:** goroutines with configurable concurrency, 120s total timeout per server, 30s init timeout, 100-page pagination safety valve
- **TLS:** strict by default. `--insecure` opts into `InsecureSkipVerify`. Regression test in `modules/mcp/transport_test.go` asserts strict default.

### A2A Collector (`modules/a2a/`)
- **Pure HTTP client** — GET `/.well-known/agent-card.json` (v0.3.0+), fallback `/.well-known/agent.json` (legacy)
- **Version detection:** `supportedInterfaces` present → v1.0, top-level `url` → v0.3.0
- **Handles both v0.3.0 and v1.0 Agent Card formats.** v1.0 moves `url` into `supportedInterfaces[].url`, removes top-level `protocolVersion`.
- **JWS signature verification** (RFC 7515) when `signatures` field present. Unsigned = flagged.
- **Auth posture scoring:** none=100, apiKey=70, bearer=50, oauth=25, oidc=20, mTLS=10
- **Produces:** A2AAgent, A2ASkill, Host nodes + ADVERTISES_SKILL, DELEGATES_TO, SAME_AUTH_DOMAIN, RUNS_ON edges
- **TLS:** strict by default. `--insecure` opts into `InsecureSkipVerify`. Regression test in `modules/a2a/fetch_test.go` asserts strict default.

## Ingest Format

All collectors output the same JSON schema (the wire contract lives in `sdk/ingest/`):

```json
{
  "meta": { "version": 1, "type": "agenthound-ingest", "collector": "mcp|a2a|config|scan", "collector_version": "0.1.0", "timestamp": "ISO8601", "scan_id": "scan-xxx" },
  "graph": {
    "nodes": [{ "id": "sha256:...", "kinds": ["MCPServer"], "properties": {...} }],
    "edges": [{ "source": "sha256:...", "target": "sha256:...", "kind": "PROVIDES_TOOL", "properties": {...} }]
  }
}
```

**Merge strategy:** MERGE by `objectid`. Same MCPServer node from Config + MCP collectors merges properties (last-write-wins). `ON MATCH SET n.previous_description_hash = n.description_hash` preserves old hash for rug pull detection.

**Normalizer:** camelCase → snake_case property keys. Timestamps → ISO 8601 UTC. Ensure `objectid` matches node `id`.

## Risk Scoring

**Edge risk weights (lower = easier to exploit):**
- TRUSTS_SERVER: none=0.1, static_key=0.3, oauth=0.7, mtls=0.9
- PROVIDES_TOOL: 0.1 (always available)
- HAS_ACCESS_TO: 0.2
- CAN_EXECUTE: 0.1
- DELEGATES_TO: none=0.1, authed=0.5
- SHADOWS: 0.4
- CAN_IMPERSONATE: 0.6

**Node risk scores (0-100):**
- Agent: 0.30×credential + 0.25×blast_radius + 0.20×auth_posture + 0.15×tool_surface + 0.10×poisoning
- Server: 0.35×auth_strength + 0.25×tool_risk + 0.20×exposure + 0.20×credential_handling
- Tool: 0.30×capability_class + 0.25×poisoning + 0.25×access_sensitivity + 0.20×input_validation

**Resource sensitivity auto-classification:** postgres/mysql/mongodb+prod → critical, file:///etc/ → critical, *.env/*.key/*.pem → critical, redis+prod → critical, DB non-prod → high, file:/// general → medium

## API Endpoints (server)

Single-user posture: network scope (127.0.0.1 by default) is the primary security boundary.
Mutating endpoints additionally require a localhost Bearer token to defeat browser drive-by attacks.

The token is auto-generated at first server startup, persisted to `~/.agenthound/server.token`
(0o600), and reused on subsequent restarts. The path is configurable via `AGENTHOUND_TOKEN_PATH`
or `XDG_CONFIG_HOME`. The embedded UI fetches it from `GET /api/v1/auth/local-token` on first
load. CLI tools (`agenthound-server ingest`, `query`) bypass HTTP entirely and don't need
the token.

CORS uses `AllowCredentials: false` — the server has no credentials to send anyway, and this
prevents a hostile origin from reading the token endpoint via a credentialed fetch.

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/v1/health` | GET | open | Neo4j + PG connectivity |
| `/api/v1/auth/local-token` | GET | open | UI token bootstrap (same-origin via CORS) |
| `/api/v1/graph/stats` | GET | open | Node/edge counts by kind |
| `/api/v1/graph/search` | GET | open | Free-text node search |
| `/api/v1/graph/nodes` | GET | open | List nodes (filter: kind, limit) |
| `/api/v1/graph/nodes/{id}` | GET | open | Node + connected edges |
| `/api/v1/graph/nodes/{id}/neighborhood` | GET | open | N-hop neighborhood |
| `/api/v1/graph/nodes/{id}/blast-radius` | GET | open | Reachable subgraph by ring |
| `/api/v1/graph/edges` | GET | open | List edges (filter: kind, source, target) |
| `/api/v1/ingest` | POST | **token** | Upload collector JSON → pipeline → post-process |
| `/api/v1/query` | POST | **token** | Raw Cypher |
| `/api/v1/analysis/shortest-path` | POST | **token** | `{source, target, max_hops, algorithm}` |
| `/api/v1/analysis/all-paths` | POST | **token** | Bounded path enumeration |
| `/api/v1/analysis/weighted-path` | POST | **token** | Dijkstra via APOC |
| `/api/v1/analysis/findings` | GET | open | All composite edges as findings with severity |
| `/api/v1/analysis/findings/{id}` | GET | open | Finding evidence detail |
| `/api/v1/analysis/prebuilt` | GET | open | List of 17 pre-built queries |
| `/api/v1/analysis/prebuilt/{id}` | GET | open | Run pre-built query |
| `/api/v1/scans` | GET | open | List scan history |
| `/api/v1/scans` | POST | **token** | Register a new scan |
| `/api/v1/scans/{id}` | GET | open | Scan status |
| `/api/v1/scans/{id}` | DELETE | **token** | Delete scan (and owned edges/nodes) |
| `/api/v1/rules` | GET | open | List active detection rules |
| `/api/v1/rules/{id}` | GET | open | Rule definition |
| `/api/v1/docs` | GET | open | OpenAPI 3.0 spec (YAML) |

The OpenAPI spec at `server/internal/api/handlers/openapi.yaml` declares a `LocalhostToken`
security scheme on the gated endpoints; routes and spec are kept in sync (verified by
`diff` in CI).

There is intentionally no JWT, no bcrypt-password user store, no RBAC, and no rate limiting.
See `docs/adr/0001-two-binary-split.md` and `docs/security.md`.

### Test fixtures and AV-bait scrubbing

Detection-rule YAML test fixtures (`sdk/rules/builtin_tests/<id>.yaml`) live OUTSIDE the
runtime `//go:embed builtin` path. Strings like `"https://attacker.io/steal?secret=..."`
exist only in source for unit tests; they never ship in the runtime binary, so EDRs
don't see them. Production rules are read from `sdk/rules/builtin/*.yaml` which contain
no `tests:` blocks.

## CLI Commands

### Collector

```bash
agenthound scan                                    # Discover + enumerate; writes ./scan-<scan_id>.json in CWD
agenthound scan --config                           # Config files only (offline)
agenthound scan --mcp --url <url>                  # Single HTTP MCP server
agenthound scan --a2a --target <url>               # Single A2A agent
agenthound scan --a2a --discover-domain <domain>   # Probe well-known agent-card
agenthound scan --output scan.json                 # Explicit file path
agenthound scan --output -                         # Stream JSON to stdout (use with a pipe)
agenthound rules list|validate|test                # YAML rules engine ops
agenthound version
```

Stub verbs (`agenthound loot|extract|poison|implant`) print "not yet implemented — see docs/future-modules.md" and exit 1. They reserve the verb space without implementing anything.

Persistent flags: `--log-level`, `--output`, `--concurrency`, `--quiet`, `--log-json`.

### Server

```bash
agenthound-server serve                          # Start API server on 127.0.0.1:8080
agenthound-server ingest <file.json>             # Ingest collector output → Neo4j + post-process
agenthound-server ingest -                       # Read collector output from stdin
agenthound-server query "<cypher>"               # Execute raw Cypher
agenthound-server query --prebuilt <query-id>    # Run pre-built query
agenthound-server query --findings --severity critical
agenthound-server version
```

The UI also exposes a drag-drop import at `Scan Manager → Import scan`, which POSTs the file to `/api/v1/ingest` (same pipeline as the CLI).

## Implementation Phases (historical)

Phases 1–5 of the original PRD shipped as the single-binary AgentHound. The two-binary split landed afterwards as a 7-step refactor recorded in commits `0531456` through this commit.

## Key Implementation Constraints

1. **Neo4j version compat:** Schema init must detect version via `CALL dbms.components()` and use 4.4 (`ON...ASSERT`) or 5.x (`FOR...REQUIRE`) syntax.
2. **APOC fallback:** All APOC-dependent code needs non-APOC fallbacks. APOC only required for Dijkstra. Node writes: group by kind, run separate MERGE per kind. Edge writes: `edgeKindCypher` map with per-kind Cypher strings.
3. **Property keys:** Neo4j is case-sensitive. All properties stored as snake_case. Normalizer converts camelCase from collector JSON.
4. **Batch writes:** 1000 operations per Neo4j transaction. Use `UNWIND $nodes AS node` pattern.
5. **go:embed constraint:** Go forbids `..` in embed paths. Makefile copies `server/ui/dist` → `server/internal/api/ui/dist` before `go build`.
6. **MCP SDK:** `mcp.CommandTransport` env vars set on `exec.Cmd.Env`, not on transport. `client.Connect()` handles full init handshake. Auto-paginating iterators handle `NextCursor`.
7. **A2A version detection:** `supportedInterfaces` → v1.0, top-level `url` → v0.3.0. Must handle both.
8. **Credential safety:** Config Collector hashes credential values by default (SHA-256). `--include-credential-values` for audit mode.
9. **Stale edge cleanup:** Only delete composite edges whose source collector ran in current scan. Prevents ping-pong on partial scans.
10. **Output file safety:** Atomic temp+rename; chmod 0o600 on POSIX. NTFS does not honor POSIX mode bits — see `docs/security.md`.
11. **TLS strict default:** Both MCP and A2A modules verify certs by default. Regression tests assert this; do not weaken.
12. **Deps boundary:** The collector binary MUST NOT link `chi`, `pgx`, `neo4j-go-driver`, or any `server/internal/`. Enforced by `scripts/deps-check.sh`.
13. **Single-user posture:** Server has no authentication at the application layer. The 127.0.0.1 default bind is the security control. Do not introduce auth without an ADR.

## OWASP Coverage

AgentHound maps all findings to OWASP MCP Top 10 (MCP01-MCP10) and OWASP Agentic Top 10 (ASI01-ASI10). Full/partial coverage documented in `docs/detection-rules.md`.

## Pre-Built Queries (18)

| ID | Category |
|----|----------|
| `agents-shell-access` | Critical Paths |
| `shortest-to-database` | Critical Paths |
| `cross-protocol-paths` | Critical Paths |
| `exfiltration-routes` | Critical Paths |
| `credential-chain` | Critical Paths |
| `litellm-credential-leak` | Critical Paths |
| `poisoned-tools` | Vulnerabilities |
| `tool-shadowing` | Vulnerabilities |
| `no-auth-servers` | Vulnerabilities |
| `no-auth-a2a` | Vulnerabilities |
| `rug-pull` | Vulnerabilities |
| `unpinned-packages` | Supply Chain |
| `instruction-poisoning` | Supply Chain |
| `unsigned-cards` | Supply Chain |
| `high-entropy-secrets` | Supply Chain |
| `chokepoint-servers` | Chokepoints |
| `chokepoint-tools` | Chokepoints |
| `unpinned-shell` | Combined |

## Node Visual Encoding (Frontend)

| Kind | Color | Size Basis |
|------|-------|-----------|
| AgentInstance | `#4A90D9` blue | risk_score |
| MCPServer | `#50C878` green | tool count |
| MCPTool | `#F5A623` orange | capability risk |
| MCPResource | `#D0021B` red | sensitivity |
| A2AAgent | `#7B68EE` purple | skill count |
| A2ASkill | `#9B59B6` light purple | fixed |
| Identity | `#8E8E93` gray | fixed |
| Credential | `#FF6B6B` warning red | exposure risk |
| ConfigFile | `#95A5A6` silver | server count |
| Host | `#2C3E50` dark | fixed |

## Config Defaults

```
# Collector
AGENTHOUND_OUTPUT=                                    # File path. Use '-' for stdout. Defaults to ./scan-<scan_id>.json in CWD.
AGENTHOUND_LOG_LEVEL=info
AGENTHOUND_CONCURRENCY=5
AGENTHOUND_QUIET=                                     # 1 = error-level only
AGENTHOUND_LOG_JSON=                                  # 1 = JSON handler instead of text

# Server
AGENTHOUND_NEO4J_URI=bolt://localhost:7687
AGENTHOUND_NEO4J_USER=neo4j
AGENTHOUND_NEO4J_PASSWORD=agenthound
AGENTHOUND_PG_URI=postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable
AGENTHOUND_BIND=127.0.0.1:8080
AGENTHOUND_LOG_LEVEL=info
AGENTHOUND_CORS_ORIGINS=http://localhost:8080
```

## Reference Docs (in repo)

| Path | Content |
|------|---------|
| `docs/adr/0001-two-binary-split.md` | ADR for the collector/server split |
| `docs/security.md` | Threat model and operator OPSEC |
| `docs/future-modules.md` | Deferred surface and planning notes (action interfaces, template signing, redaction) |
| `docs/quickstart.md` | 5-minute setup |
| `docs/cli-reference.md` | All CLI commands |
| `docs/api-reference.md` | REST API endpoints |
| `docs/graph-model.md` | Node/edge types, ID strategy, risk scoring |
| `docs/detection-rules.md` | All 17 detections with OWASP mappings |
| `docs/architecture.md` | Architecture for contributors |
| `collectors/01-mcp-collector.md` | MCP collector spec + Go SDK usage |
| `collectors/02-a2a-collector.md` | A2A collector spec + card schema |
| `collectors/03-config-collector.md` | Config collector spec + 12 client formats |
| `collectors/04-graph-pipeline.md` | Full ingest → post-process → query pipeline |
| `collectors/05-visual-architecture.md` | Mermaid diagrams of the graph |
| `collectors/06-ui-scenarios.md` | UI graph rendering scenarios |
| `research/mcp-spec-2025-11-25.md` | MCP protocol reference (JSON-RPC, transports, OAuth, Tasks) |
