<p align="center">
  <h1 align="center">AgentHound</h1>
  <p align="center"><strong>Attack path discovery for AI agent infrastructure</strong></p>
  <p align="center">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
    <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.25+-00ADD8.svg" alt="Go"></a>
    <a href="https://neo4j.com"><img src="https://img.shields.io/badge/Neo4j-4.4+-008CC1.svg" alt="Neo4j"></a>
    <a href="https://github.com/adithyan-ak/agenthound/actions"><img src="https://img.shields.io/github/actions/workflow/status/adithyan-ak/agenthound/ci.yml?branch=main&label=CI" alt="CI"></a>
  </p>
</p>

AgentHound enumerates MCP servers and A2A agents, builds a directed trust graph in Neo4j, and uses shortest-path algorithms to discover attack paths across protocol boundaries.

It is the first open-source tool to perform **cross-protocol graph-based attack path analysis** for AI agent infrastructure -- finding paths like `A2A Agent -> MCP Server -> Shell Tool -> Host` that no single-protocol scanner can see.

Think [BloodHound](https://github.com/BloodHoundAD/BloodHound), but for MCP and A2A.

---

## What It Finds

AgentHound discovers security issues across your AI agent infrastructure, mapped to [OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and [OWASP Agentic Top 10](https://genai.owasp.org/):

| Finding | Severity | What It Means |
|---------|----------|---------------|
| Shell access paths | Critical | An agent can reach tools with arbitrary command execution |
| Database access paths | Critical | An agent can reach production database resources |
| Data exfiltration routes | Critical | An agent can read sensitive data AND send it outbound |
| Cross-protocol attack paths | Critical | An A2A agent can pivot through host co-location to reach MCP resources |
| Credential chain paths | Critical | Multi-hop paths that traverse shared credential boundaries |
| Tool poisoning | High | Tool descriptions contain prompt injection patterns |
| Tool shadowing | High | A malicious tool mimics a legitimate tool to hijack actions |
| Rug pull detection | High | A tool's description changed between scans (supply chain attack) |
| Unauthenticated servers/agents | High | MCP servers or A2A agents with no authentication |
| Instruction file poisoning | High | Agent instruction files contain exfiltration or override patterns |
| Hardcoded secrets | High | High-entropy strings (API keys) in config files |
| Unpinned packages | Medium | `npx -y @pkg` without version pin -- supply chain risk |
| Unsigned agent cards | Medium | A2A agents without JWS signatures |

All 17 findings are available as pre-built queries from the CLI and UI.

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- [Go 1.25+](https://go.dev/dl/) (for building from source)

### 1. Start the infrastructure

```bash
git clone https://github.com/adithyan-ak/agenthound.git
cd agenthound
docker compose -f docker/docker-compose.yml up -d
```

This starts Neo4j (graph database), PostgreSQL (application database), and the AgentHound server on port 8080.

### 2. Build from source

```bash
make build
# Binary at bin/agenthound
```

Or install directly:

```bash
go install github.com/adithyan-ak/agenthound/cmd/agenthound@latest
```

### 3. Scan your infrastructure

```bash
# Discover all MCP client configs (Claude Desktop, Cursor, VS Code, etc.)
agenthound collect config --discover --ingest

# Connect to each server and enumerate tools, resources, prompts
agenthound collect mcp --discover --ingest

# (Optional) Scan A2A agents
agenthound collect a2a --target https://agent.example.com --ingest
```

### 4. Find attack paths

```bash
# Open the web UI
open http://localhost:8080
# Login: admin / agenthound

# Or query from the CLI
agenthound query --findings --severity critical
```

---

## How It Works

```
  Config Collector          MCP Collector           A2A Collector
  (12 client parsers)      (Go SDK, stdio/HTTP)    (HTTP + JWS verify)
        |                        |                        |
        v                        v                        v
  +-------------------------------------------------------------------+
  |                      Ingest Pipeline                               |
  |  validate --> normalize --> deduplicate --> write --> post-process  |
  +-------------------------------------------------------------------+
                                 |
                    +------------+------------+
                    |                         |
               +---------+           +-------------+
               |  Neo4j  |           | PostgreSQL  |
               | (graph) |           | (app state) |
               +---------+           +-------------+
                    |
         +----------+----------+
         |                     |
    +---------+         +-------------+
    | REST API|         |   React UI  |
    | (chi)   |         | (Sigma.js)  |
    +---------+         +-------------+
```

**Three collectors** enumerate your AI agent infrastructure and produce standardized JSON. The **ingest pipeline** validates, normalizes, and writes nodes/edges to Neo4j, then runs **9 post-processors** that compute composite attack paths (`CAN_REACH`, `CAN_EXFILTRATE_VIA`, `SHADOWS`, etc.) and risk scores. The **REST API** and **React UI** let you explore the graph, run pathfinding, and investigate findings.

### The Graph

AgentHound builds a directed trust graph with **14 node types** and **23 edge types**:

- **Nodes:** `AgentInstance`, `MCPServer`, `MCPTool`, `MCPResource`, `MCPPrompt`, `A2AAgent`, `A2ASkill`, `Identity`, `Credential`, `Host`, `ConfigFile`, `InstructionFile`, `ResourceGroup`, `TrustZone`
- **Direct edges (13):** `TRUSTS_SERVER`, `PROVIDES_TOOL`, `PROVIDES_RESOURCE`, `AUTHENTICATES_WITH`, `RUNS_ON`, `DELEGATES_TO`, etc.
- **Computed edges (10):** `HAS_ACCESS_TO`, `CAN_EXECUTE`, `CAN_REACH`, `CAN_EXFILTRATE_VIA`, `SHADOWS`, `POISONED_DESCRIPTION`, `CAN_IMPERSONATE`, cross-protocol `CAN_REACH`, `POISONED_INSTRUCTIONS`, plus risk scores

Node IDs are deterministic SHA-256 hashes, enabling cross-collector merge: the same `MCPServer` discovered by Config Collector and MCP Collector merges into a single node.

### Risk Scoring

Every node gets a risk score (0--100) based on weighted factors:

- **Agents:** credential handling, blast radius, auth posture, tool surface, poisoning exposure
- **Servers:** auth strength, tool risk, network exposure, credential handling
- **Tools:** capability class, poisoning indicators, access sensitivity, input validation

---

## Collectors

### Config Collector

Parses MCP client configuration files -- no network access required. Discovers trust relationships, credentials, and instruction files.

```bash
agenthound collect config --discover                    # Auto-discover all configs
agenthound collect config --path ~/.cursor/mcp.json     # Single file
agenthound collect config --discover --output scan.json  # Save to file
agenthound collect config --discover --ingest            # Write directly to graph
```

**Supported clients (12):** Claude Desktop, Claude Code, Cursor, VS Code (Copilot), Windsurf, Continue, Zed, Cline, JetBrains, Kiro, Amazon Q, Augment

**Detects:** Unpinned packages, hardcoded secrets (Shannon entropy analysis), instruction file poisoning (imperative overrides, exfiltration commands, hidden Unicode)

### MCP Collector

Connects to MCP servers via the [official Go SDK](https://github.com/modelcontextprotocol/go-sdk) and enumerates capabilities. Read-only -- never calls `tools/call` or `resources/read`.

```bash
agenthound collect mcp --discover                       # All servers from configs
agenthound collect mcp --config ~/.cursor/mcp.json      # Servers from one config
agenthound collect mcp --url https://mcp.example.com    # Single HTTP server
```

**Enumerates:** `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`

**Transports:** stdio (launches server process) and Streamable HTTP (with legacy SSE fallback)

**Per-tool analysis:** description hashing (rug pull detection), injection pattern scanning, cross-reference detection, capability surface classification (shell_access, file_read, file_write, network_outbound, database_access, email_send, code_execution, credential_access)

### A2A Collector

Fetches [A2A Agent Cards](https://google.github.io/A2A/) via HTTP and analyzes agent security posture.

```bash
agenthound collect a2a --target https://agent.example.com
agenthound collect a2a --targets url1,url2,url3
agenthound collect a2a --discover-domain example.com      # Probe well-known path
agenthound collect a2a --targets-file agents.txt
```

**Supports:** A2A v1.0 and v0.3.0 Agent Card formats with automatic version detection

**Security analysis:** JWS signature verification (RS256/ES256), auth posture scoring (none=100 ... mTLS=10), unsigned card flagging, delegation chain mapping

---

## CLI Reference

### Scan management

```bash
agenthound serve                          # Start API server + UI on :8080
agenthound serve --port 9090              # Custom port
```

### Ingestion

```bash
agenthound ingest scan.json               # Ingest collector output file
```

The pipeline validates, normalizes (camelCase to snake_case), deduplicates by node ID, batch-writes to Neo4j, then runs all 9 post-processors to compute attack paths and risk scores.

### Querying

```bash
# Security findings
agenthound query --findings
agenthound query --findings --severity critical

# Pre-built queries (17 available)
agenthound query --prebuilt agents-shell-access
agenthound query --prebuilt cross-protocol-paths
agenthound query --prebuilt exfiltration-routes
agenthound query --prebuilt poisoned-tools
agenthound query --prebuilt unpinned-shell

# Shortest path between nodes
agenthound query --shortest-path \
  --from AgentInstance:claude-desktop \
  --to MCPResource:postgres://prod

# Raw Cypher
agenthound query "MATCH (a:AgentInstance)-[:CAN_REACH]->(r:MCPResource) RETURN a.name, r.uri"

# Output as JSON
agenthound query --findings --format json
```

### Pre-built Queries

| ID | Category | Severity |
|----|----------|----------|
| `agents-shell-access` | Critical Paths | Critical |
| `shortest-to-database` | Critical Paths | Critical |
| `cross-protocol-paths` | Critical Paths | Critical |
| `exfiltration-routes` | Critical Paths | Critical |
| `credential-chain` | Critical Paths | Critical |
| `unpinned-shell` | Combined | Critical |
| `poisoned-tools` | Vulnerabilities | High |
| `tool-shadowing` | Vulnerabilities | High |
| `no-auth-servers` | Vulnerabilities | High |
| `no-auth-a2a` | Vulnerabilities | High |
| `rug-pull` | Vulnerabilities | High |
| `instruction-poisoning` | Supply Chain | High |
| `high-entropy-secrets` | Supply Chain | High |
| `unpinned-packages` | Supply Chain | Medium |
| `unsigned-cards` | Supply Chain | Medium |
| `chokepoint-servers` | Chokepoints | Medium |
| `chokepoint-tools` | Chokepoints | Medium |

---

## Web UI

The embedded React UI provides five main views:

- **Dashboard** -- node/edge counts, risk distribution, top findings, auth coverage stats
- **Graph Explorer** -- interactive Sigma.js visualization (handles 100K+ nodes), click to inspect, filter by node type
- **Pathfinder** -- find shortest, all, or weighted (Dijkstra) paths between any two nodes with highlighted path overlay
- **Entity Inspector** -- detailed view of any node's properties, connections, and risk score breakdown
- **Query Library** -- run any of the 17 pre-built queries with results table
- **Scan Manager** -- view scan history, trigger new scans

Access at `http://localhost:8080` after starting the server. Default credentials: `admin` / `agenthound`.

---

## REST API

All endpoints are under `/api/v1`. Authentication via JWT (from login) or API token (`ah_` prefix).

Full machine-readable spec available at `GET /api/v1/docs` (OpenAPI 3.0).

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | None | Service health check |
| `/auth/login` | POST | None | Login, returns JWT |
| `/graph/stats` | GET | Viewer+ | Node/edge counts by kind |
| `/graph/nodes` | GET | Viewer+ | List/filter nodes |
| `/graph/nodes/{id}` | GET | Viewer+ | Node detail + connections |
| `/graph/edges` | GET | Viewer+ | List/filter edges |
| `/analysis/findings` | GET | Viewer+ | All findings with severity |
| `/analysis/prebuilt` | GET | Viewer+ | List pre-built queries |
| `/analysis/prebuilt/{id}` | GET | Viewer+ | Run pre-built query |
| `/analysis/shortest-path` | POST | Analyst+ | Shortest path query |
| `/analysis/all-paths` | POST | Analyst+ | Bounded path enumeration |
| `/analysis/weighted-path` | POST | Analyst+ | Dijkstra via APOC |
| `/ingest` | POST | Analyst+ | Upload collector JSON |
| `/scans` | GET/POST | Varies | List/create scans |
| `/auth/tokens` | GET/POST | Analyst+ | Manage API tokens |
| `/auth/users` | GET/POST/DELETE | Admin | User management |
| `/query` | POST | Admin | Raw Cypher execution |
| `/audit` | GET | Admin | Audit log |

### API Tokens

For automation and CI/CD integration:

```bash
# Create a token (requires JWT auth first)
curl -X POST http://localhost:8080/api/v1/auth/tokens \
  -H "Authorization: Bearer $JWT" \
  -d '{"name": "ci-scanner"}'
# Returns: {"token": "ah_...", "id": "...", "name": "ci-scanner"}

# Use the token
curl http://localhost:8080/api/v1/analysis/findings \
  -H "Authorization: Bearer ah_..."
```

---

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTHOUND_NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection |
| `AGENTHOUND_NEO4J_USER` | `neo4j` | Neo4j username |
| `AGENTHOUND_NEO4J_PASSWORD` | `agenthound` | Neo4j password |
| `AGENTHOUND_PG_URI` | `postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable` | PostgreSQL connection |
| `AGENTHOUND_API_PORT` | `8080` | API server port |
| `AGENTHOUND_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |
| `AGENTHOUND_JWT_SECRET` | *(auto-generated)* | JWT signing secret. Set this for stable sessions across restarts. |
| `AGENTHOUND_ADMIN_PASSWORD` | `agenthound` | Initial admin password. Change in production. |
| `AGENTHOUND_CORS_ORIGINS` | `http://localhost:8080` | Comma-separated allowed CORS origins |

---

## Deployment

### Docker Compose (recommended)

```bash
docker compose -f docker/docker-compose.yml up -d
```

Runs three containers: `graph-db` (Neo4j 4.4 Community + APOC), `app-db` (PostgreSQL 16), `agenthound` (API + UI). Database ports are bound to localhost only.

### Production considerations

```bash
# Set secrets via environment
export AGENTHOUND_JWT_SECRET=$(openssl rand -hex 32)
export AGENTHOUND_ADMIN_PASSWORD=$(openssl rand -base64 16)
export AGENTHOUND_NEO4J_PASSWORD=<strong-password>

# Update docker-compose.yml with your secrets, then:
docker compose -f docker/docker-compose.yml up -d
```

- Set `AGENTHOUND_JWT_SECRET` -- without it, sessions invalidate on container restart
- Change default passwords for admin, Neo4j, and PostgreSQL
- The container runs as non-root (UID 1001)
- Database ports are bound to `127.0.0.1` by default

### Pre-built binaries

Download from [GitHub Releases](https://github.com/adithyan-ak/agenthound/releases):

```bash
# Linux (amd64)
curl -L https://github.com/adithyan-ak/agenthound/releases/latest/download/agenthound-linux-amd64.tar.gz | tar xz

# macOS (Apple Silicon)
curl -L https://github.com/adithyan-ak/agenthound/releases/latest/download/agenthound-darwin-arm64.tar.gz | tar xz

# Run with external databases
./agenthound serve
```

Available for: Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64/arm64).

---

## Demo

Seed the graph with synthetic demo data that demonstrates all detection capabilities:

```bash
make demo
# or
bash scripts/seed-demo.sh
```

This ingests three pre-built scan files covering: critical attack paths, data exfiltration routes, cross-protocol pivots, tool poisoning, credential chains, unpinned packages, unsigned A2A agents, and instruction file poisoning.

---

## RBAC

Three roles with hierarchical permissions:

| Role | Permissions |
|------|-------------|
| **Viewer** | Read graph, view findings, run pre-built queries |
| **Analyst** | All viewer permissions + ingest data, create scans, manage own API tokens, run pathfinding |
| **Admin** | All permissions + raw Cypher, user management, audit log access |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Quickstart](docs/quickstart.md) | 5-minute setup guide with step-by-step instructions |
| [CLI Reference](docs/cli-reference.md) | All commands, flags, and usage examples |
| [API Reference](docs/api-reference.md) | REST API endpoints and request/response formats |
| [Graph Model](docs/graph-model.md) | Node types, edge types, ID strategy, risk scoring |
| [Detection Rules](docs/detection-rules.md) | All 17 detections with OWASP mappings |
| [Architecture](docs/architecture.md) | System architecture for contributors |
| [Contributing](CONTRIBUTING.md) | How to contribute collectors, detections, and queries |
| [Changelog](CHANGELOG.md) | Release notes |
| [Security](SECURITY.md) | Vulnerability reporting policy |

Machine-readable API spec: `GET /api/v1/docs` (OpenAPI 3.0)

---

## License

[Apache License 2.0](LICENSE)
