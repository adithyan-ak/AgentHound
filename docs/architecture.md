# Architecture Overview

AgentHound enumerates MCP servers and A2A agents, builds a directed trust graph in Neo4j, and uses shortest-path algorithms to discover attack paths across protocol boundaries.

## Components

```
                         +---------------------------+
                         |      CLI (cobra)          |
                         |  collect | ingest | query |
                         +------------+--------------+
                                      |
                         +------------v--------------+
                         |    API Server (chi/v5)    |
                         |      /api/v1/*            |
                         |  +--------------------+   |
                         |  | Embedded React SPA |   |
                         |  | (go:embed ui/dist) |   |
                         +--+----+----------+----+---+
                              |  |          |
               +--------------+  |          +--------------+
               v                 v                         v
    +----------+---+   +---------+--------+   +------------+----+
    | Neo4j 4.4+   |   | Ingest Pipeline  |   | PostgreSQL 16   |
    | Graph DB     |   | validate/norm/   |   | users, scans,   |
    | (Cypher,     |   | dedup/write/     |   | audit_log,      |
    | APOC)        |   | post-process     |   | api_tokens      |
    +--------------+   +------------------+   +-----------------+
```

The Go binary ships as a single artifact. The React SPA is built by Vite, copied into
`internal/api/ui/dist/`, and embedded at compile time via `go:embed`.

## Data Flow

```
collect config --discover       collect mcp --discover       collect a2a --target <url>
        |                               |                               |
        v                               v                               v
  Parse 12 client configs      Connect via Go MCP SDK         HTTP GET agent cards
  (no network required)        (stdio / Streamable HTTP)      (JWS signature verify)
        |                               |                               |
        +---------------+---------------+-------------------------------+
                        |
                        v
              Unified ingest JSON
              (BloodHound OpenGraph-aligned)
                        |
                        v
         +------------------------------+
         |       Ingest Pipeline        |
         |  1. Schema validation        |
         |  2. Normalize (snake_case)   |
         |  3. Deduplicate (MERGE)      |
         |  4. Batch write to Neo4j     |
         |  5. Post-process (9 stages)  |
         |  6. Risk scoring             |
         +------------------------------+
                        |
                        v
              Query / Pathfinding
              (Cypher, APOC Dijkstra,
               17 pre-built queries)
```

## Graph Data Model

**Core direction:** `Agent -> Server -> Tool -> Resource`. Edges represent exploitable relationships.

### Node Types (14 total)

| Label | Source | Description |
|-------|--------|-------------|
| MCPServer | Config + MCP | Server endpoint, transport, auth, capabilities |
| MCPTool | MCP | Tool with capability surface, injection signals |
| MCPResource | MCP | URI-addressable resource with sensitivity level |
| MCPPrompt | MCP | Prompt template with arguments |
| A2AAgent | A2A | Agent card: skills, auth, delegation, signature |
| A2ASkill | A2A | Individual skill with input/output modes |
| AgentInstance | Config | Client instance (Claude, Cursor, etc.) |
| Identity | Config + MCP | Auth identity (none/apiKey/oauth/bearer/mtls) |
| Credential | Config | Credential reference with entropy analysis |
| Host | Config + A2A | Hostname or IP with network classification |
| ConfigFile | Config | Parsed configuration file |
| InstructionFile | Config | Agent instruction file with poisoning signals |
| ResourceGroup | Post-processor | Synthetic: groups resources by sensitivity |
| TrustZone | Post-processor | Synthetic: groups nodes by trust level |

Node IDs are deterministic SHA-256 hashes of `Kind:` + identifying properties. MCPServer IDs
match across Config and MCP collectors -- this is the merge point connecting trust to capabilities.

### Edge Types (21 total)

**13 raw edges** (from collectors): TRUSTS_SERVER, PROVIDES_TOOL, PROVIDES_RESOURCE,
PROVIDES_PROMPT, ADVERTISES_SKILL, DELEGATES_TO, AUTHENTICATES_WITH, USES_CREDENTIAL,
RUNS_ON, CONFIGURED_IN, HAS_ENV_VAR, LOADS_INSTRUCTIONS, SAME_AUTH_DOMAIN.

**8 composite edges** (computed by post-processors in dependency order):

| # | Edge | Meaning |
|---|------|---------|
| 1 | HAS_ACCESS_TO | Tool can reach a resource (capability + URI match) |
| 2 | CAN_EXECUTE | Tool can execute commands on a host |
| 3 | SHADOWS | Tool mimics another tool's description cross-server |
| 4 | POISONED_DESCRIPTION | Tool description contains injection patterns |
| 5 | CAN_REACH | Agent has transitive access to a resource |
| 6 | CAN_EXFILTRATE_VIA | Agent can reach sensitive data + outbound channel |
| 7 | CAN_IMPERSONATE | A2A agent mimics another (TF-IDF cosine > 0.8) |
| 8 | Cross-protocol CAN_REACH | A2A agent reaches MCP resources via host correlation |

All edges carry: `scan_id`, `last_seen`, `confidence`, `risk_weight`, `is_composite`, `evidence`.

## Three Collectors

| Collector | Network | Input | Output Nodes | Key Signals |
|-----------|---------|-------|-------------|-------------|
| **Config** | None | 12 MCP client config formats (Claude Desktop, Cursor, VS Code, Windsurf, Zed, Cline, Continue, JetBrains, Kiro, Amazon Q, Augment, Claude Code) | ConfigFile, AgentInstance, MCPServer, Identity, Credential, Host, InstructionFile | Unpinned packages, high-entropy secrets, instruction poisoning |
| **MCP** | stdio / HTTP | Live MCP servers via Go SDK v1.5.0 | MCPServer, MCPTool, MCPResource, MCPPrompt | Capability surface (8 categories), injection patterns, description hashes, cross-references |
| **A2A** | HTTP | Agent Card JSON (v0.3.0 + v1.0) | A2AAgent, A2ASkill, Host | JWS signature verification, auth posture scoring, delegation chains |

All collectors produce the same JSON ingest format. The Config and MCP collectors share
MCPServer node IDs so their outputs merge cleanly on ingest.

## Security Model

| Layer | Implementation |
|-------|---------------|
| Authentication | bcrypt password hashing, JWT (HMAC-SHA256, 24h expiry), API tokens (`ah_` prefix) |
| Authorization | RBAC with three roles: **admin** (full access + raw Cypher), **analyst** (read + analysis), **viewer** (read-only) |
| Audit | All mutating actions logged to `audit_log` table (actor, action, resource, timestamp) |
| Credential safety | Config Collector hashes credential values by default (SHA-256). `--include-credential-values` for audit mode. |

## Deployment

Docker Compose runs three containers:

| Container | Image | Purpose | Default Port |
|-----------|-------|---------|-------------|
| graph-db | neo4j:4.4-community | Graph storage, Cypher queries, APOC pathfinding | 7687 (bolt), 7474 (browser) |
| app-db | postgres:16-alpine | Users, scans, audit log, API tokens | 5432 |
| agenthound | golang:1.25-alpine (multi-stage) | API server + embedded UI | 8080 |

```bash
docker compose -f docker/docker-compose.yml up -d
```

Configuration is env-based: `AGENTHOUND_NEO4J_URI`, `AGENTHOUND_PG_URI`, `AGENTHOUND_API_PORT`.
