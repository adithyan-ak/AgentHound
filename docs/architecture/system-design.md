# Architecture Overview

AgentHound is an offensive security framework for AI agent infrastructure. It runs the full red-team lifecycle — recon, fingerprinting, credential looting, model and modelfile inventory, model inversion, tool/instruction poisoning, and config-implant persistence — then merges every fact into a Neo4j graph and computes the attack paths that tie it together. It ships as **two binaries** in the BloodHound/SharpHound mold: a lean field collector (`agenthound`) and a single-user analysis server (`agenthound-server`).

## Components

```
   +-----------------------+              +---------------------------------+
   |    agenthound         |  JSON file   |     agenthound-server           |
   |    (collector)        | -- or stdin->|     (single-user)               |
   |                       |  pipe / UI   |                                 |
   |  scan / discover /    |  drag-drop   |  serve / ingest / query         |
   |  loot / extract /     |              |  +---------------------------+  |
   |  poison / implant /   |              |  |    API Server (chi/v5)    |  |
   |  revert / campaign    |              |  | /api/v1/* — read=open,    |  |
   |  (+ rules)            |              |  |  mutate=Origin allowlist  |  |
   +-----------------------+              |  |  +---------------------+  |  |
                                          |  |  | Embedded React SPA  |  |  |
                                          |  |  | (go:embed)          |  |  |
                                          |  +--+----+----------+----+--+  |
                                          |       |  |          |          |
                                          |       v  v          v          |
                                          |   Neo4j  Ingest  PostgreSQL    |
                                          |   4.4+   pipe-   16            |
                                          |          line    (scans)       |
                                          +---------------------------------+
```

The collector binary contains zero database clients, no UI, and no chi router. It produces JSON conforming to `sdk/ingest`. The server binary embeds the React SPA built by Vite.

## Data Flow

```
scan --config         scan --mcp --url <url>           scan --a2a --target <url>
        |                               |                               |
        v                               v                               v
  Parse 12 client configs      Connect via Go MCP SDK         HTTP GET agent cards
  (no network required)        (stdio / Streamable HTTP)      (versioned conformance + v1 JWS)
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
         |  5. Post-process (15         |
         |     processors producing 12  |
         |     composite edge kinds,    |
         |     plus node risk scoring)  |
         +------------------------------+
                        |
                        v
              Query / Pathfinding
              (Cypher, bounded traversal,
               19 pre-built queries)
```

## Graph Data Model

**Core direction:** `Agent -> Server -> Tool -> Resource`. Edges represent exploitable relationships.

### Node Types (23 total)

| Label | Source | Description |
|-------|--------|-------------|
| MCPServer | Config + MCP | Server endpoint, transport, auth, capabilities |
| MCPTool | MCP | Tool with capability surface, injection signals |
| MCPResource | MCP | URI-addressable resource with sensitivity level |
| MCPPrompt | MCP | Prompt template with arguments |
| A2AAgent | A2A | Agent card: versioned conformance, ordered interfaces, OR-of-AND auth, delegation, signature validity/key trust |
| A2ASkill | A2A | Individual skill with input/output modes and independent conformance |
| AgentInstance | Config | Client instance (Claude, Cursor, etc.) |
| Identity | Config + A2A | Auth identity (none/apiKey/oauth/bearer/mtls) |
| Credential | Config + LiteLLM/Open WebUI Looters | Observed credential material or an explicitly masked/hashed reference |
| Host | Config + A2A + MCP | Hostname or IP with network classification |
| ConfigFile | Config | Parsed configuration file |
| InstructionFile | Config | Agent instruction file with poisoning signals |
| OllamaInstance | Network scan + Ollama fingerprinter | Ollama service endpoint and anonymous loot posture |
| VLLMInstance | Network scan + vLLM fingerprinter | vLLM service endpoint and auth posture |
| QdrantInstance | Network scan + Qdrant fingerprinter | Qdrant endpoint and collection metadata |
| MLflowServer | Network scan + MLflow fingerprinter | MLflow endpoint, experiments, and run metadata |
| LiteLLMGateway | Network scan + LiteLLM fingerprinter | LiteLLM gateway endpoint and credential exposure |
| JupyterServer | Network scan + Jupyter fingerprinter + Looter | Public `/api` + canonical status identity; protected-operation auth/anonymous evidence |
| LangServeApp | Network scan + LangServe fingerprinter | LangServe endpoint and chain metadata |
| OpenWebUIInstance | Network scan + Open WebUI fingerprinter | Open WebUI endpoint and auth posture |
| AIService | Multi-label umbrella | Companion label shared by AI service nodes |
| AIModel | Looter | Model artifact served by an AI service |
| ExtractedTrainingSignal | Extractor | Signal recovered from a model artifact |

Node IDs are deterministic SHA-256 hashes of `Kind:` + identifying properties. MCPServer IDs
match across Config and MCP collectors -- this is the merge point connecting trust to capabilities.

### Edge Types (32 total)

**20 raw edges** (from collectors): TRUSTS_SERVER, PROVIDES_TOOL, PROVIDES_RESOURCE,
PROVIDES_PROMPT, ADVERTISES_SKILL, DELEGATES_TO, AUTHENTICATES_WITH, USES_CREDENTIAL,
RUNS_ON, CONFIGURED_IN, HAS_ENV_VAR, LOADS_INSTRUCTIONS, SAME_AUTH_DOMAIN, EXPOSES,
EXPOSES_CREDENTIAL, PROVIDES_MODEL, EXTRACTED_FROM, INGESTS_UNTRUSTED,
CREDENTIAL_REACH_VERIFIED, PUBLIC_ACCESS_OBSERVED.

**12 composite edges** (computed by post-processors in dependency order):

| # | Edge | Meaning |
|---|------|---------|
| 1 | HAS_ACCESS_TO | Tool can reach a resource (capability + URI match) |
| 2 | CAN_EXECUTE | Tool can execute commands on a host |
| 3 | SHADOWS | Tool mimics another tool's description cross-server |
| 4 | POISONED_DESCRIPTION | Tool description contains injection patterns |
| 5 | POISONED_INSTRUCTIONS | Instruction file contains injection patterns |
| 6 | TAINTS | Untrusted-input tool shares schema keys with a tool on another server |
| 7 | CAN_REACH | Agent has transitive access to a resource (incl. credential-chain + cross-protocol, up to 6 hops) |
| 8 | CAN_EXFILTRATE_VIA | Agent can reach sensitive data + an outbound channel |
| 9 | IFC_VIOLATION | Untrusted source shares a resource with a high-impact sink |
| 10 | CAN_IMPERSONATE | A2A agent mimics another (TF-IDF cosine > 0.8) |
| 11 | CONFUSED_DEPUTY | Weakly-authed agent delegates to a strongly-authed one |
| 12 | POISONS_CONTEXT | Injection-bearing tool poisons context driving a high-capability tool |

Edge constructors and processors normally populate `scan_id`, `last_seen`,
`confidence`, `risk_weight`, and `is_composite`. Structured `evidence` is
edge-specific, not universal. Finding-producing composite edges use bounded
`evidence_*` witness references that are persisted into finding snapshots.

## Three Collectors

| Collector | Network | Input | Output Nodes | Key Signals |
|-----------|---------|-------|-------------|-------------|
| **Config** | None | 12 MCP client config formats (Claude Desktop, Cursor, VS Code, Windsurf, Zed, Cline, Continue, JetBrains, Kiro, Amazon Q, Augment, Claude Code) | ConfigFile, AgentInstance, MCPServer, Identity, Credential, Host, InstructionFile | Unpinned packages, high-entropy secrets, instruction poisoning |
| **MCP** | stdio / HTTP | Live MCP servers via Go SDK v1.6.1 | MCPServer, MCPTool, MCPResource, MCPPrompt | Capability surface (8 categories), injection patterns, description hashes, cross-references |
| **A2A** | HTTP | Agent Card JSON (v0.3.0 + v1.0.1) | A2AAgent, A2ASkill, Host | Required-field conformance without dropping invalid observations, ordered interfaces, versioned security requirements, v1 ProtoJSON/JCS/JWS validity and key trust, delegation hypotheses |

All collectors produce the same JSON ingest format. The Config and MCP collectors share
MCPServer node IDs so their outputs merge cleanly on ingest.

## Security Model

Single-user posture. The server has **no application-layer authentication, no RBAC, no audit log**. Protect via the network layer (loopback bind, VPN, SSH tunnel). See [`security.md`](../operator/security.md) for the full threat model.

| Layer | Implementation |
|-------|---------------|
| Network scope | `agenthound-server` binds `127.0.0.1:8080` by default. Override with `--bind 0.0.0.0:8080` only inside a trusted network. |
| TLS (collector outbound) | Strict cert verification by default. Use `--insecure` only against self-signed collection targets; card-controlled A2A `jku` remains HTTPS-only with identity validation. |
| Credential safety | Config Collector hashes credential values by default (SHA-256). `--include-credential-values` for audit mode. |
| Output files | Written `0o600` on POSIX; NTFS ACLs apply on Windows. |
| Supply chain | Cosign-signed `checksums.txt` per release; SBOM per archive (syft); pinned action SHAs; `govulncheck` blocking; collector dependency allowlist. |

## Deployment

Docker Compose runs three containers:

| Container | Image | Purpose | Default Port (host) |
|-----------|-------|---------|---------------------|
| graph-db | neo4j:4.4-community | Graph storage and Cypher queries | 127.0.0.1:7687 (bolt), 127.0.0.1:7474 (browser) |
| app-db | postgres:16-alpine | scan lifecycle, finding snapshots/triage, posture publications (no users/tokens/audit) | 127.0.0.1:5432 |
| agenthound | golang:1.25-alpine (multi-stage) | API server + embedded UI | 127.0.0.1:8080 |

```bash
docker compose -f docker/docker-compose.yml up -d
```

Configuration is env-based: `AGENTHOUND_NEO4J_URI`, `AGENTHOUND_PG_URI`,
`AGENTHOUND_BIND` (default `127.0.0.1:8080`),
and `AGENTHOUND_CORS_ORIGINS`. Collection-point/network-context provenance and
the PostgreSQL/Neo4j storage-pair UUID are derived or generated internally;
there are no public identity settings.
