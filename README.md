<p align="center">
  <h1 align="center">AgentHound</h1>
  <p align="center"><strong>Attack-path discovery for AI agent infrastructure</strong></p>
  <p align="center">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
    <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.25+-00ADD8.svg" alt="Go"></a>
    <a href="https://neo4j.com"><img src="https://img.shields.io/badge/Neo4j-4.4+-008CC1.svg" alt="Neo4j"></a>
    <a href="https://github.com/adithyan-ak/agenthound/actions"><img src="https://img.shields.io/github/actions/workflow/status/adithyan-ak/agenthound/ci.yml?branch=main&label=CI" alt="CI"></a>
  </p>
</p>

**AgentHound is the BloodHound for MCP/A2A config sprawl.** It enumerates MCP servers, A2A agents, and AI-agent client configurations across an operator's environment, builds a directed trust graph in Neo4j, and uses shortest-path algorithms to surface multi-hop attack paths the configuration files alone never reveal.

It ships as **two binaries** in the SharpHound/BloodHound style:

- **`agenthound`** — a lean field collector. ~9 MiB stripped on linux/amd64. No Neo4j, no Postgres, no UI. Drops on a target host, enumerates, writes JSON to a file or stdout. The collector is offline-by-default — it does not phone home.
- **`agenthound-server`** — the operator's single-user ingest + analysis server. Runs Neo4j-backed graph storage, post-processors, the REST API, and the React UI. Operators move scan JSON to the server via file copy, an SSH pipe, or the UI's drag-drop import.

The marquee detection is **credential-chain CAN_REACH**: multi-hop paths where Server A reads a credential, Server B uses that credential, and an agent reaches B's resources without trusting B directly. The graph model is what makes this feasible — single-file static analyzers cannot see the path because no individual config declares it.

Prior art on adjacent problems: Snyk Toxic Flow Analysis (Jul 2025) for static MCP code analysis, and Invariant Labs (Apr 2025) for runtime tool-call inspection. AgentHound's contribution is the credential-chain graph + collector/server split optimized for red-team workflows.

---

## What it finds

AgentHound discovers security issues across your AI agent infrastructure, mapped to [OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and [OWASP Agentic Top 10](https://genai.owasp.org/):

| Finding | Severity | What it means |
|---------|----------|---------------|
| **Credential-chain paths** | Critical | Multi-hop paths where Server A reads a credential, Server B uses that credential, and an agent reaches B's resources without trusting B directly. The genuine "no other tool finds this" attack path — config-file scanners never see the chain. |
| Shell access paths | Critical | An agent can reach tools with arbitrary command execution |
| Database access paths | Critical | An agent can reach production database resources |
| Data exfiltration routes | Critical | An agent can read sensitive data AND send it outbound |
| Tool poisoning | High | Tool descriptions contain prompt injection patterns |
| Tool shadowing | High | A malicious tool mimics a legitimate tool to hijack actions |
| Rug pull detection | High | A tool's description changed between scans (supply chain attack) |
| Unauthenticated servers/agents | High | MCP servers or A2A agents with no authentication |
| Instruction file poisoning | High | Agent instruction files contain exfiltration or override patterns |
| Hardcoded secrets | High | High-entropy strings (API keys) in config files |
| Unpinned packages | Medium | `npx -y @pkg` without version pin — supply chain risk |
| Unsigned agent cards | Medium | A2A agents without JWS signatures |
| Cross-protocol attack paths[^xprotocol] | Critical | An A2A agent can pivot through host co-location to reach MCP resources |

[^xprotocol]: Cross-protocol pivot detection is the academically-novel piece, but in practice it fires rarely because most A2A and MCP deployments don't share hosts. It exists; the credential-chain detection above is what most operators will actually use.

All 17 findings are exposed as pre-built queries from the CLI and UI.

---

## Install

### Collector (`agenthound`)

The collector is a single static binary. No Docker, no DBs, no `sudo`.

#### One-line install

```bash
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/install.sh | sh
```

The installer:

- Pins to the latest GitHub Release tag.
- Downloads the archive plus `checksums.txt` and verifies the SHA-256.
- Verifies the cosign signature on `checksums.txt` if `cosign` is on `$PATH`. If not, prints the verification command for you to run manually.
- Extracts to `$HOME/.local/bin/agenthound` (override with `AGENTHOUND_INSTALL_DIR=/path`).
- Atomic install via temp staging — a SIGINT mid-install never leaves a half-written binary.

For reproducibility, pin to a tag explicitly:

```bash
AGENTHOUND_VERSION=v0.5.0 curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/v0.5.0/install.sh | sh
```

#### Homebrew

```bash
brew tap adithyan-ak/agenthound
brew install agenthound
```

If you previously had the bundled single-binary AgentHound installed via Homebrew:

```bash
brew upgrade agenthound                              # Now the lean collector
brew install adithyan-ak/agenthound/agenthound-server # Server is now a separate formula
```

#### Docker

```bash
docker pull ghcr.io/adithyan-ak/agenthound:latest
docker run --rm ghcr.io/adithyan-ak/agenthound scan --help
```

#### Build from source

```bash
git clone https://github.com/adithyan-ak/agenthound
cd agenthound
go build -o bin/agenthound ./collector/cmd/agenthound
```

### Server (`agenthound-server`)

The server runs on the operator's laptop or a host they fully control. It binds to `127.0.0.1:8080` by default. **Authentication is not implemented at the application layer** — protect access with the network layer (VPN, SSH tunnel, Tailscale, etc.). See [`docs/security.md`](docs/security.md) for the full posture.

#### Docker Compose (recommended)

```bash
git clone https://github.com/adithyan-ak/agenthound
cd agenthound
docker compose -f docker/docker-compose.yml up -d
```

Runs three containers: `graph-db` (Neo4j 4.4 + APOC), `app-db` (PostgreSQL 16), and `agenthound-server`. All ports bind to `127.0.0.1`.

#### Homebrew

```bash
brew install adithyan-ak/agenthound/agenthound-server
agenthound-server serve
```

You'll need a running Neo4j and Postgres; the simplest path is to keep using the docker-compose file for the databases:

```bash
docker compose -f docker/docker-compose.yml up -d graph-db app-db
agenthound-server serve
```

#### Build from source

```bash
make build-server      # Builds UI + binary at bin/agenthound-server
```

### Remote access

The default `127.0.0.1` bind is the security model. To reach the server from another machine, use the network you already trust:

```bash
ssh -L 8080:localhost:8080 operator-host
# Now http://localhost:8080 on your laptop forwards to the server
```

Or run the server inside Tailscale / WireGuard / a VPN you control. **Do not** expose the server on `0.0.0.0` over plain HTTP.

---

## Quick scan

```bash
# Discover and enumerate everything reachable from this host (default: ./scan-<scan_id>.json in CWD)
agenthound scan

# Choose a path explicitly
agenthound scan --output /tmp/scan.json

# Stream JSON to stdout for piping
agenthound scan --output - | ssh op-box 'agenthound-server ingest -'

# Scope to one collector
agenthound scan --config                              # Config files only (offline)
agenthound scan --mcp --url https://mcp.example.com   # Single HTTP MCP server
agenthound scan --a2a --targets url1,url2             # A2A agents
```

## Network scan + Looter (v0.2)

The v0.2 offensive surface adds active network discovery for AI services and the first concrete `Looter` action. The network scanner sweeps a CIDR for AI services on standard ports and dispatches fingerprinters at each open port; the LiteLLM Looter extracts upstream provider credentials (OpenAI, Anthropic, AWS Bedrock, Azure, Cohere) from a master-key-authenticated LiteLLM gateway:

```bash
# Discover AI services on a private CIDR (Ollama on 11434, LiteLLM on 4000, ...).
agenthound scan 10.0.0.0/24

# Public IP space requires explicit override + interactive AUTHORIZED prompt + watermark.
agenthound scan 1.1.1.1 --allow-public-targets --authorization-file ./engagement.pdf

# Loot a discovered LiteLLM gateway. value_hash on every emitted Credential is the
# cross-collector merge primitive — same secret seen as an env var by the Config
# Collector lights up the credential-chain finding in the analysis server.
agenthound loot 10.0.0.10:4000 --type litellm \
    --master-key sk-... --engagement-id ENG-001 --output -
```

See [`docs/scanner.md`](docs/scanner.md) for the full network scanner guide (legal warnings, port set, safety controls) and [`docs/loot-litellm.md`](docs/loot-litellm.md) for the LiteLLM Looter audit-trail residue caveat.

## Workflow

The collector writes JSON. The operator's box ingests it. There are three equivalent paths:

```bash
# (a) File copy + CLI ingest
scp scan.json operator-box:/tmp/
ssh operator-box 'agenthound-server ingest /tmp/scan.json'

# (b) Stdin pipe (no file at rest on either side)
agenthound scan --output - | ssh operator-box 'agenthound-server ingest -'

# (c) UI drag-drop import
# Open http://localhost:8080 → Scan Manager → "Import scan" → drag scan.json into the dropzone
```

The server validates, normalizes, deduplicates, writes the graph, and runs the post-processors. Then open the UI:

```bash
open http://localhost:8080
```

Or query from the CLI:

```bash
agenthound query --findings --severity critical
agenthound query --prebuilt agents-shell-access
```

---

## How it works

```
                                FIELD                                |          OPERATOR
                                                                     |
  Config Collector       MCP Collector       A2A Collector           |
  (12 client parsers)    (Go SDK, stdio/HTTP) (HTTP + JWS verify)    |
        |                      |                      |              |
        v                      v                      v              |
  +-------------------------------------------------+               |          +---------------+
  |                  agenthound (collector)          | -- JSON --> | -- API ->| ingest pipeline|
  +-------------------------------------------------+               |          +---------------+
                                                                     |                |
                                                                     |                v
                                                                     |          +---------+
                                                                     |          |  Neo4j  |
                                                                     |          +---------+
                                                                     |                |
                                                                     |                v
                                                                     |       +-----------------+
                                                                     |       | post-processors |
                                                                     |       +-----------------+
                                                                     |                |
                                                                     |    +-----------+----------+
                                                                     |    |                      |
                                                                     |    v                      v
                                                                     | +---------+        +-------------+
                                                                     | | REST API|        |  React UI    |
                                                                     | | (chi)   |        | (React Flow) |
                                                                     | +---------+        +-------------+
```

The collector is a **single static binary** with the three enumeration modules statically linked. The server holds Neo4j, the post-processors, the REST API, and the embedded React + React Flow + ELK UI.

### The graph

AgentHound builds a directed trust graph with **12 collector-produced node types** (plus 2 synthetic) and **13 raw edge types** (plus 8 post-processed composite edge types — 21 total):

- **Nodes:** `AgentInstance`, `MCPServer`, `MCPTool`, `MCPResource`, `MCPPrompt`, `A2AAgent`, `A2ASkill`, `Identity`, `Credential`, `Host`, `ConfigFile`, `InstructionFile`
- **Direct edges:** `TRUSTS_SERVER`, `PROVIDES_TOOL`, `PROVIDES_RESOURCE`, `PROVIDES_PROMPT`, `ADVERTISES_SKILL`, `DELEGATES_TO`, `AUTHENTICATES_WITH`, `USES_CREDENTIAL`, `RUNS_ON`, `CONFIGURED_IN`, `HAS_ENV_VAR`, `LOADS_INSTRUCTIONS`, `SAME_AUTH_DOMAIN`
- **Composite edges (computed by post-processors):** `HAS_ACCESS_TO`, `CAN_EXECUTE`, `CAN_REACH`, `CAN_EXFILTRATE_VIA`, `SHADOWS`, `POISONED_DESCRIPTION`, `POISONED_INSTRUCTIONS`, `CAN_IMPERSONATE`. The cross-protocol A2A→MCP traversal reuses the `CAN_REACH` label with `source_collector` annotations.

Node IDs are deterministic SHA-256 hashes — the same `MCPServer` discovered by the Config Collector and the MCP Collector merges into a single node by ID.

### Risk scoring

Every node gets a risk score (0–100) based on weighted factors:

- **Agents:** credential handling, blast radius, auth posture, tool surface, poisoning exposure
- **Servers:** auth strength, tool risk, network exposure, credential handling
- **Tools:** capability class, poisoning indicators, access sensitivity, input validation

---

## Configuration

### Collector

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTHOUND_OUTPUT` | | Write scan JSON to this path. Use `-` for stdout. Defaults to `./scan-<scan_id>.json` in CWD. |
| `AGENTHOUND_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `AGENTHOUND_QUIET` | | `1` suppresses non-error logs (same as `--quiet`) |
| `AGENTHOUND_LOG_JSON` | | `1` emits structured JSON logs instead of text |
| `AGENTHOUND_CONCURRENCY` | `5` | Max parallel collector workers |

Global flags (available on every subcommand): `--log-level`, `--output`, `--concurrency`, `--quiet`, `--log-json`.

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTHOUND_NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection |
| `AGENTHOUND_NEO4J_USER` | `neo4j` | Neo4j username |
| `AGENTHOUND_NEO4J_PASSWORD` | `agenthound` | Neo4j password |
| `AGENTHOUND_PG_URI` | `postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable` | Postgres connection |
| `AGENTHOUND_BIND` | `127.0.0.1:8080` | Server bind address `host:port`. Set to `0.0.0.0:8080` only inside a trusted network. |
| `AGENTHOUND_LOG_LEVEL` | `info` | Log level |
| `AGENTHOUND_CORS_ORIGINS` | `http://localhost:8080` | Comma-separated allowed CORS origins (dev only) |

There is intentionally no `AGENTHOUND_JWT_SECRET`, `AGENTHOUND_ADMIN_PASSWORD`, or `AGENTHOUND_API_TOKEN` — the server has no application-layer auth.

---

## Output handling

- The collector writes scan JSON via atomic `temp + rename`. A SIGINT mid-write never leaves a half-written file at the destination.
- Output files are `chmod 0o600` on POSIX. **NTFS does not honor POSIX permission bits** — on Windows the file inherits the directory's NTFS ACL, which typically allows any local user to read it. Treat output stored on Windows as readable by every local user account.
- When `--output` is unset, the collector writes to `./scan-<scan_id>.json` in the current working directory. Pass `--output -` to stream JSON to stdout (no file is created); use this with a pipe (`| agenthound-server ingest -`).

---

## Demo

Seed the graph with synthetic demo data that covers all detection capabilities:

```bash
make demo
# or
bash scripts/seed-demo.sh
```

This stands up a multi-host Docker lab (MCP server, A2A agent, LiteLLM gateway, Ollama, vLLM, Open WebUI, Jupyter) and runs a live `scan` → `discover` → `loot` against it, ingesting the results into the server. The seeded graph covers: critical attack paths, data exfiltration routes, cross-protocol pivots, tool poisoning, credential chains, unpinned packages, unsigned A2A agents, and instruction file poisoning.

---

## OPSEC

AgentHound is a transparent assessment tool, not an evasion implant. The binary is named `agenthound`, is statically linked, and is detectable by any modern EDR. If your engagement requires evasion, the right tools are Sliver / Mythic / a custom implant — and you can shuttle AgentHound's JSON output through that channel.

See [`docs/security.md`](docs/security.md) for the full threat model and operator OPSEC notes.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Quickstart](docs/quickstart.md) | 5-minute setup guide |
| [CLI Reference](docs/cli-reference.md) | All commands, flags, and examples |
| [API Reference](docs/api-reference.md) | REST API endpoints |
| [Graph Model](docs/graph-model.md) | Node types, edge types, ID strategy, risk scoring |
| [Detection Rules](docs/detection-rules.md) | All 17 detections with OWASP mappings |
| [Architecture](docs/architecture.md) | System architecture for contributors |
| [Security](docs/security.md) | Threat model and operational posture |
| [Two-binary split (ADR)](docs/adr/0001-two-binary-split.md) | Why and how the split happened |
| [Future modules](docs/future-modules.md) | Deferred surface and planning notes |
| [Contributing](CONTRIBUTING.md) | How to contribute collectors, detections, and queries |
| [Changelog](CHANGELOG.md) | Release notes |
| [Vulnerability reporting](SECURITY.md) | Disclosure process |

Machine-readable API spec: `GET /api/v1/docs` (OpenAPI 3.0, YAML format)

---

## License

[Apache License 2.0](LICENSE)
