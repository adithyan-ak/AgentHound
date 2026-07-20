# Quickstart

Get AgentHound running the full offensive chain (scan, discover, loot, poison, revert) in under 10 minutes.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Docker + Compose | v2+ | Runs the analysis server stack (Neo4j + Postgres + UI) |

The collector is a single static binary (no Go needed). The server runs from a pre-built image (no source checkout, no `make build`). You also need at least one MCP client configured (Claude Desktop, Cursor, VS Code, etc.) for the config scan to find anything interesting.

For contributor / source-build paths see [Installation](./install.md).

## 1. Start the Analysis Server

```bash
# Pick these once. Keep all three values with the deployment configuration.
export AGENTHOUND_HOST_ID=security-laptop
export AGENTHOUND_NETWORK_REALM_ID=corp-lab
export AGENTHOUND_STORAGE_PAIR_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"

curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/docker/docker-compose.public.yml \
  | docker compose -f - -p agenthound up -d --wait
```

Use canonical lowercase IDs that match
`[a-z0-9][a-z0-9._-]{0,127}`. If `uuidgen` is unavailable, generate a random
UUID v4 with your platform's trusted UUID utility and lowercase it. Never copy
the example UUID from the reference docs.

Pulls `neo4j:4.4-community`, `postgres:16-alpine`, and `ghcr.io/adithyan-ak/agenthound-server:latest`, then blocks until every healthcheck (Neo4j, Postgres, and the AgentHound server itself) reports healthy — first boot is ~30-60s while Neo4j initializes. To inspect state manually:

```bash
docker compose -p agenthound ps
```

The server binds `127.0.0.1:8080`. No application-layer auth; mutating endpoints are gated by an `Origin` allowlist (`OriginGuard`) — browser CSRF is rejected, non-browser callers (curl, the agenthound CLI, cron) pass through. Protect with VPN/SSH tunnel if you need remote access.

The host and realm also become required collector artifact provenance. One
database pair accepts only that exact tuple because local paths, loopback
services, private addresses, and lifecycle coverage are meaningful only from
one collection vantage point. The storage UUID is stamped into both databases
and prevents accidentally crossing a PostgreSQL volume with a different Neo4j
volume. Keep all three values stable for the lifetime of both volumes. These
IDs are not secrets or artifact authentication.

## 2. Install the Collector

```bash
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"     # add to ~/.zshrc or ~/.bashrc to persist
```

Verifies checksums (and cosign signature when cosign is on `$PATH`), installs to `~/.local/bin/agenthound`. Confirm:

```bash
agenthound --version
```

## 3. Run Your First Scan and Ingest

The config scan is offline and safe. It parses all 12 supported MCP client config formats on the local machine and reports trust relationships, credentials, and instruction files. Stream straight into the running server in one pipe:

```bash
agenthound scan --config --output - \
  | curl --data-binary @- -H "Content-Type: application/json" \
         http://127.0.0.1:8080/api/v1/ingest
```

Or write to disk and ingest in two steps. The collector prints the
exact filename (`./scan-<scan_id>.json`); use that, not a glob, since
later scans accumulate alongside it:

```bash
agenthound scan --config                     # prints ./scan-<scan_id>.json
curl --data-binary @./scan-<scan_id>.json \
  -H "Content-Type: application/json" \
  http://127.0.0.1:8080/api/v1/ingest
```

Drag-drop a `scan-*.json` into the UI's Scan Manager also works — same endpoint.

## 4. Run a Network Scan

Pass a CIDR or host to sweep for AI/ML services (Ollama, vLLM, Qdrant, MLflow, LiteLLM, Jupyter, LangServe, Open WebUI) on their standard ports:

```bash
agenthound scan 10.0.0.0/24
```

Public IP targets require an explicit opt-in and interactive AUTHORIZED confirmation:

```bash
agenthound scan 203.0.113.0/28 --allow-public-targets
```

CIDRs larger than /16 additionally require `--allow-large-cidr`. The scan output is the same ingest envelope format; pipe or ingest as above.

## 5. Discover MCP and A2A Services

`discover` is the protocol-probe counterpart to `scan`. Where scan fingerprints known AI-service ports, discover issues JSON-RPC initialize probes (MCP) and well-known agent-card fetches (A2A) to find services that respond to protocol handshakes:

```bash
agenthound discover 10.0.0.0/24
```

Scope to a single protocol:

```bash
agenthound discover 10.0.0.0/24 --mcp          # MCP only (ports 3000,8000,8080,8443)
agenthound discover 10.0.0.0/24 --a2a          # A2A only (ports 80,443,3000,8080)
```

Ingest the result the same way (stream form, or curl the file the
collector wrote):

```bash
agenthound discover 10.0.0.0/24 --output - \
  | curl --data-binary @- -H "Content-Type: application/json" \
         http://127.0.0.1:8080/api/v1/ingest
```

## 6. Loot a Service

Looters extract latent credentials from discovered services via read-only HTTP (GET/HEAD only). The first invocation prompts for an interactive AUTHORIZED confirmation:

```bash
agenthound loot 10.0.0.20:4000 --type litellm \
    --master-key sk-... \
    --engagement-id MY-ENGAGEMENT \
    --output -
```

Available looter types: `litellm`, `ollama`, `mlflow`, `qdrant`, `openwebui`, `jupyter`. The `--engagement-id` flag is a correlation key recorded on every emitted edge for IR coordination.

Loot Ollama models and modelfiles:

```bash
agenthound loot 10.0.0.10:11434 --type ollama \
    --engagement-id MY-ENGAGEMENT \
    --output loot-ollama.json
```

Ingest the loot envelope to surface credential-chain findings in the
graph (point curl at the file the collector wrote):

```bash
curl --data-binary @./loot-ollama.json \
  -H "Content-Type: application/json" \
  http://127.0.0.1:8080/api/v1/ingest
```

## 7. Explore Findings

**UI (recommended):** Open [http://localhost:8080](http://localhost:8080).

- **Dashboard** -- node/edge counts, risk distribution, top findings
- **Graph Explorer** -- interactive visualization (React Flow + ELK layout)
- **Findings** -- per-finding detail with embedded attack-path diagrams
- **Query Library** -- 19 pre-built security queries mapped to OWASP MCP/Agentic Top 10
- **Scan Manager** -- history, drag-drop import

**HTTP queries (no extra install):**

```bash
# Pre-built query (agents with shell access)
curl http://127.0.0.1:8080/api/v1/analysis/prebuilt/agents-shell-access

# Cross-protocol paths (MCP-to-A2A boundary traversal)
curl http://127.0.0.1:8080/api/v1/analysis/prebuilt/cross-protocol-paths

# Findings (filter by severity)
curl 'http://127.0.0.1:8080/api/v1/analysis/findings?severity=critical'

# Raw Cypher (OriginGuard admits no-Origin callers)
curl -H "Content-Type: application/json" \
  --data '{"cypher":"MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s) RETURN a.name, s.name"}' \
  http://127.0.0.1:8080/api/v1/query
```

If you have `agenthound-server` installed locally (Homebrew / `go install` / source build), the equivalent CLI is `agenthound-server query --findings` / `--prebuilt <id>` / raw Cypher as a positional arg — see [CLI reference](../reference/cli.md).

## 8. Poison and Revert (Advanced -- Destructive)

The poison/revert cycle demonstrates exploitability by modifying on-target state. MCP does not define a tool-metadata update API, so AgentHound supports tool-description mutation only through its explicit ContextForge management adapter. Every Poisoner must implement a Reverter at compile time. That guarantees a recovery path exists, not that an external provider will accept restoration after a policy change or conflict; AgentHound verifies recovery instead of assuming it.

**Safety gates:**

- `--commit` is OFF by default. Without it, the poisoner runs end-to-end but issues no mutating writes (dry-run).
- First invocation requires typing AUTHORIZED (separate sentinel from loot).
- Receipts persist to `~/.agenthound/state/<module-id>/<engagement-id>.json` for deterministic rollback.
- The `--engagement-id` flag is mandatory and correlates all mutations with their recovery receipts and verified revert outcome.
- Use a ContextForge session token or an API token with an empty/wildcard permission ceiling. AgentHound reads the provider profile; for non-admins it also queries team-context effective permissions, requiring `servers.read`, `tools.read`, and `tools.update` plus successful exact server/tool reads. Keep the account's provider RBAC least-privileged, and make it the direct owner of both objects. Team membership alone is insufficient. A platform-admin bypass is accepted only when the provider profile reports admin. An exact non-wildcard API-token ceiling is rejected because ContextForge v1.0.5 blocks this preflight proof.

Optionally override management authentication through the environment, never a flag. The override is required when `--management-url` changes the origin:

```bash
export AGENTHOUND_CONTEXTFORGE_TOKEN='...'
```

AgentHound derives the ContextForge deployment root and server UUID from a canonical `.../servers/<server-uuid>/mcp` URL. Copy the ContextForge v1.0.5 server ID exactly: its wire form is lowercase 32-hex text without hyphens, and alternate UUID spellings are rejected. If the management API is exposed under a different deployment root, add `--management-url https://gateway.example/<prefix>` without `/v1`; AgentHound appends its fixed API prefix. Set `AGENTHOUND_MCP_TOKEN` for an explicit MCP bearer value, or leave it unset to use one uniquely discovered `Authorization` header for the exact positional URL. When `AGENTHOUND_CONTEXTFORGE_TOKEN` is unset, same-origin management reuses that resolved MCP bearer; cross-origin management requires the explicit ContextForge override.

Put the authorized direct-poison payload in `payload.txt`. The round-trip campaign, by contrast, generates its benign proof marker internally.

**Dry-run (no mutation):**

```bash
agenthound poison https://gateway.example/servers/<server-uuid>/mcp \
    --type mcp.tool.description --adapter contextforge \
    --target-id support-lookup \
    --inject-file payload.txt \
    --engagement-id DC35-DEMO
```

**Live commit (mutates the target):**

```bash
agenthound poison https://gateway.example/servers/<server-uuid>/mcp \
    --type mcp.tool.description --adapter contextforge \
    --target-id support-lookup \
    --inject-file payload.txt --commit \
    --engagement-id DC35-DEMO
```

**Roll back all changes for an engagement:**

```bash
agenthound revert DC35-DEMO
```

Revert restores only the exact tool UUID at `V+1` with AgentHound's forward operation User-Agent; the landed description may be the provider-normalized value rather than the outbound text. Even an original-looking normalized landing completes the restore version/User-Agent transition. Association drift does not block restoration of that attributed row, but MCP verification is then reported unavailable. ContextForge and every intervening proxy must preserve the operation User-Agent for safe attribution. Use `agenthound revert DC35-DEMO --insecure` only when the authorized target deliberately uses certificates you cannot validate. If the deployment's description-validation policy changed after tools were created, verify the current policy still accepts the original text before committing: v1.0.5 exposes no non-mutating restorability probe.

For the lower-effort validation workflow, AgentHound generates the benign marker, proves the intermediate MCP-visible change, and restores the original in one scenario:

```bash
agenthound campaign https://gateway.example/servers/<server-uuid>/mcp \
    --scenario mcp-poison-roundtrip --adapter contextforge \
    --target-id support-lookup \
    --engagement-id DC35-ROUNDTRIP --commit
```

This round-trip takes no operator-supplied mutation text. It is a standalone reversible-mutation validation, not a graph finding.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTHOUND_NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection |
| `AGENTHOUND_NEO4J_USER` | `neo4j` | Neo4j username |
| `AGENTHOUND_NEO4J_PASSWORD` | `agenthound` | Neo4j password |
| `AGENTHOUND_PG_URI` | `postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable` | PostgreSQL |
| `AGENTHOUND_HOST_ID` | _(required for artifact output and DB commands)_ | Exact lowercase collector host admitted by this database pair |
| `AGENTHOUND_NETWORK_REALM_ID` | _(required for artifact output and DB commands)_ | Exact lowercase private-network realm admitted by this database pair |
| `AGENTHOUND_STORAGE_PAIR_ID` | _(required for DB commands)_ | Canonical lowercase UUID generated once for the PostgreSQL/Neo4j volume pair |
| `AGENTHOUND_BIND` | `127.0.0.1:8080` | Server bind address |
| `AGENTHOUND_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `AGENTHOUND_CORS_ORIGINS` | `http://localhost:8080,http://127.0.0.1:8080` | CORS origins for the UI |
| `AGENTHOUND_OUTPUT` | `./scan-<id>.json` | Collector output path (`-` for stdout) |
| `AGENTHOUND_CONCURRENCY` | `5` | Collector parallelism |
| `AGENTHOUND_MCP_TOKEN` | _(unset)_ | Explicit MCP bearer value for ContextForge observation; overrides exact-URL client-config discovery |
| `AGENTHOUND_CONTEXTFORGE_TOKEN` | _(unset)_ | Explicit management-bearer override; required across origins, optional for same-origin MCP/management |

## Next Steps

- [CLI Reference](../reference/cli.md) -- full command documentation
- [API Reference](../reference/api.md) -- REST API endpoints
- [Graph Model](../reference/graph-model.md) -- node types, edge types, risk scoring
- [Detection Rules](../reference/detection-rules.md) -- all detections with OWASP mappings
- [Security](../operator/security.md) -- threat model and operator OPSEC
