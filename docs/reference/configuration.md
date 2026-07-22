# Configuration Reference

AgentHound uses a three-tier precedence model for all settings:

```
CLI flag > environment variable > compiled default
```

Both binaries read environment variables at startup. The collector has no config file; the server has no config file either (env-only by design).

---

## Collector (`agenthound`)

| Variable | Flag | Default | Description |
|----------|------|---------|-------------|
| `AGENTHOUND_LOG_LEVEL` | `--log-level` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `AGENTHOUND_OUTPUT` | `--output` | `./scan-<scan_id>.json` | Output path. Use `-` for stdout. |
| `AGENTHOUND_CONCURRENCY` | `--concurrency` | `5` | Max parallel collector goroutines. For `scan`, used as the fallback for `--scan-concurrency` when that flag is not set explicitly (explicit `--scan-concurrency` wins; `--network-scan-concurrency` is unaffected). |
| `AGENTHOUND_QUIET` | `--quiet` | _(unset)_ | Set to `1` to suppress non-error log output, plus the `scan` / `discover` progress line, the per-host/endpoint summary, and fingerprint output |
| `AGENTHOUND_LOG_JSON` | `--log-json` | _(unset)_ | Set to `1` for structured JSON logs to stderr |
| `AGENTHOUND_RULES_BUNDLE` | `--rules-bundle` | _(unset)_ | Path to a fingerprint rules bundle (directory or `.tar.gz`). Same-id rules override the embedded set. Verify cosign signature before use. |
| `AGENTHOUND_RULES_DIR` | _(none)_ | `~/.agenthound/rules/` | Custom text-detection rule directory. |
| `AGENTHOUND_CAMPAIGN_CREDENTIAL` | `--credential-env` (names the var) | _(unset)_ | Out-of-band credential material for `agenthound campaign`. Hash-matched locally against the witness `value_hash`; never logged, serialized, or written to the graph. Never pass credentials as a flag. |
| `AGENTHOUND_MCP_TOKEN` | _(none)_ | _(unset)_ | Explicit bearer value for MCP SDK observation by the ContextForge poison/round-trip adapter. Overrides exact-URL MCP client-config credential discovery. Never stored in receipts or reports. |
| `AGENTHOUND_CONTEXTFORGE_TOKEN` | _(none)_ | _(unset)_ | Explicit ContextForge management-bearer override. Required for cross-origin management; otherwise same-origin management reuses the resolved MCP bearer. Never stored in receipts or reports. |
| `AGENTHOUND_CAMPAIGN_AUTHORIZED` | _(none)_ | _(unset)_ | Set to `AUTHORIZED` to acknowledge the `campaign` authorization gate non-interactively (needed when stdin is consumed by `--witness -` / `--credential-stdin`). |
| `AGENTHOUND_STATE_DIR` | _(none)_ | `~/.agenthound/state/` | Override the protected offensive-action and campaign receipt root. Does not relocate acknowledgement sentinels. |

Output file permissions: `0600` on POSIX. Atomic write via temp file + rename.

Collection provenance is automatic and has no public flags, environment
variables, or config file. At artifact-write time the collector derives a
versioned `collection_point_id` from native OS-instance, effective-principal,
platform, and filesystem/container evidence. It derives `network_context_id`
from that point plus active network-profile, private/ULA route-table, default-
gateway, interface-prefix, and DNS evidence. This includes split VPN and pivot
routes. Each retained private route is bound to its next hop and a stable native
profile/link discriminator when available, so an overlapping prefix reached
through a different pivot derives a different context. Route metrics and
interface names are not identity inputs. macOS ARP/neighbor-cache and cloned
host routes are excluded because their expiry does not change network
visibility. Raw identity signal values are transformed with AgentHound-specific
HMAC-SHA-256 before they enter the artifact. No child process is spawned and no
target-side AgentHound state is created.

Collection-point quality and network-context quality are independent. If the
collector cannot inspect the route table or active interfaces—or cannot
distinguish the path for a retained private route—a strong local collection
point stays strong, while only remote/network-scoped facts and coverage receive
artifact-local additive-only scope for that import. The artifact reports
network quality as `unknown`; it is never treated as an authoritative offline
view.

Hostname, OS, and architecture may also appear in clear as bounded display-only
labels. They never participate in an ID, match, graph scope, lifecycle key, or
admission decision.

When OS-instance evidence is unavailable, hostname and permanent MAC addresses
are weak fallbacks. Weak artifacts are still accepted and analyzed, but their
authoritative graph and lifecycle identity is artifact-local so they cannot
merge with or retire another vantage point. Derived provenance is deterministic
recognition, not authentication or attestation.

For ContextForge operations, MCP and management authentication remain independently configurable and origin-bound. If `AGENTHOUND_MCP_TOKEN` is unset, AgentHound searches its existing MCP client-config discovery paths for one unique `Authorization` header whose configured URL is byte-for-byte equal to the positional MCP URL after surrounding whitespace is trimmed. It does not use host-only, prefix, normalized, or fuzzy matching, and conflicting exact-URL headers fail closed. Stdio wrappers, routing headers, and unresolved credential references are not inferred.

When `AGENTHOUND_CONTEXTFORGE_TOKEN` is set, it overrides the management bearer only. Otherwise management may reuse the resolved MCP bearer only when its origin is the same; a cross-origin `--management-url` requires the explicit ContextForge override. ContextForge v1.0.5 enforces token permission claims as a ceiling before its database RBAC check. AgentHound therefore accepts a session token or an API token whose permission ceiling is empty or contains `*`, then reads the fixed `/v1/auth/email/me` profile. For a non-admin it queries `/v1/rbac/my/permissions?team_id=<uuid>` for the exact server and tool team contexts; effective RBAC must contain `servers.read`, `tools.read`, and `tools.update`, so use a dedicated account whose provider roles contain only those permissions. The account must also be the direct `ownerEmail` of both objects; token team membership does not establish ContextForge's team-owner role. A platform-admin bypass is accepted only from the provider-authenticated profile. Exact non-wildcard API-token ceilings fail closed because they block the preflight endpoints needed to prove authorization. Exact server/tool reads must also succeed. Credentials are never persisted.

AgentHound does not create, retrieve, or elevate ContextForge management credentials. Obtain the bearer from the authorized deployment's existing authentication or API-token workflow, and provision its provider identity/RBAC before running the adapter.

---

## Server (`agenthound-server`)

| Variable | Flag | Default | Description |
|----------|------|---------|-------------|
| `AGENTHOUND_LOG_LEVEL` | `--log-level` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `AGENTHOUND_BIND` | `--bind` | `127.0.0.1:8080` | Listen address. Loopback-only by default (no app-layer auth). |
| `AGENTHOUND_NEO4J_URI` | `--neo4j-uri` | `bolt://localhost:7687` | Neo4j Bolt endpoint |
| `AGENTHOUND_NEO4J_USER` | `--neo4j-user` | `neo4j` | Neo4j username |
| `AGENTHOUND_NEO4J_PASSWORD` | `--neo4j-password` | `agenthound` | Neo4j password |
| `AGENTHOUND_PG_URI` | `--pg-uri` | `postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable` | PostgreSQL connection string |
| `AGENTHOUND_CORS_ORIGINS` | `--cors-origins` | `http://localhost:8080,http://127.0.0.1:8080` | Comma-separated allowed origins. Shared by CORS and OriginGuard (mutating-endpoint CSRF defense). |

### Automatic storage binding and multi-vantage ingest

The server accepts every structurally valid ingest-v4 artifact. It does not
bind a database to one host or network and has no collection-origin admission
configuration. Ambiguous graph identities and coverage ownership are scoped by
the artifact's derived collection point or network context before mutation.

PostgreSQL and Neo4j are still an inseparable storage pair. On first startup,
the server generates one internal UUID and atomically installs it in both empty
stores under a PostgreSQL advisory lock. On later startups it verifies both
markers. It repairs a one-sided marker only when both stores remain
product-empty, covering a crash during first initialization. Crossed volumes,
invalid markers, or a missing marker beside non-empty product data fail closed.
There is no public storage-pair flag or environment variable.

Back up and restore PostgreSQL and Neo4j together. Ingest v4 is a clean database
boundary: preserve an ingest-v3 deployment or backup as read-only, create fresh
v4 volumes, and recollect. Existing unscoped graph state is never mixed into
the v4 projection automatically.

---

## State Directory (`~/.agenthound/`)

The collector's custom rules and offensive modules persist state under
`~/.agenthound/`:

```
~/.agenthound/
  loot-acknowledged              # Marker file — operator acknowledged loot output risks
  poison-acknowledged            # Marker file — operator acknowledged poisoner risks
  extract-acknowledged           # Marker file — operator acknowledged extractor risks
  campaign-acknowledged          # Marker file — operator acknowledged campaign risks
  rules/                         # Custom text-detection rules
  state/
    <module>/
      <engagement>.json          # Poison/implant/campaign recovery receipts
```

`AGENTHOUND_STATE_DIR` overrides the receipt state-root path
(`~/.agenthound/state/`). Sentinels (`loot-acknowledged`,
`poison-acknowledged`, `extract-acknowledged`, and
`campaign-acknowledged`) always live under `~/.agenthound/`, resolved via
`os.UserHomeDir()`.

---

## CSRF defense (OriginGuard)

Mutating API endpoints (`POST /api/v1/ingest`, `POST /api/v1/query`, security/topology path operations, scan CRUD, triage PATCH) are gated by an `Origin` allowlist. Browsers must originate from a value in `AGENTHOUND_CORS_ORIGINS` (default covers `http://localhost:8080` and `http://127.0.0.1:8080`). Non-browser callers (curl, the agenthound CLI, cron pipelines) send no `Origin` header and pass through. CLI commands (`agenthound-server ingest`, `query`) bypass HTTP entirely. See [`security.md`](../operator/security.md#origin-guard-on-mutating-endpoints).

---

## Docker Compose Defaults

The shipped `docker/docker-compose.yml` passes these to the `agenthound` service container:

```yaml
AGENTHOUND_NEO4J_URI: bolt://graph-db:7687
AGENTHOUND_NEO4J_USER: neo4j
AGENTHOUND_NEO4J_PASSWORD: agenthound
AGENTHOUND_PG_URI: postgres://agenthound:agenthound@app-db:5432/agenthound?sslmode=disable
AGENTHOUND_BIND: 0.0.0.0:8080   # reachable from host via port mapping
AGENTHOUND_LOG_LEVEL: info
```

The shipped Compose files require no collection-identity or storage-pair
settings.

Port mappings bind to `127.0.0.1` on the host side — no external exposure by default.
