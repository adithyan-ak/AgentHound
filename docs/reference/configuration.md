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
| `AGENTHOUND_HOST_ID` | `--host-id` | _(required for ingest-artifact output)_ | Stable lowercase ID for the machine running the collector, for example `security-laptop`. |
| `AGENTHOUND_NETWORK_REALM_ID` | `--network-realm-id` | _(required for ingest-artifact output)_ | Stable lowercase ID for the private-network view reachable from that machine, for example `corp-lab`. |
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

`host-id` and `network-realm-id` are required by `scan`, `discover`, `loot`,
committed `extract`, and witness-backed committed `campaign` operations because
those operations emit ingest artifacts. They are not required by local-only
commands that emit no graph artifact, such as `version`, `rules`, dry-run
`extract`, poison/revert, implants, or the standalone MCP round-trip campaign.
Each identifier is 1-128 bytes and must match
`[a-z0-9][a-z0-9._-]{0,127}` exactly. Do not derive either value from an
ephemeral container hostname or IP address.

The pair is collection provenance: it prevents a server from merging local
paths, loopback endpoints, private addresses, and lifecycle coverage from a
different collection context. It is not authentication or a signature; anyone
who can rewrite an artifact can rewrite these non-secret fields too.

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
| `AGENTHOUND_HOST_ID` | `--host-id` | _(required for DB commands)_ | Exact collector host admitted by this database pair. Must equal artifact `meta.origin.host_id`. |
| `AGENTHOUND_NETWORK_REALM_ID` | `--network-realm-id` | _(required for DB commands)_ | Exact private-network realm admitted by this database pair. Must equal artifact `meta.origin.network_realm_id`. |
| `AGENTHOUND_STORAGE_PAIR_ID` | `--storage-pair-id` | _(required for DB commands)_ | Canonical lowercase UUID permanently pairing the PostgreSQL and Neo4j volumes. Generate once and keep it across restarts. |
| `AGENTHOUND_CORS_ORIGINS` | `--cors-origins` | `http://localhost:8080,http://127.0.0.1:8080` | Comma-separated allowed origins. Shared by CORS and OriginGuard (mutating-endpoint CSRF defense). |

### Collection realm and storage binding

One AgentHound database pair accepts one exact collector host in one exact
private-network realm. This is deliberate: the graph contains facts whose
meaning is local to the collection vantage point, including filesystem paths,
loopback services, RFC1918 endpoints, host nodes, and lifecycle coverage roots.
Merging two such vantage points into one projection could silently join
unrelated infrastructure or retire another host's current observations.

Generate `AGENTHOUND_STORAGE_PAIR_ID` once when creating the PostgreSQL and
Neo4j volumes, then store it alongside the deployment configuration. On every
DB-using startup, the server takes a PostgreSQL advisory lock and reads the
binding marker from both stores before running migrations, creating graph
schema, or accepting ingest. Exact markers are admitted. A missing marker is
repaired only when that store and its partner are still product-empty, which
covers a crash between the two initial marker writes. A future marker version,
crossed storage pair, realm mismatch, or unbound non-empty database fails
closed without mutating either store.

Back up and restore PostgreSQL and Neo4j as one pair. Do not regenerate the
UUID on restart, attach either volume to a different partner, or submit an
artifact collected with another host/realm tuple. To intentionally change the
admitted host or realm, archive the source artifacts, reset both volumes, pick
a new storage-pair UUID, and recollect from the new vantage point.

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
AGENTHOUND_HOST_ID: security-laptop
AGENTHOUND_NETWORK_REALM_ID: corp-lab
AGENTHOUND_STORAGE_PAIR_ID: 7bc1f56e-c890-4de5-9cc5-921797176fa6
```

The shipped Compose files intentionally have no defaults for the final three
values. Shell interpolation fails before container startup when any is absent.
Keep the same values for the lifetime of the named volumes; the UUID above is
an example and must not be copied into a real deployment.

Port mappings bind to `127.0.0.1` on the host side — no external exposure by default.
