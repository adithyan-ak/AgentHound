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
| `AGENTHOUND_QUIET` | `--quiet` | _(unset)_ | Set to `1` to suppress all non-error log output |
| `AGENTHOUND_LOG_JSON` | `--log-json` | _(unset)_ | Set to `1` for structured JSON logs to stderr |
| `AGENTHOUND_RULES_BUNDLE` | `--rules-bundle` | _(unset)_ | Path to a fingerprint rules bundle (directory or `.tar.gz`). Same-id rules override the embedded set. Verify cosign signature before use. |

Output file permissions: `0600` on POSIX. Atomic write via temp file + rename.

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
| `AGENTHOUND_CORS_ORIGINS` | `--cors-origins` | `http://localhost:8080` | Comma-separated allowed origins. `AllowCredentials: false`. |
| `AGENTHOUND_TOKEN_PATH` | _(none)_ | `~/.agenthound/server.token` | Path to the localhost Bearer token file. Also respects `XDG_CONFIG_HOME`. |

---

## State Directory (`~/.agenthound/`)

The server and offensive modules persist state under `~/.agenthound/`:

```
~/.agenthound/
  server.token                   # Auto-generated Bearer token (0600). UI fetches via /api/v1/auth/local-token.
  loot-acknowledged              # Marker file — operator acknowledged loot output risks
  poison-acknowledged            # Marker file — operator acknowledged poisoner risks
  extract-acknowledged           # Marker file — operator acknowledged extractor risks
  state/
    <module>/
      <engagement>.json          # Per-module engagement state (e.g. scanner session, poison undo log)
```

When `XDG_CONFIG_HOME` is set, the base path becomes `$XDG_CONFIG_HOME/agenthound/` instead.

---

## Localhost Token

The server auto-generates a random token on first startup (persisted at `server.token`, mode `0600`). Mutating API endpoints (`POST /api/v1/ingest`, `POST /api/v1/query`, path operations, scan CRUD) require `Authorization: Bearer <token>`. Read-only endpoints are open.

The embedded UI retrieves the token from `GET /api/v1/auth/local-token` (same-origin only, enforced via CORS). CLI commands (`agenthound-server ingest`, `query`) bypass HTTP and do not need the token.

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

Port mappings bind to `127.0.0.1` on the host side — no external exposure by default.
