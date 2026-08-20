# Configuration reference

Command-line flags take precedence over environment variables, which take precedence over defaults.

## Collector

| Environment variable | Related flag | Default | Meaning |
|---|---|---:|---|
| `AGENTHOUND_LOG_LEVEL` | — | `info` | `debug`, `info`, `warn`, or `error`. |
| `AGENTHOUND_OUTPUT` | `--output` | generated scan filename | Default artifact path. |
| `AGENTHOUND_QUIET` | `--quiet` | unset | `1` suppresses non-error progress and raw-secret output. |
| `AGENTHOUND_MCP_TOKEN` | — | unset | Bearer override for the ContextForge MCP surface. |
| `AGENTHOUND_CONTEXTFORGE_TOKEN` | — | unset | Management bearer override when ContextForge management uses a distinct origin. |

The collector writes a plain ingest V1 JSON artifact with file mode `0600` where supported. It includes raw Credential values, scan mode, normalized exclusions, action outcomes, and recovery state under `meta.extra.scan_execution`.

## Analysis server

| Environment variable | Related flag | Default |
|---|---|---|
| `AGENTHOUND_LOG_LEVEL` | `--log-level` | `info` |
| `AGENTHOUND_BIND` | `--bind` | `127.0.0.1:8080` |
| `AGENTHOUND_NEO4J_URI` | `--neo4j-uri` | `bolt://localhost:7687` |
| `AGENTHOUND_NEO4J_USER` | `--neo4j-user` | `neo4j` |
| `AGENTHOUND_NEO4J_PASSWORD` | `--neo4j-password` | `agenthound` |
| `AGENTHOUND_PG_URI` | `--pg-uri` | `postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable` |
| `AGENTHOUND_CORS_ORIGINS` | `--cors-origins` | `http://localhost:8080,http://127.0.0.1:8080` |

PostgreSQL and Neo4j form one storage pair. Back up and restore them together; the server verifies their shared binding marker during startup.
