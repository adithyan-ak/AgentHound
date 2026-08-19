# Configuration reference

The collector has no configuration file. The small environment surface is intentional; operational choices belong on `agenthound scan`.

## Collector

| Environment variable | Related flag | Default | Meaning |
|---|---|---:|---|
| `AGENTHOUND_LOG_LEVEL` | none | `info` | `debug`, `info`, `warn`, or `error`. |
| `AGENTHOUND_OUTPUT` | `--output` | `scan-<scan_id>.json` | Default artifact file when `--output` is not supplied. `-` and directories are rejected. |
| `AGENTHOUND_QUIET` | `--quiet` | unset | Value `1` suppresses progress, summaries, ingest hint, and discovered-secret output. |
| `AGENTHOUND_MCP_TOKEN` | none | unset | Advanced bearer override used only by the internal ContextForge adapter. Normal planner actions use the exact raw Credential node selected for the candidate. |
| `AGENTHOUND_CONTEXTFORGE_TOKEN` | none | unset | Management bearer override required only when ContextForge management is on a different origin from MCP. |

There is no concurrency setting, runtime rule directory/bundle, state directory, campaign credential, authorization sentinel, or remote-ingest setting.

The artifact is a plain ingest V1 JSON file with mode `0600` where supported. It contains raw Credential values and the complete action/recovery journal under `meta.extra.scan_execution`, including the normalized exclusions required to preserve the contact boundary during standalone recovery.

Collection identity remains automatic. AgentHound derives collection-point and network-context identity from local platform and routing evidence; there are no manual identity flags. Display hostname, OS, and architecture do not participate in merge identity.

## Server

| Environment variable | Flag | Default |
|---|---|---|
| `AGENTHOUND_LOG_LEVEL` | `--log-level` | `info` |
| `AGENTHOUND_BIND` | `--bind` | `127.0.0.1:8080` |
| `AGENTHOUND_NEO4J_URI` | `--neo4j-uri` | `bolt://localhost:7687` |
| `AGENTHOUND_NEO4J_USER` | `--neo4j-user` | `neo4j` |
| `AGENTHOUND_NEO4J_PASSWORD` | `--neo4j-password` | `agenthound` |
| `AGENTHOUND_PG_URI` | `--pg-uri` | `postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable` |
| `AGENTHOUND_CORS_ORIGINS` | `--cors-origins` | `http://localhost:8080,http://127.0.0.1:8080` |

The server accepts manual file/CLI ingest and retains the full artifact execution journal. It exposes no collector callback, action-ticket stream, witness export, or campaign endpoint.

PostgreSQL and Neo4j remain an inseparable storage pair. Back up and restore them together. The server verifies their shared binding marker on startup.
