---
paths:
  - "server/**"
---
# Server Development Rules

- API routes at /api/v1/*. Read endpoints open; mutating endpoints require localhost bearer token.
- Token auto-generated at first startup, persisted to ~/.agenthound/server.token (0o600).
- CORS: AllowCredentials=false. CORSOrigins configurable via AGENTHOUND_CORS_ORIGINS.
- Neo4j version compat: detect via CALL dbms.components(), branch on 4.4 vs 5.x constraint syntax.
- APOC fallback: all APOC-dependent code needs non-APOC fallbacks. APOC only required for Dijkstra.
- Batch writes: group by (primaryLabel, sortedUmbrellaLabels) tuple. 1000 ops/txn with UNWIND.
- go:embed constraint: server/ui/dist must be copied to server/internal/api/ui/dist before build.
- 18 pre-built queries in server/internal/analysis/prebuilt/
- 11 post-processors in server/internal/analysis/processors/ — execution order is dependency-driven
