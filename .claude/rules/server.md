---
paths:
  - "server/**"
---
# Server Development Rules

- API routes at /api/v1/*. Read endpoints open; mutating endpoints require localhost bearer token.
- Token auto-generated at first startup, persisted to ~/.agenthound/server.token (0o600).
- CORS: AllowCredentials=false. CORSOrigins configurable via AGENTHOUND_CORS_ORIGINS.
- No chi `middleware.RealIP`: it rewrites RemoteAddr from spoofable X-Forwarded-For / X-Real-IP (GHSA-3fxj-6jh8-hvhx) and staticcheck flags it as deprecated (SA1019) at chi >=5.3.0. Server is localhost-only and nothing reads RemoteAddr. If ever placed behind a trusted reverse proxy, use chi 5.3.0's `middleware.ClientIP` (one of its 4 mutually-exclusive variants — no safe default) instead of re-adding RealIP.
- Neo4j version compat: detect via CALL dbms.components(), branch on 4.4 vs 5.x constraint syntax.
- APOC fallback: all APOC-dependent code needs non-APOC fallbacks. APOC only required for Dijkstra.
- Batch writes: group by (primaryLabel, sortedUmbrellaLabels) tuple. 1000 ops/txn with UNWIND.
- go:embed constraint: server/ui/dist must be copied to server/internal/api/ui/dist before build.
- 18 pre-built queries in server/internal/analysis/prebuilt/
- 11 post-processors in server/internal/analysis/processors/ — execution order is dependency-driven
