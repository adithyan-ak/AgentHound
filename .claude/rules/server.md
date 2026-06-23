---
paths:
  - "server/**"
---
# Server Development Rules

- API routes at /api/v1/*. Read endpoints open; mutating endpoints gated by `OriginGuard` (server/internal/api/middleware/originguard.go) — browsers must originate from `AGENTHOUND_CORS_ORIGINS`, callers with no Origin header (curl, CLI, cron) pass through.
- CORS and OriginGuard share `AGENTHOUND_CORS_ORIGINS` (default `http://localhost:8080,http://127.0.0.1:8080`). CORS: AllowCredentials=false.
- No chi `middleware.RealIP`: it rewrites RemoteAddr from spoofable X-Forwarded-For / X-Real-IP (GHSA-3fxj-6jh8-hvhx) and staticcheck flags it as deprecated (SA1019) at chi >=5.3.0. Server is localhost-only and nothing reads RemoteAddr. If ever placed behind a trusted reverse proxy, use chi 5.3.0's `middleware.ClientIP` (one of its 4 mutually-exclusive variants — no safe default) instead of re-adding RealIP.
- Neo4j version compat: detect via CALL dbms.components(), branch on 4.4 vs 5.x constraint syntax.
- APOC fallback: all APOC-dependent code needs non-APOC fallbacks. APOC only required for Dijkstra.
- Batch writes: group by (primaryLabel, sortedUmbrellaLabels) tuple. 1000 ops/txn with UNWIND.
- go:embed constraint: server/ui/dist must be copied to server/internal/api/ui/dist before build.
- 19 pre-built queries in server/internal/analysis/prebuilt/
- 15 post-processors in server/internal/analysis/processors/ — execution order is dependency-driven
