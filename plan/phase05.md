# Phase 5: Hardening & Release

**Timeline:** Weeks 11–12
**Goal:** Production-quality MVP release — authentication, audit logging, error handling, documentation, comprehensive testing, performance validation, security review, release artifacts, and demo environment.

**Depends on:** All previous phases (1–4)

---

## 1. Pre-Phase Security Fixes (Audit Findings)

Phase 5 absorbs the remaining security findings from the Phase 1-2 audit. These are resolved as part of the hardening work — not as separate tasks, but woven into the relevant sections below. This section summarizes the mapping.

| Finding | Severity | Resolved In | Section |
|---------|----------|-------------|---------|
| **S1** Unauthenticated Cypher endpoint | CRITICAL | Auth middleware on all routes | §2.5, §2.6 |
| **S2** Unauthenticated ingest endpoint | CRITICAL | Auth middleware on all routes | §2.5, §2.6 |
| **S3** No auth on any endpoint | CRITICAL | Full auth system | §2 |
| **S5** CORS AllowedOrigins: `*` | HIGH | CORS tightened to configured origins | §1.1 |
| **S6** Internal error messages leaked | HIGH | Standardized error responses | §4.1 |
| **S7** No rate limiting | HIGH | Rate limiting middleware | §1.2 |
| **S9** Docker container runs as root | MEDIUM | Non-root container user | §1.3 |
| **S10** DB ports exposed on 0.0.0.0 | MEDIUM | Bind to 127.0.0.1 | §1.4 |
| **S11** JWS signature verification stub | MEDIUM | Complete A2A JWS verification | §1.5 |

### 1.1 Tighten CORS to Configured Origins [S5, HIGH]

**Problem:** `middleware/cors.go:11` — `AllowedOrigins: []string{"*"}` allows any website to hit the API. Once auth is added (JWT in cookies or headers), this becomes exploitable via cross-origin requests.

**Fix:** Replace wildcard with configurable origin list:

```go
// middleware/cors.go
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
    if len(allowedOrigins) == 0 {
        allowedOrigins = []string{"http://localhost:8080"}
    }
    return cors.Handler(cors.Options{
        AllowedOrigins:   allowedOrigins,
        AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders:   []string{"Authorization", "Content-Type"},
        AllowCredentials: true,
    })
}
```

Add `AGENTHOUND_CORS_ORIGINS` env var (comma-separated). Default to `http://localhost:8080` (embedded UI only).

**Verify:** `curl -H "Origin: https://evil.com" -I /api/v1/health` — no `Access-Control-Allow-Origin` header in response.

### 1.2 Add Rate Limiting Middleware [S7, HIGH]

**Problem:** No rate limiting on any endpoint. Expensive Cypher queries or rapid ingest requests can exhaust Neo4j/PG resources.

**Fix:** Add `go-chi/httprate` middleware:

```go
// Global: 100 requests/minute per IP
r.Use(httprate.LimitByIP(100, time.Minute))

// Per-endpoint tighter limits:
r.With(httprate.LimitByIP(10, time.Minute)).Post("/query", queryH.Handle)
r.With(httprate.LimitByIP(20, time.Minute)).Post("/ingest", ingestH.Handle)
```

**Verify:** 101st request within 1 minute returns 429 Too Many Requests.

### 1.3 Run Docker Container as Non-Root [S9, MEDIUM]

**Problem:** `docker/Dockerfile` has no `USER` directive. Process runs as root, increasing blast radius on compromise.

**Fix:** Add to the Dockerfile runtime stage:

```dockerfile
FROM alpine:3.19
RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1001 agenthound
COPY --from=builder /bin/agenthound /usr/local/bin/agenthound
USER 1001
EXPOSE 8080
ENTRYPOINT ["agenthound"]
CMD ["serve"]
```

**Verify:** `docker exec <container> whoami` returns `agenthound`, not `root`.

### 1.4 Bind Database Ports to Localhost [S10, MEDIUM]

**Problem:** `docker-compose.yml` uses short port syntax (`"7474:7474"`) which binds to `0.0.0.0`. Neo4j and PostgreSQL with hardcoded default credentials are accessible to anyone on the network.

**Fix:** Change all development port bindings to localhost:

```yaml
services:
  graph-db:
    ports:
      - "127.0.0.1:7474:7474"
      - "127.0.0.1:7687:7687"
  app-db:
    ports:
      - "127.0.0.1:5432:5432"
```

The `agenthound` service connects via Docker network names (`graph-db:7687`, `app-db:5432`), so it doesn't need host-exposed ports at all. The port mappings are only for local development tooling (Neo4j Browser, psql).

**Verify:** `nmap -p 7687 <host-ip>` from another machine shows port closed. `cypher-shell -a bolt://localhost:7687` still works.

### 1.5 Complete JWS Signature Verification for A2A Agent Cards [S11, MEDIUM]

**Problem:** `internal/collector/a2a/jws.go` is a stub — it detects the presence of the `signatures` field but always returns `valid=false`. Unsigned agent cards are flagged, but signed cards cannot be validated.

**Fix:**
1. Implement RS256 and ES256 verification per RFC 7515 (JSON Web Signature)
2. Support public key discovery from the agent card's `jwks` or `jwks_uri` field
3. Verify the `signatures` array: decode base64url header+payload, validate algorithm, check signature with discovered key
4. On success: set `signature_valid=true` on the A2AAgent node
5. On verification failure (bad signature, expired key, unknown algorithm): set `signature_valid=false` with `signature_error` property

**Exit criterion:** `TestJWSSignatureValid` passes using a test-signed agent card with a known keypair. `TestJWSSignatureInvalid` detects a tampered card.

### 1.6 Add `--discover-domain` Flag to A2A Collector CLI

**Problem:** Phase 2 planned `agenthound collect a2a --discover-domain example.com` for convenient domain-level probing. Not implemented — functionally a thin UX wrapper around `--target`.

**Fix:** In `internal/cli/collect_a2a.go`, add `--discover-domain` flag that constructs `https://<domain>/.well-known/agent-card.json` and passes the URL to the existing fetch pipeline. Accept multiple domains via comma separation.

**Exit criterion:** `agenthound collect a2a --discover-domain example.com` produces the same output as `agenthound collect a2a --target https://example.com`.

---

## 2. Authentication System

### 2.1 Strategy

MVP uses username/password + API tokens. No SSO/SAML/OIDC (deferred to v0.3).

**Roles:**
| Role | Permissions |
|------|------------|
| `admin` | All operations: manage users, execute raw Cypher, trigger scans |
| `analyst` | Read graph, run queries, trigger scans, view findings |
| `viewer` | Read-only: view graph, run pre-built queries |

### 2.2 Implementation Files

```
internal/auth/
├── auth.go            # Auth middleware + token validation
├── password.go        # bcrypt password hashing
├── session.go         # Session management (JWT)
├── token.go           # API token generation and validation
└── rbac.go            # Role-based access control checks
```

### 2.3 Password Authentication

```go
// POST /api/v1/auth/login
type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}
type LoginResponse struct {
    Token     string    `json:"token"`      // JWT
    ExpiresAt time.Time `json:"expires_at"`
    User      UserInfo  `json:"user"`
}
```

- Passwords hashed with bcrypt (cost=12)
- JWT tokens with 24h expiry, signed with HMAC-SHA256
- JWT secret from `AGENTHOUND_JWT_SECRET` env var (required in production)
- Refresh tokens (optional, 7-day expiry)

### 2.4 API Token Authentication

For programmatic access (CLI, CI/CD):

```go
// POST /api/v1/auth/tokens
type CreateTokenRequest struct {
    Name      string     `json:"name"`
    ExpiresAt *time.Time `json:"expires_at,omitempty"` // null = never
}
type CreateTokenResponse struct {
    Token string `json:"token"` // Shown once, stored as SHA-256 hash
    ID    string `json:"id"`
}
```

- Tokens prefixed: `ah_` for easy identification
- Stored as SHA-256 hash in PostgreSQL
- Sent via `Authorization: Bearer ah_xxx` header
- Last-used timestamp updated on each use

### 2.5 Auth Middleware

**Note [S1/S2/S3 fix]:** This middleware resolves all three "unauthenticated endpoint" findings. Once applied to the router, every non-public endpoint requires a valid JWT or API token.

```go
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 1. Check Authorization header
        token := extractToken(r)
        if token == "" {
            http.Error(w, "unauthorized", 401)
            return
        }

        // 2. Try JWT first, then API token
        user, err := validateJWT(token)
        if err != nil {
            user, err = validateAPIToken(token)
        }
        if err != nil {
            http.Error(w, "unauthorized", 401)
            return
        }

        // 3. Inject user into context
        ctx := context.WithValue(r.Context(), "user", user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

### 2.6 RBAC Middleware

```go
func RequireRole(roles ...string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := r.Context().Value("user").(*User)
            for _, role := range roles {
                if user.Role == role { next.ServeHTTP(w, r); return }
            }
            http.Error(w, "forbidden", 403)
        })
    }
}
```

**Route permissions:**
| Endpoint | Required Role |
|----------|--------------|
| `GET /api/v1/health` | None (public) |
| `GET /api/v1/graph/*` | viewer+ |
| `GET /api/v1/analysis/*` | viewer+ |
| `POST /api/v1/analysis/*` | analyst+ |
| `POST /api/v1/ingest` | analyst+ |
| `POST /api/v1/scans` | analyst+ |
| `POST /api/v1/query` | admin only |
| `POST /api/v1/auth/tokens` | analyst+ |
| `GET /api/v1/audit/*` | admin only |
| `POST /api/v1/auth/users` | admin only |

### 2.7 First-Run Setup

On first boot with empty users table:
1. Create default admin user: `admin` / `agenthound` (logged to stdout)
2. Log warning: "Change the default admin password!"
3. Optionally: `AGENTHOUND_ADMIN_PASSWORD` env var overrides default

---

## 3. Audit Logging

### 3.1 What Gets Logged

Every API action logged to `audit_log` table:

| Action | Details |
|--------|---------|
| `auth.login` | username, success/failure, IP |
| `auth.token_create` | token name, user |
| `ingest.upload` | scan_id, collector, node/edge counts |
| `scan.start` | scan type, targets |
| `scan.complete` | scan_id, duration, node/edge counts |
| `query.execute` | cypher (first 500 chars), user |
| `query.prebuilt` | query_id, user |
| `analysis.shortest_path` | source, target, algorithm |
| `user.create` | username, role |
| `user.delete` | username |

### 3.2 Implementation

```go
// internal/audit/logger.go
type AuditLogger struct {
    db *pgxpool.Pool
}

func (l *AuditLogger) Log(ctx context.Context, action string, details map[string]interface{}) error {
    user := auth.UserFromContext(ctx)
    userID := ""
    if user != nil { userID = user.ID }

    _, err := l.db.Exec(ctx,
        "INSERT INTO audit_log (action, user_id, details) VALUES ($1, $2, $3)",
        action, userID, details)
    return err
}
```

### 3.3 Audit API

```
GET /api/v1/audit?action=ingest.upload&limit=100&offset=0
GET /api/v1/audit?from=2026-04-01&to=2026-04-07
```

Admin-only endpoint.

---

## 4. Error Handling & Graceful Degradation

### 4.1 API Error Responses

**Note [S6 fix]:** This section resolves the "internal error messages leaked to clients" finding. Currently, handlers pass raw `err.Error()` to clients (e.g., `graph.go:23`, `query.go:36`, `health.go:30`), which can expose Neo4j URIs, connection strings, and schema details. The standardized error format below replaces all raw error leakage.

Standardized error format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid ingest data: meta.collector must be one of: mcp, a2a, config",
    "details": {
      "field": "meta.collector",
      "value": "unknown"
    }
  }
}
```

Error codes:
| Code | HTTP Status | Meaning |
|------|------------|---------|
| `VALIDATION_ERROR` | 400 | Invalid input |
| `UNAUTHORIZED` | 401 | Missing/invalid auth |
| `FORBIDDEN` | 403 | Insufficient role |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Duplicate resource |
| `NEO4J_ERROR` | 503 | Neo4j unavailable |
| `POSTGRES_ERROR` | 503 | PostgreSQL unavailable |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

**Implementation pattern:** Log full error server-side with `slog.Error(...)`, return generic message + request ID to the client:

```go
func writeInternalError(w http.ResponseWriter, r *http.Request, err error) {
    reqID := middleware.GetReqID(r.Context())
    slog.Error("internal error", "error", err, "request_id", reqID)
    writeJSON(w, http.StatusInternalServerError, ErrorResponse{
        Error: ErrorDetail{
            Code:    "INTERNAL_ERROR",
            Message: "An internal error occurred. Reference: " + reqID,
        },
    })
}
```

Replace every `writeError(w, 500, err.Error())` call across all handlers with `writeInternalError(w, r, err)`.

### 4.2 Graceful Degradation

| Failure | Behavior |
|---------|----------|
| Neo4j down | Health endpoint reports degraded. Graph endpoints return 503. Ingest queued (written to file). |
| PostgreSQL down | Health endpoint reports degraded. Auth works via JWT (stateless). Audit logging disabled. |
| Collector failure (single server) | Other servers continue. Failed server emitted as unreachable node. |
| Frontend asset missing | Go server returns 404. API still functional. |
| Post-processing failure | Ingest succeeds (raw data saved). Post-processing retried on next ingest. |

### 4.3 Structured Logging

All log output via `slog` (Go 1.21+):

```go
slog.Info("ingest complete",
    "scan_id", scanID,
    "nodes", result.NodesWritten,
    "edges", result.EdgesWritten,
    "duration", time.Since(start))

slog.Error("neo4j write failed",
    "error", err,
    "batch_size", len(nodes))
```

Log levels: debug, info, warn, error
Format: JSON in production (`--log-format json`), text in development

---

## 5. Documentation

### 5.1 Files to Create

| File | Contents |
|------|----------|
| `README.md` | Project overview, quickstart (5 min), feature list, screenshots |
| `docs/quickstart.md` | Detailed installation + first scan guide |
| `docs/architecture.md` | High-level architecture for contributors |
| `docs/cli-reference.md` | All CLI commands with examples |
| `docs/api-reference.md` | All API endpoints (or OpenAPI spec) |
| `docs/graph-model.md` | Node types, edge types for security analysts |
| `docs/detection-rules.md` | What AgentHound detects, mapped to OWASP |
| `CONTRIBUTING.md` | How to contribute (collectors, detection rules) |
| `CHANGELOG.md` | v0.1.0 release notes |
| `LICENSE` | Apache 2.0 |

### 5.2 OpenAPI Spec

Generate OpenAPI 3.0 spec for all API endpoints:

```yaml
openapi: "3.0.3"
info:
  title: AgentHound API
  version: "0.1.0"
  description: Graph-based attack path analysis for MCP + A2A agent infrastructure
paths:
  /api/v1/health:
    get:
      summary: Health check
      # ...
  /api/v1/graph/nodes:
    get:
      summary: List graph nodes
      parameters:
        - name: kind
          in: query
          schema: { type: string }
        - name: limit
          in: query
          schema: { type: integer, default: 100 }
      # ...
  /api/v1/analysis/shortest-path:
    post:
      summary: Find shortest attack path
      # ...
```

Use `swaggo/swag` or hand-write the spec. Serve at `GET /api/v1/docs`.

### 5.3 README Quickstart

```markdown
## Quickstart (5 minutes)

# 1. Start infrastructure
docker compose up -d

# 2. Scan your MCP configs
agenthound collect config --discover --output config-scan.json

# 3. Scan your MCP servers
agenthound collect mcp --discover --output mcp-scan.json

# 4. Ingest data
agenthound ingest config-scan.json
agenthound ingest mcp-scan.json

# 5. Open UI
open http://localhost:8080
```

---

## 6. Comprehensive Testing

### 6.1 Test Coverage Targets

| Package | Target | Strategy |
|---------|--------|----------|
| `internal/model/` | > 90% | Unit tests for all struct methods |
| `internal/ingest/` | > 85% | Unit tests + integration tests |
| `internal/graph/` | > 80% | Integration tests (require Neo4j) |
| `internal/collector/config/` | > 85% | Unit tests with fixtures |
| `internal/collector/mcp/` | > 75% | Unit tests + integration with mock server |
| `internal/collector/a2a/` | > 80% | Unit tests + HTTP mock tests |
| `internal/analysis/` | > 80% | Unit tests + integration tests |
| `internal/api/` | > 75% | HTTP handler tests |
| `internal/auth/` | > 85% | Unit tests for all auth paths |
| Overall | > 80% | `go test -coverprofile` |

### 6.2 Integration Test Suite

A full end-to-end test that:
1. Starts Docker containers (Neo4j + PostgreSQL) via testcontainers-go
2. Runs schema initialization
3. Runs all 3 collectors against test fixtures
4. Ingests all outputs
5. Runs post-processing
6. Verifies graph state (node counts, edge counts, composite edges)
7. Runs all 17 pre-built queries, verifies results
8. Tests API endpoints (health, nodes, edges, pathfinding)
9. Tests auth flow (login, token, RBAC)

### 6.3 E2E UI Tests (Playwright)

**Deferred from Phase 4.** E2E tests require the full stack (Neo4j + Postgres + seeded data + running server). Phase 4 delivered component tests (vitest + RTL, 34 tests) but not Playwright E2E. This section must implement them from scratch.

**Setup:** Install Playwright, configure `playwright.config.ts`, add `docker compose up` as test fixture, seed test data via `scripts/seed-test-data.sh`.

**Required tests (8):**
- Dashboard loads with data
- Graph Explorer renders
- Node click → Inspector
- Pathfinding flow
- Search flow
- Filter flow
- Scan Manager
- Query Library

### 6.4 Security Tests

| Test | What It Validates |
|------|-------------------|
| `TestNoHardcodedSecrets` | grep codebase for patterns: `sk-`, `ghp_`, `password=` |
| `TestCypherInjection` | Parameterized Cypher queries — input with Cypher syntax doesn't execute |
| `TestSQLInjection` | Parameterized SQL queries — input with SQL syntax doesn't execute |
| `TestAuthRequired` | All non-public endpoints return 401 without token |
| `TestRBACEnforced` | Viewer can't POST to admin endpoints |
| `TestPasswordHashing` | Passwords stored as bcrypt hashes, never plaintext |
| `TestTokenHashing` | API tokens stored as SHA-256 hashes |
| `TestJWTValidation` | Expired/invalid JWTs rejected |
| `TestCORSHeaders` | CORS allows configured origins only |
| `TestInputValidation` | Oversized payloads rejected (max 10MB) |

---

## 7. Performance Testing

### 7.1 Graph Scale Benchmarks

| Scenario | Nodes | Edges | Target |
|----------|-------|-------|--------|
| Small (single developer) | ~50 | ~100 | Ingest < 1s, query < 100ms |
| Medium (team) | ~500 | ~2000 | Ingest < 5s, query < 500ms |
| Large (enterprise) | ~5000 | ~20000 | Ingest < 30s, query < 2s |
| Stress test | ~50000 | ~200000 | Ingest < 5min, query < 10s |

### 7.2 Benchmark Tool

```go
// cmd/agenthound/bench.go
// agenthound bench --nodes 5000 --edges 20000
// Generates synthetic graph data, ingests, runs queries, reports timings
```

### 7.3 Frontend Performance

| Test | Metric | Target |
|------|--------|--------|
| 100 nodes graph load | Time to interactive | < 500ms |
| 1000 nodes graph load | Time to interactive | < 2s |
| 5000 nodes graph load | Time to interactive | < 5s |
| Node hover latency | Interaction delay | < 50ms |
| Shortest path highlight | Animation time | < 200ms |

Measure with Lighthouse and Chrome DevTools Performance tab.

---

## 8. Security Review Checklist

Self-audit before release:

| # | Check | Audit Finding | Status |
|---|-------|---------------|--------|
| 1 | No hardcoded secrets in source code | — | |
| 2 | All Cypher queries use parameterized inputs (no string concatenation) | — | |
| 3 | All SQL queries use parameterized inputs | — | |
| 4 | Authentication required on all non-public API endpoints | **S1, S2, S3** | |
| 5 | RBAC enforced per endpoint | **S1** (admin-only Cypher) | |
| 6 | Passwords hashed with bcrypt (cost >= 12) | — | |
| 7 | API tokens stored as SHA-256 hashes | — | |
| 8 | JWT tokens have reasonable expiry (24h) | — | |
| 9 | JWT secret is configurable via environment variable | — | |
| 10 | Input validation on all API endpoints (max payload size) | — | |
| 11 | Credential values from config collector are hashed by default | — | |
| 12 | CORS configured appropriately (not `*` in production) | **S5** | |
| 13 | Docker containers don't run as root | **S9** | |
| 14 | Neo4j and PostgreSQL credentials configurable (not hardcoded) | — | |
| 15 | No verbose error messages leak internal details to clients | **S6** | |
| 16 | Audit logging captures all security-relevant actions | — | |
| 17 | Dependency versions pinned in go.mod | — | |
| 18 | No known CVEs in dependencies (`govulncheck`) | — | |
| 19 | Rate limiting on all endpoints, tighter on query/ingest | **S7** | |
| 20 | Database ports bound to 127.0.0.1 in docker-compose | **S10** | |
| 21 | APOC procedures restricted to apoc.merge.*, apoc.algo.* | **S4** (done in Phase 3) | |

---

## 9. Release Artifacts

### 9.1 Docker Images

Published to GitHub Container Registry (GHCR):

```
ghcr.io/agenthound/agenthound:0.1.0
ghcr.io/agenthound/agenthound:latest
```

Multi-arch: `linux/amd64`, `linux/arm64`

### 9.2 CLI Binaries

Cross-compiled binaries:

| OS | Arch | Filename |
|----|------|----------|
| Linux | amd64 | `agenthound-linux-amd64` |
| Linux | arm64 | `agenthound-linux-arm64` |
| macOS | amd64 | `agenthound-darwin-amd64` |
| macOS | arm64 | `agenthound-darwin-arm64` |
| Windows | amd64 | `agenthound-windows-amd64.exe` |

Published as GitHub Release assets.

### 9.3 Release CI/CD

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - uses: actions/setup-node@v4
        with: { node-version: '20' }

      # Build frontend
      - run: cd ui && pnpm install && pnpm build

      # Cross-compile Go binaries
      - uses: goreleaser/goreleaser-action@v6
        with:
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # Build and push Docker images
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          push: true
          platforms: linux/amd64,linux/arm64
          tags: |
            ghcr.io/agenthound/agenthound:${{ github.ref_name }}
            ghcr.io/agenthound/agenthound:latest
```

### 9.4 GoReleaser Config

```yaml
# .goreleaser.yml
builds:
  - id: agenthound
    main: ./cmd/agenthound
    binary: agenthound
    env: [CGO_ENABLED=0]
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]

archives:
  - format: tar.gz
    name_template: "{{ .ProjectName }}-{{ .Version }}-{{ .Os }}-{{ .Arch }}"
    format_overrides:
      - goos: windows
        format: zip

checksum:
  name_template: 'checksums.txt'

changelog:
  sort: asc
  filters:
    exclude: ['^docs:', '^test:', '^ci:']
```

---

## 10. Demo Environment

### 10.1 Synthetic Test Data

Create a rich demo dataset that showcases all AgentHound features:

```
testdata/demo/
├── config_scan.json    # 2 agent instances, 6 MCP servers, credentials
├── mcp_scan.json       # 6 servers with 25 tools, 8 resources, 1 poisoned tool
├── a2a_scan.json       # 3 A2A agents, 1 with no auth, delegation chain
```

The demo data includes:
- **Critical path:** Agent → no-auth server → execute_sql → production DB
- **Exfiltration path:** Agent → prod DB + Slack send_message
- **Cross-protocol path:** External A2A agent → internal agent → MCP → prod DB
- **Tool poisoning:** One tool with `<IMPORTANT>` injection, SHADOWS another
- **Credential chain:** filesystem → .env → credential → database server
- **Unpinned packages:** 2 servers with `npx -y @pkg` (no version pin)
- **Unsigned A2A card:** 1 agent without JWS signatures
- **Instruction file poisoning:** CLAUDE.md with suspicious patterns

### 10.2 Demo Seed Script

```bash
#!/bin/bash
# scripts/seed-demo.sh
set -e

echo "Seeding demo data..."
agenthound ingest testdata/demo/config_scan.json
agenthound ingest testdata/demo/mcp_scan.json
agenthound ingest testdata/demo/a2a_scan.json

echo "Demo data loaded. Open http://localhost:8080"
echo ""
echo "Try these queries:"
echo "  agenthound query --prebuilt agents-shell-access"
echo "  agenthound query --prebuilt cross-protocol-paths"
echo "  agenthound query --prebuilt exfiltration-routes"
```

---

## 11. Final v0.1.0 Acceptance Criteria

The MVP is complete when ALL of these are true:

| # | Criterion | Test |
|---|-----------|------|
| 0a | **[S5]** CORS rejects requests from unconfigured origins | `curl -H "Origin: https://evil.com"` gets no ACAO header |
| 0b | **[S6]** No internal error details in API responses | 500 errors return generic message + request ID only |
| 0c | **[S7]** Rate limiting returns 429 on excess requests | 101st request/min returns 429 |
| 0d | **[S9]** Docker container runs as non-root user | `docker exec whoami` returns `agenthound` |
| 0e | **[S10]** DB ports not accessible from remote hosts | `nmap -p 7687,5432 <host-ip>` from LAN shows closed |
| 1 | `docker compose up` starts all containers, healthy in < 60s | Manual + CI |
| 2 | `agenthound collect config --discover` enumerates local MCP configs | Manual test |
| 3 | `agenthound collect mcp --discover` enumerates MCP servers | Manual test |
| 4 | `agenthound collect a2a --target <url>` fetches Agent Card | Manual test |
| 5 | `agenthound ingest <file>` loads data into Neo4j | Integration test |
| 6 | Post-processing computes composite edges (CAN_REACH, CAN_EXFILTRATE_VIA) | Integration test |
| 7 | UI Dashboard shows correct node counts and findings | E2E test |
| 8 | Graph Explorer renders nodes with correct colors and sizes | E2E test |
| 9 | Clicking a node shows Entity Inspector with properties | E2E test |
| 10 | Pathfinder: shortest path from agent to resource returns correct result | E2E test |
| 11 | All 17 pre-built queries execute and return results | Integration test |
| 12 | Auth: login, API token, RBAC all work | Security tests |
| 13 | Audit log captures all actions | Integration test |
| 14 | `govulncheck` reports no known vulnerabilities | CI |
| 15 | Test coverage > 80% | CI |
| 16 | Documentation covers installation, quickstart, CLI, API | Review |
| 17 | Docker images published to GHCR | Release CI |
| 18 | CLI binaries for Linux/macOS/Windows published | Release CI |
| 19 | Demo environment loads and showcases all features | Manual test |
| 20 | No hardcoded secrets in codebase | Security review |

---

## 12. Post-Release Checklist

After v0.1.0 tag:

- [ ] GitHub Release with changelog, binaries, Docker instructions
- [ ] README with badges (CI status, Go version, license)
- [ ] Open GitHub Issues for known limitations (labeled `v0.2`)
- [ ] Create GitHub Discussions for community Q&A
- [ ] Set up GitHub Actions for dependabot (Go + npm)
- [ ] Create `SECURITY.md` with vulnerability reporting instructions
- [ ] Tag `v0.1.0` and push to main

---

## 13. Risks and Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| JWT secret management in Docker | Medium | Document env var requirement. Provide `docker-compose.override.yml` example. |
| bcrypt performance on high-frequency auth | Low | Cache validated JWTs. Bcrypt only at login. |
| GoReleaser cross-compilation issues | Low | Test all platforms in CI. CGO_ENABLED=0 avoids most issues. |
| Demo data doesn't exercise all features | Medium | Checklist of features, verify each has demo data. |
| Documentation becomes stale quickly | High | Keep docs minimal. Auto-generate API reference from code. |
