# ADR 0001: Two-Binary Split — `agenthound` (collector) + `agenthound-server`

## Status

Accepted — 2026-04-25.

## Context

AgentHound v0.x shipped as a single Go binary. That binary bundled four very
different responsibilities into one artifact:

1. **Field collection** — config-file parsing, MCP SDK enumeration, A2A HTTP
   probing.
2. **Graph storage** — Neo4j Bolt driver, Postgres `pgx/v5`, schema migrations.
3. **HTTP API + UI** — chi router, embedded React SPA via `go:embed`.
4. **Multi-user team server** — bcrypt password hashing, JWT issuance, API
   tokens, RBAC, audit log.

Two problems forced a split:

- **The vision is shifting toward a red-team field tool.** Operators want to
  drop a small static binary on a target host, run it, and ship JSON to a
  server they control. They do not want to land a 50+ MiB image that pulls
  Neo4j drivers, Postgres drivers, and a React bundle on a compromised box.
- **Multi-user team-server features were unused.** No deployment of AgentHound
  in the field had more than one operator. The auth/RBAC/audit code was
  >1 kLOC of Go that was never exercised under real load and could not be
  tested without provisioning Postgres. It was a maintenance tax with no
  corresponding benefit.

A SharpHound/BloodHound-style split addresses both:

- A lean **collector** drops on the target. Static binary, no DB clients,
  ~9 MiB stripped on linux/amd64. Outputs JSON or uploads it to a server.
- A **server** runs on the operator's laptop or on a hardened host they
  fully control. Single user, localhost-bound by default, no auth at the
  application layer.

## Decision

The repository is split along these lines, all top-level:

```
agenthound/
├── collector/        # `agenthound` binary entrypoint and CLI
├── server/           # `agenthound-server` binary entrypoint, internal/, ui/
├── sdk/              # Public Go SDK: ingest types, action interfaces, module registry, rules engine
├── modules/          # Self-registering enumeration modules (mcp/, a2a/, config/)
├── docker/           # Dockerfile.agenthound, Dockerfile.agenthound-server
└── scripts/          # deps-check.sh, size-check.sh
```

Concrete decisions:

- **Two binaries.** `agenthound` (collector) at `collector/cmd/agenthound`.
  `agenthound-server` at `server/cmd/agenthound-server`. Each is independently
  buildable and shippable.
- **Public Go SDK.** Ingest request/response types, action interfaces, module
  registry, and rules engine live under `sdk/`. Stability policy is documented
  in `sdk/ingest/doc.go` — versions before 1.0 are explicitly unstable.
- **Self-registering modules.** Each module under `modules/` has a `register.go`
  that calls `sdk/module.Register()` from `init()`. The collector's
  `main.go` blank-imports each module to bring it into the binary.
  Future modules slot in by adding a directory and a blank import, without
  touching shared code.
- **Auth, RBAC, audit, users, API tokens — deleted.** All gone. The
  `users`, `api_tokens`, and `audit_log` Postgres tables are dropped via
  migration. `AGENTHOUND_JWT_SECRET`, `AGENTHOUND_ADMIN_PASSWORD`, and
  `AGENTHOUND_API_TOKEN` env vars are removed.
- **Server binds 127.0.0.1:8080 by default.** Remote access is the
  operator's responsibility (VPN, SSH tunnel, Tailscale). The application
  layer does not authenticate; the network layer does.
- **Collector ships as a single static binary.** No Docker dependency in
  `install.sh`. Default install path is `$HOME/.local/bin` (no sudo).

## Consequences

Positive:

- Collector binary is ~9 MiB stripped (linux/amd64). Easy to land on a target
  host, easy to detect-and-evade for blue team analysis, fast to upgrade.
- The collector deps tree no longer includes `neo4j-go-driver`, `pgx`,
  `chi`, `go-jose`, `golang-jwt`, or `bcrypt`. A `deps-check` CI gate
  enforces that boundary going forward.
- Releases ship two binaries, two Homebrew formulas, two Docker images —
  but the GoReleaser config covers all of that in one job.
- The server's API surface shrinks. No `/api/v1/auth/*`, no
  `/api/v1/audit`. Authentication concerns disappear from request
  handlers.

Negative / accepted:

- **No multi-user support.** Single-user only. Anyone with network access
  to the server has full access to its data and API. Operators must scope
  network access accordingly.
- **Upgrading destroys existing user/token/audit data.** The first server
  startup after upgrade runs the drop-table migration. There is no
  data-preservation path because there is no equivalent storage in the
  new model.
- **Public SDK at `sdk/` is unstable until 1.0.** Type renames, removals,
  and signature changes are possible across pre-1.0 minor releases.
  Documented in `sdk/ingest/doc.go`.
- **Operators who need evasion features are on their own.** AgentHound is
  a transparent assessment tool. See `docs/security.md`.

## Alternatives considered

- **Keep monorepo with shared CLI and conditional builds.** Build tags
  could include or exclude server-only deps. Rejected — build tags are
  invisible at code-review time and lead to silent dependency drift. The
  explicit physical split is enforceable at the `go list -deps` boundary.
- **Two separate repos (BloodHound + SharpHound style).** Tighter
  isolation, but the two binaries share the SDK, the rules engine, the
  ingest types, and the module registry. Splitting to two repos forces a
  versioning ceremony for changes that are inherently cross-cutting.
  Rejected for now; revisit when the SDK reaches 1.0.
- **Plugin system for modules.** Go has no first-class shared-library
  plugin story that works across cross-compilation targets. Rejected as
  not idiomatic Go and not portable.

## References

- `docs/operator/security.md` — threat model and operational posture.
- `sdk/ingest/doc.go` — SDK stability policy.
- `scripts/deps-check.sh` — enforcement of the dep boundary.
