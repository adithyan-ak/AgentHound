# ADR 0001: Two-Binary Split — `agenthound` (collector) + `agenthound-server`

## Status

Accepted — 2026-04-25.

## Context

AgentHound's pre-1.0 development tree used a single Go binary. Version 1.0.0 was
the first public release and already contained the split described by this ADR.
The development binary bundled four very different responsibilities into one
artifact:

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
  ~9 MiB stripped on linux/amd64. Outputs JSON for the operator to transfer or
  explicitly pipe to the server ingest API/CLI; it has no built-in upload or
  server control channel.
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
  registry, and rules engine live under `sdk/`. The released ingest and action
  contracts document their v1 stability policies in their package docs.
- **Compile-time registration.** Action modules call `sdk/module.Register()`
  from `init()` and are blank-imported by the collector. Campaign scenarios use
  `sdk/campaign`; `protoscan` is an engine. Config/MCP/A2A enumeration remains a
  compatibility path driven by legacy collectors rather than `Enumerator`
  dispatch.
- **Auth, RBAC, audit, users, API tokens — deleted.** All gone. The current
  single-user Postgres baseline never creates `users`, `api_tokens`, or
  `audit_log`. `AGENTHOUND_JWT_SECRET`, `AGENTHOUND_ADMIN_PASSWORD`, and
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
  `chi`, `golang-jwt`, or `bcrypt`. A `deps-check` CI gate enforces that
  boundary going forward. (`go-jose` remains a legitimate collector
  dependency: `modules/a2a` uses it for JWS signature verification of A2A
  Agent Cards per RFC 7515, and it is explicitly on the collector
  allowlist — see `scripts/deps-check.sh` and
  `scripts/collector-allowlist.txt`.)
- Releases ship two binaries, two Homebrew formulas, two Docker images —
  but the GoReleaser config covers all of that in one job.
- The server's API surface shrinks. No `/api/v1/auth/*`, no
  `/api/v1/audit`. Authentication concerns disappear from request
  handlers.

Negative / accepted:

- **No multi-user support.** Single-user only. Anyone with network access
  to the server has full access to its data and API. Operators must scope
  network access accordingly.
- **Pre-launch database history is disposable.** Development Neo4j and
  Postgres state from before the single-user baseline must be dropped and
  recreated. There is no compatibility migration for the removed
  user/token/audit schema.
- **The pre-1.0 SDK was unstable.** At the time of this decision, type renames,
  removals, and signature changes were permitted across development versions.
  The released ingest and action contracts now document their v1 policies in
  their package docs.
- **Operators who need evasion features are on their own.** AgentHound is
  a transparent assessment tool. See `docs/operator/security.md`.

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
