# AgentHound

Offensive security framework for AI agent infrastructure (BloodHound for the agentic stack). Two binaries: `agenthound` (lean collector, ~9.9 MiB) and `agenthound-server` (Neo4j + Postgres + React UI, binds 127.0.0.1:8080).

## Pre-Commit Checks (MANDATORY)

```bash
gofmt -l .                  # Must produce no output
go build ./...              # Must pass with zero errors
go vet ./...                # Must pass with zero warnings
go test ./... -race         # All tests pass with race detector
```

CI also runs: `golangci-lint` (errcheck + gofmt), `govulncheck`, `go-licenses check`, `scripts/deps-check.sh`, `scripts/size-check.sh`.

IMPORTANT: Before any release tag, run `make prerelease` — it gates on all release checks (version-check, gofmt, golangci-lint, vet, govulncheck, go-licenses, build, test -race, deps-check, size-check, slop-check, UI build, cross-compile). Never tag without a passing `make prerelease`.

### Release versioning (single source of truth)

The first `## vX.Y.Z` header in `CHANGELOG.md` is the SSOT for the human-maintained version. The binary / Docker / Homebrew versions are injected by GoReleaser from the git tag, so the only strings to bump are the install pins in `install.sh` and `README.md`.

Release prep: write the new `CHANGELOG.md` section, run `make sync-version` (rewrites both pins from the CHANGELOG), then `make prerelease`. `scripts/version-check.sh` runs as a `prerelease` step (and as a path-filtered CI job on `install.sh` / `README.md` / `CHANGELOG.md` changes); it fails if the pins or the pushed tag disagree with the CHANGELOG, so a mismatched version can never ship.

## Key Constraints

- **Deps boundary:** Collector binary MUST NOT link `chi`, `pgx`, `neo4j-go-driver`, or any `server/internal/` code. Enforced by `scripts/deps-check.sh`. Every new module needs its package added to `scripts/collector-allowlist.txt`.
- **Binary size:** Collector linux/amd64 stripped must stay within baseline + 10% (`scripts/size-check.sh`).
- **License allowlist:** `Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, Unlicense, Zlib`.
- **Neo4j compat:** Schema init detects version via `CALL dbms.components()` — use 4.4 (`ON...ASSERT`) or 5.x (`FOR...REQUIRE`) syntax.
- **TLS strict default:** Both MCP and A2A modules verify certs by default. `--insecure` opts in.
- **No application-layer auth:** Server is single-user, localhost-only. `OriginGuard` gates mutating endpoints — browser `Origin` must be in `AGENTHOUND_CORS_ORIGINS`; callers with no `Origin` (curl, the agenthound CLI, cron) pass through.
- **go:embed constraint:** Go forbids `..` in embed paths. Makefile copies `server/ui/dist` → `server/internal/api/ui/dist` before build.

## Module Registration

Modules self-register via `init()`. To add one:
1. Create `modules/<name>/`
2. Implement an action interface from `sdk/action/`
3. Add `register.go` calling `sdk/module.Register(...)`
4. Blank-import in `collector/cmd/agenthound/main.go`
5. Add package to `scripts/collector-allowlist.txt`

## Critical Architectural Facts

- **Node IDs:** Deterministic SHA-256 content-based. MCPServer ID MUST match between Config Collector and MCP Collector (the merge point).
- **value_hash:** SHA-256 of credential value. Cross-collector merge primitive. Every Looter MUST populate it on every emitted Credential. **Exception:** when a Looter cannot observe the raw credential value (e.g. LiteLLM masks upstream provider `api_key` via `/model/info`), it may synthesize a stable identity via `SHA-256("provider:name")` and mark the node `merge_key: "identity"`. The cross-service credential-chain processor explicitly filters these out of value_hash joins (`server/internal/analysis/processors/cross_service_credential_chain.go`), so synthetic identities cannot false-positive against real credentials.
- **Batch writes:** 1000 operations per Neo4j transaction. UNWIND + MERGE pattern.
- **Stale edge cleanup:** Only delete composite edges whose source_collector ran in current scan.
- **Post-processor order:** HAS_ACCESS_TO → CAN_EXECUTE → SHADOWS → POISONED_DESCRIPTION → POISONED_INSTRUCTIONS → CAN_REACH → cross_service_credential_chain → CAN_EXFILTRATE_VIA → CAN_IMPERSONATE → Cross-protocol CAN_REACH → RiskScore.
- **Poisoner safety:** Receipt persisted BEFORE mutation. Reverter is compile-time mandatory (embedded interface).

## Documentation Updates

IMPORTANT: When making changes that affect any of these, update the corresponding doc:
- New node/edge kinds → `docs/reference/graph-model.md`
- New CLI flags or verbs → `docs/reference/cli.md`
- New env vars or config → `docs/reference/configuration.md`
- New modules → `docs/contributing/modules.md` (if pattern changes)
- New post-processors → `docs/architecture/post-processors.md`
- API endpoint changes → `docs/reference/api.md`
- Risk scoring changes → `docs/reference/risk-scoring.md`
- New detection rules → `docs/reference/detection-rules.md`
- Deployment changes → `docs/operator/deployment.md`
- Security posture changes → `docs/operator/security.md`
- New docs page → add it to the `nav` in `mkdocs.yml` (Docs CI runs `mkdocs build --strict` on every docs PR, so an orphan page, broken link, or bad anchor fails the build; run `make docs-check` locally first).

## Quick Reference

| What | Where |
|------|-------|
| All docs | `docs/README.md` (navigation hub) |
| Graph schema (nodes, edges, IDs) | `docs/reference/graph-model.md` |
| CLI flags | `docs/reference/cli.md` |
| Module authoring guide | `docs/contributing/modules.md` |
| Architecture deep-dive | `docs/architecture/` |
| Ingest wire format | `sdk/ingest/` (Node, Edge, IngestData, GraphData) |
| Action interfaces | `sdk/action/` (Fingerprinter, Looter, Poisoner, Extractor, etc.) |
| Module registry | `sdk/module/` (Register, Get, ListByAction) |
| Post-processors | `server/internal/analysis/processors/` |
| Neo4j writer | `server/internal/graph/writer.go` |

## Tech Stack

Go 1.25.11 | cobra | chi/v5 | Neo4j 4.4+ | PostgreSQL 16 | pgx/v5 | MCP Go SDK v1.6.1 | React 18 + Vite 6 + React Flow + ELK | shadcn/ui + Zustand 5 + TanStack Query 5 | Docker Compose | GoReleaser v2 + cosign | Apache 2.0
