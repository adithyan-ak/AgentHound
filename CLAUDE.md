# AgentHound maintainer contract

AgentHound provides autonomous offensive collection and access verification for AI agent infrastructure.

- `agenthound` is the static foothold-time collector. It scans, plans, verifies, restores, and checkpoints one local JSON artifact.
- `agenthound-server` manually ingests artifacts, publishes the Neo4j graph and PostgreSQL finding state, and serves the API and dashboard.

## Required checks

Before committing:

```bash
make check
```

Changes spanning collection, planning, artifacts, ingestion, or findings also run `make integration`. Documentation changes run `make docs-check`.

Before a release tag, run `make prerelease` and `make docs-check`. Release tags are numeric SemVer without a `v` prefix. The first numeric heading in `CHANGELOG.md` is the version source of truth; `make sync-version` updates the installer pins in `README.md` and `install.sh`.

## Hard boundaries

- The collector must not link `chi`, `pgx`, `neo4j-go-driver`, or `server/internal` packages. `scripts/deps-check.sh` enforces the boundary.
- The stripped Linux amd64 collector must remain within the budget enforced by `scripts/size-check.sh`.
- Add every collector package and dependency to `scripts/collector-allowlist.txt`.
- Allowed dependency licenses are Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, Unlicense, and Zlib.
- TLS verification is enabled by default. Every AgentHound-owned connection uses the shared contact policy through the final dial.
- The server is single-user and binds to loopback by default. OriginGuard protects browser mutations; callers without an `Origin` header are inside the local-process trust boundary.
- PostgreSQL and Neo4j form one storage pair and must be backed up and restored together.
- Build the UI before the server so `server/internal/api/ui/dist` contains the files required by `go:embed`.

## Core invariants

- Node IDs are deterministic SHA-256 identities. Config and MCP collection must emit the same MCPServer identity for the same endpoint.
- Concrete credentials store raw material in `properties.value` and SHA-256 identity in `properties.value_hash`. Masks, hashes, and unresolved references never become planner input.
- Collectors return explicit observation domains and honest coverage outcomes. Partial evidence remains useful but cannot be recorded as action success.
- The planner uses deterministic candidates and completed-key deduplication. It contains no database, workflow language, policy engine, or model dependency.
- Recovery state is checkpointed into the scan artifact before mutation. Reversible actions restore immediately under a detached cleanup context and confirm the original before planning resumes.
- A complete raw-domain promotion retires the composite epoch. All registered processors rebuild against the current retained projection before publication.
- Neo4j writes use UNWIND and MERGE in bounded batches.

## Module registration

1. Implement the applicable interface under `sdk/action`.
2. Register the module with `sdk/module.Register` from its package `init()`.
3. Blank-import the package in `collector/cmd/agenthound/main.go`.
4. Add it to `scripts/collector-allowlist.txt`.
5. Add focused module, contact-policy, graph, and coverage tests.

The reversible ContextForge implementation backs the `mcp.description.roundtrip` planner action and must use the artifact Journal for recovery transitions.

## Documentation ownership

| Change | Canonical document |
|---|---|
| Commands and flags | `docs/reference/cli.md` |
| Environment and defaults | `docs/reference/configuration.md` |
| Scan behavior | `docs/operator/scanner.md` |
| Node or edge kinds | `docs/reference/graph-model.md` |
| API behavior | `docs/reference/api.md` and served OpenAPI |
| Analysis lifecycle | `docs/architecture/server-analysis.md` |
| Risk formulas | `docs/reference/risk-scoring.md` |
| Detection coverage | `docs/reference/detection-rules.md` |
| Module contract | `docs/contributing/modules.md` |
| Deployment or trust boundary | `docs/operator/deployment.md` and `docs/operator/security.md` |

Every page under `docs/` belongs in `mkdocs.yml`; strict Docs CI rejects broken links, bad anchors, and orphan pages.
