# Development setup

## Toolchain

| Tool | Purpose |
|---|---|
| Go version pinned in `go.mod` | Collector, server, tests, and tooling |
| Node.js 20+ | React UI build and tests |
| Docker with Compose v2 | Local storage stack and integration tests |
| golangci-lint | Go lint gate |

GoReleaser and cosign are useful for release work but are not required for normal development.

## Build

```bash
git clone https://github.com/adithyan-ak/agenthound.git
cd agenthound
make build
```

Useful focused targets:

| Target | Result |
|---|---|
| `make build-collector` | Build `bin/agenthound`. |
| `make build-server` | Build the UI and `bin/agenthound-server`. |
| `make ui-dev` | Start the Vite development server. |
| `make ui-test` | Run frontend tests. |
| `make check` | Run the required local pull-request checks. |
| `make security-check` | Check reachable Go vulnerabilities, binary licenses, and production dashboard dependencies. |
| `make integration` | Run the lean collector-to-ingest smoke test. |
| `make upstream-test` | Run the complete pinned-upstream compatibility harness. |
| `make deps-check` | Validate collector/server dependency boundaries. |
| `make size-check` | Check the stripped collector size budget. |
| `make docs-check` | Build the MkDocs site in strict mode. |

## Test

```bash
make check
make integration
```

Use `-short` to skip integration tests that require external databases. CI supplies Neo4j and PostgreSQL for database-backed suites.

## Local analysis stack

```bash
make up
make seed
make down
```

The server binds to `127.0.0.1:8080`; Neo4j and PostgreSQL also bind to loopback. The stack creates its collection and storage identities automatically.

## Repository layout

```text
collector/   collector CLI and planner orchestration
modules/     scanners, protocol collectors, service collectors, and action adapters
sdk/         ingest contract, action interfaces, contact policy, registry, and rules
server/      ingest, graph analysis, API, persistence, CLI, and UI
docker/      container builds and Compose definitions
scripts/     validation and release tooling
test-infra/  pinned upstream compatibility harness
docs/        operator, reference, architecture, and contributor manuals
```

## Release gate

`make prerelease` runs version consistency, contributor checks, pinned vulnerability and license checks, and canonical Linux, macOS, and Windows cross-builds. Run `make docs-check` separately for documentation changes.
