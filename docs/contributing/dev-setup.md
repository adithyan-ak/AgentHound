# Development Setup

Clone to green CI in 5 minutes.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.25.10 | Pinned in `go.mod` |
| Node.js | 20+ | UI build (Vite 6) |
| Docker + Compose | Latest stable | Integration tests, local Neo4j/Postgres |
| golangci-lint | v2.11+ | Linting (CI uses this exact version) |

Optional: `goreleaser` v2 for local release builds, `cosign` for signature verification.

## Clone and Build

```bash
git clone https://github.com/adithyan-ak/agenthound.git
cd agenthound
make build          # Builds both binaries (collector + server)
```

`make build` runs `make build-all` which:
1. `build-collector` -- produces `bin/agenthound`
2. `build-server` -- runs `ui-build` first (npm ci + vite build + copy to embed dir), then produces `bin/agenthound-server`

For collector-only work, `make build-collector` skips the UI build entirely.

## Run Tests

```bash
make test           # go test ./... -v -race -count=1
make lint           # golangci-lint run ./...
```

Unit tests run without external services (`-short` flag skips integration tests that need Neo4j/Postgres).

## Pre-Commit Checks (Mandatory)

Run before every commit:

```bash
gofmt -l .                  # Must produce no output
go build ./...              # Zero errors
go vet ./...                # Zero warnings
go test ./... -race         # All tests pass with race detector
```

CI will reject PRs that fail any of these.

## CI Structure

| Job | Trigger | What it does |
|-----|---------|--------------|
| `lint` | push + PR | golangci-lint, go-licenses check |
| `test-unit` | push + PR | `go test -short -race`, coverage gate (55%) |
| `build` | push + PR | Full build (UI + both binaries), deps-check, size-check |
| `test-integration` | PR only | Neo4j + Postgres in Docker, full ingest pipeline tests |
| `xplatform-build` | PR only | Cross-compile linux/amd64, darwin/arm64, windows/amd64 |
| `docker` | PR only | Validates all Dockerfiles build successfully |

## CI Gates (Blocking)

- **deps-check:** Collector binary must NOT link `chi`, `pgx`, `neo4j-go-driver`, or `server/internal/`. Server must NOT link MCP SDK or `modules/`.
- **size-check:** Collector linux/amd64 stripped binary must stay within baseline + 10%.
- **go-licenses:** Only Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, Unlicense, Zlib.
- **govulncheck:** Zero known vulnerabilities.

## Local Integration Environment

```bash
make up             # docker compose: neo4j:4.4 + postgres:16 + agenthound-server
make down           # tear down
make seed           # Load test data into running instance
```

## Directory Layout

```
collector/          # agenthound binary (CLI + module dispatch)
server/             # agenthound-server binary (API + ingest + analysis + UI)
sdk/                # Public SDK (ingest contract, action interfaces, module registry, rules engine)
modules/            # Self-registering modules (fingerprinters, looters, poisoners, etc.)
docker/             # Dockerfiles + compose
scripts/            # CI scripts (deps-check, size-check, seed)
testdata/           # JSON fixtures for ingest tests
docs/               # Architecture, API reference, contributing guides
```

## Useful Make Targets

| Target | Purpose |
|--------|---------|
| `make build-collector` | Collector binary only (fast iteration) |
| `make ui-dev` | Vite dev server with HMR |
| `make ui-test` | Frontend unit tests |
| `make deps-check` | Run dependency boundary validation locally |
| `make release` | Local GoReleaser snapshot (no publish) |
