# Contributing to AgentHound

## Start locally

```bash
git clone https://github.com/adithyan-ak/agenthound.git
cd agenthound
make build
make test
```

`make build` produces the collector and the server with its embedded UI. Collector-only work can use `make build-collector` without Node.js.

## Before opening a pull request

```bash
gofmt -l .
go build ./...
go vet ./...
go test ./... -race
make deps-check
make size-check
cd server/ui && npm test && npm run build
```

`gofmt -l .` must produce no output. CI also runs golangci-lint, govulncheck, license checks, integration tests, cross-compilation, Docker builds, UI architecture checks, and strict documentation validation.

## Repository conventions

- Go uses `gofmt`; all returned errors must be handled or explicitly discarded.
- TypeScript uses ESLint, Prettier, and the feature-sliced boundaries in `server/ui/ARCHITECTURE.md`.
- Public graph properties use canonical `snake_case` keys.
- Collector node IDs are deterministic SHA-256 identities.
- The collector cannot depend on server packages, database drivers, or UI code.
- New collector packages and dependencies must appear in `scripts/collector-allowlist.txt`.
- User-facing behavior changes require the corresponding manual or reference update.

## Common contribution paths

| Change | Guide or source |
|---|---|
| Service collector, fingerprinter, or planner action | [Writing modules](docs/contributing/modules.md) |
| Text or fingerprint rule | [Authoring rules](docs/contributing/authoring-rules.md) |
| Post-processor | `server/internal/analysis/postprocessor.go` and [Server Analysis](docs/architecture/server-analysis.md) |
| Prebuilt query | `server/internal/analysis/prebuilt/` |
| Config parser | `modules/config/parser.go` and adjacent parsers/tests |
| API endpoint | `server/internal/api/` and [API reference](docs/reference/api.md) |
| UI feature | [UI architecture](server/ui/ARCHITECTURE.md) |

All additions need focused tests. Use package-local `testdata/` for module fixtures and the repository `testdata/` directory only for shared ingest fixtures.

## Integration environment

```bash
make up
make seed
make down
```

Database-backed tests use `AGENTHOUND_NEO4J_URI` and `AGENTHOUND_PG_URI`. The compatibility harness under `test-infra/` exercises the collector against pinned upstream implementations.

## Reporting issues

Open a [GitHub issue](https://github.com/adithyan-ak/agenthound/issues) with reproduction steps, expected and actual behavior, both binary versions, operating system, and database versions where relevant.

Report vulnerabilities through the process in [SECURITY.md](SECURITY.md).
