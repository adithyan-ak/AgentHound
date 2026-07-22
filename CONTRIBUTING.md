# Contributing to AgentHound

## Getting started

```bash
git clone https://github.com/adithyan-ak/agenthound.git
cd agenthound
docker compose -f docker/docker-compose.yml up -d   # Neo4j + PostgreSQL + server
make build                                            # Build collector + server (UI auto-built)
make test                                             # Run all tests
```

Collection provenance and the database storage-pair UUID are automatic; no
identity environment variables are required.

`make build` invokes `make ui-build` first, which compiles the React UI (`server/ui`) and copies the output into `server/internal/api/ui/dist/` so `go:embed` finds it. Raw `go build ./...` also works on a fresh clone — a placeholder fallback page ships at `server/internal/api/ui/fallback/index.html`.

## Development workflow

1. Fork the repo and create a feature branch from `main`.
2. Make your changes.
3. Run pre-commit checks (mandatory):
   ```bash
   gofmt -l .          # Must produce no output
   go build ./...      # Must pass
   go vet ./...        # Must pass
   make test           # Must pass (race detector enabled)
   ```
4. Commit with a clear message describing what changed and why.
5. Open a PR against `main`.

CI additionally runs `golangci-lint`, `govulncheck`, `go-licenses`, `scripts/deps-check.sh` (collector dep-boundary), and `scripts/size-check.sh` (collector binary stays within baseline + 10%).

## Code style

- **Go:** `gofmt` formatting, `errcheck` compliance (handle all error return values).
- **TypeScript:** Prettier + ESLint (`cd server/ui && npm run lint`).
- **No manual alignment padding** — `golangci-lint` enforces this.
- **Intentionally discarded errors** use `_, _ =` (e.g., `_, _ = fmt.Fprintf(os.Stderr, ...)`).
- **Property keys** in collector JSON and Neo4j are canonical `snake_case`.
  Non-canonical keys are rejected before normalization.

## How to add a new module (collector / fingerprinter / looter)

Action modules live under `modules/` and self-register at init time. Config,
MCP, and A2A enumeration are current compatibility exceptions: their registry
entries describe the capability, while the CLI invokes their legacy collectors
directly. Do not use `Enumerator` as an extension point until the CLI dispatches
it.

1. Create a new directory: `modules/<name>/`.
2. Implement a currently dispatched action interface from `sdk/action/` — for
   example `Fingerprinter`, `Looter`, `Extractor`, `Poisoner`, or `Implanter`.
3. Add `register.go` calling `module.Register(...)` in `init()`.
4. Blank-import your module in `collector/cmd/agenthound/main.go`:
   ```go
   _ "github.com/adithyan-ak/agenthound/modules/<name>"
   ```
5. Produce JSON output matching `sdk/ingest.IngestData` (see
   `docs/reference/graph-model.md` for the schema). Node IDs must be
   deterministic SHA-256 hashes per `sdk/common`.
6. Add the module package and any new dependency packages to
   `scripts/collector-allowlist.txt`.
7. Add tests + fixtures under `modules/<name>/testdata/` (or repo-root
   `testdata/` for shared fixtures).

See `modules/README.md` for the canonical example and `modules/mcp/`, `modules/a2a/`, `modules/config/` for working modules.

## How to add a post-processor

Post-processors implement the `PostProcessor` interface in `server/internal/analysis/postprocessor.go`. They run after every ingest and compute composite edges from the raw graph state.

1. Create `server/internal/analysis/processors/<name>.go`.
2. Implement:
   ```go
   type PostProcessor interface {
       Name() string
       Dependencies() []string
       Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error)
   }
   ```
3. `Dependencies()` returns processor names that must run before this one (e.g. `CAN_REACH` depends on `HAS_ACCESS_TO`).
4. Register the processor by appending to `allProcessors()` in `server/internal/analysis/registry.go`.
5. Add `<name>_test.go` against the mock `GraphDB` in
   `server/internal/graph/mock_graphdb.go`.
6. If the detection should appear as a pre-built query, also add it under `server/internal/analysis/prebuilt/`.

## How to add a pre-built query

1. Add the Cypher constant to `server/internal/analysis/prebuilt/cypher.go`.
2. Register it in `server/internal/analysis/prebuilt/queries.go` with:
   - Unique ID (kebab-case).
   - Name, description, category, severity.
   - OWASP mapping (`MCP01`–`MCP10`, `ASI01`–`ASI10`).
3. The query is automatically available via the CLI (`agenthound-server query --prebuilt <id>`) and the API (`GET /api/v1/analysis/prebuilt/{id}`).

## How to add a config parser

Config parsers are `modules/config/parser_*.go` files in package `config` and
implement the `ConfigParser` interface defined in `modules/config/parser.go`.

1. Create `modules/config/parser_<client>.go`.
2. Implement:
   ```go
   type ConfigParser interface {
       ClientName() string
       ConfigPaths(homeDir string) []string
       Parse(path string, data []byte) (*ParsedConfig, error)
   }
   ```
3. `ConfigPaths()` returns platform-specific default config file locations.
4. Add the parser to the `parsers` slice in `NewConfigCollector()`.
5. Add parser cases to `modules/config/parsers_test.go` and any fixtures under
   `modules/config/testdata/<client>/`.

## How to add a detection rule (YAML)

Rules engine: `sdk/rules/`. Builtin rules: `sdk/rules/builtin/*.yaml`.

1. Create `sdk/rules/builtin/<id>.yaml` with `id`, `description`, `severity`, `matcher`, and (optionally) OWASP mapping. Matcher types: `keyword`, `prefix`, `regex`, `entropy`, `compound`. See existing files for examples.
2. Add a test fixture in `sdk/rules/builtin_tests/<id>.yaml` with sample inputs/expected matches. Test fixtures live OUTSIDE the runtime `//go:embed builtin` path — attacker-shaped strings never ship in production binaries.
3. Run `make test`. The Go rule tests attach fixtures from
   `sdk/rules/builtin_tests/`; the production CLI intentionally does not embed
   or load those fixtures.

## Testing

- All new features must include tests.
- Run `make test` for Go (race detector enabled), `cd server/ui && npm test` for frontend.
- Use `testdata/` fixtures for collector and ingest tests.
- Post-processor tests should verify edge creation against a known graph state
  via `server/internal/graph/mock_graphdb.go`.
- DB-touching tests skip locally unless `AGENTHOUND_NEO4J_URI` and a Postgres URI are set; CI runs them with services.

## Reporting bugs

Open a [GitHub issue](https://github.com/adithyan-ak/agenthound/issues) with:
- Steps to reproduce.
- Expected vs. actual behavior.
- AgentHound version (`agenthound version` and `agenthound-server version`).
- Neo4j version and OS.

## Security vulnerabilities

See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
