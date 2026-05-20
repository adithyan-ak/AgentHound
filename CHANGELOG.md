# Changelog

## Unreleased

Test coverage hardening (post-v0.5.0).

## v0.5.0

The "extract" milestone — ships the last offensive verb and closes the full DC35 demo arc (scan → discover → loot → poison → revert → extract).

### `agenthound extract` — embedding-inversion PoC

- Pure Go GGUF parser (`modules/embeddinginvert/gguf.go`): reads magic, version, metadata KVs (tokenizer vocabulary), tensor info, seeks to data section. Supports F32 + Q8_0 dequantization. Zero external dependencies.
- Statistical outlier detection: computes per-row L2 norms on the embedding matrix, flags z-score outliers above configurable threshold, maps outlier indices to tokenizer vocabulary strings from GGUF metadata. Emits `ExtractedTrainingSignal` nodes + `EXTRACTED_FROM` edges.
- CLI verb: `agenthound extract <source-node-id> --type embedding-invert --artifact <path> [--commit] --engagement-id <id>`. Same safety gates as Poisoner (AUTHORIZED prompt + sentinel, --commit=false default).
- Schema: `ExtractedTrainingSignal` node kind (23 collector kinds), `EXTRACTED_FROM` edge (17 raw, 25 total).
- All offensive verb stubs now implemented — zero stubs remain.

### Infrastructure

- Size-check baseline rebased from 9.4 MiB (prototype era) to 9.8 MiB (v0.4 post-ship). Gives future work ~985 KiB headroom within the +10% CI gate.
- Inter-process receipt flock locking (`sdk/module/flock_unix.go`, `flock_other.go`): advisory file lock via `flock(2)` on unix, directory-lock fallback on other platforms. Eliminates the documented race in `WriteReceipt` where concurrent processes on the same engagement-id could silently drop receipts.
- `golang.org/x/sys/unix` added to collector allowlist (flock dependency).

## v0.4.0

## v0.3.0

The "broaden the scan surface, harden the operations" milestone. v0.2 turned the credential-chain pitch into a recordable demo with two fingerprinters and one Looter; v0.3 triples the scan surface, ships the rules-bundle update path, and introduces the FlagsModule sidecar pattern that v0.4's destructive primitives are built on.

### Schema additions

- New node kind `:AIModel` (`AllowedNodeKinds` 21 → 22, `AllNodeLabels` 23 → 24). Emitted by the Ollama Looter — one node per `/api/tags` entry, properties from `/api/show` (modelfile, family, parameters, fine-tune flag).
- New edge kind `PROVIDES_MODEL` in both `RawEdgeKinds` and `AllowedEdgeKinds` (15 → 16 raw; 23 → 24 total). Direction: `OllamaInstance -[:PROVIDES_MODEL]-> AIModel`. The model artifacts are owned, not exposed — distinct from `:EXPOSES`.
- `AIModel` is NOT in `UmbrellaLabels` — it gets its own uniqueness constraint via the existing schema-init loop. Cross-collector merge primitive is `value_hash` on the modelfile content (same SHA-256 hash → same node).

### Three new fingerprinters

- **vLLM** (`modules/vllmfp/`) — GET `/v1/models` returning the canonical OpenAI list shape. Default port 8000.
- **Open WebUI** (`modules/openwebuifp/`) — GET `/api/version` for identity + GET `/api/config` to capture `ollama.base_url`. **First emitter of `:EXPOSES`** — the captured backend URL drives an `OpenWebUIInstance -[:EXPOSES]-> OllamaInstance` edge with the writer's MERGE-by-objectid semantics handling not-yet-discovered Ollama nodes via placeholder write. Falls back to single-probe match when `/api/config` is auth-locked. Default port 3000.
- **Jupyter** (`modules/jupyterfp/`) — GET `/api/status` returning the canonical Jupyter status JSON. Default port 8888.
- All three rules ship in `sdk/rules/builtin/fingerprints/{vllm,openwebui,jupyter}.yaml`. The networkscan default port set already covered all three; no scanner change needed.

### Ollama Looter — second concrete `Looter`

- `agenthound loot <host> --type ollama` extracts model inventory + modelfiles via two anonymous GETs (`/api/tags`, `/api/show`). Implemented in `modules/ollamaloot/`.
- Each emitted `:AIModel` carries `value_hash` over the modelfile content — the cross-collector merge primitive extends to model artifacts, so the same fine-tune leaked via Ollama matches the same modelfile discovered through any future collector.
- Two flag-gated extras (default OFF, opt-in only):
  - `--include-weights` + `--weights-dir <path>` — streams `/api/blobs/<digest>` to disk. Multi-GiB. Bandwidth-heavy. Loud. SHA-256 + bytes-written recorded on the AIModel node.
  - `--include-embeddings` — single POST `/api/embeddings` to confirm the inference compute path is consumable. The Looter contract is GET-only by default; this POST is the documented exception, allowed because it is read-only-in-effect on the target. Gated because operator-billed compute is the cost.
- GET-only contract enforced by `get_only_test.go` with an explicit allowlist for the two POST exceptions (`/api/show` is a "lookup with a body"; `/api/embeddings` per above).
- Modelfile / template / system-prompt content NOT promoted onto the node by default — only `value_hash` + size + has-system-prompt boolean. `--include-credential-values` opts into raw modelfile content, mirroring the LiteLLM Looter.

### `FlagsModule` sidecar interface

- New `sdk/module/flags.go` declares `type FlagsModule interface { RegisterFlags(*pflag.FlagSet) }` as a pure side-interface. Modules that need per-module CLI flags add the method; modules that don't, don't.
- `module.RegisterFlagsFor(cmd, m)` helper does the type-assert in one call so action subcommands (`agenthound loot` etc.) don't repeat the boilerplate.
- `agenthound loot --help` lists every per-module flag from every registered Looter at command-construction time — operators discover module-specific flags without having to specify `--type` first. Per-module flag values flow into `LootOptions.Extras` (new field on the v0.2 `LootOptions` struct) at dispatch time.
- The Ollama Looter is the first consumer (`--include-weights`, `--weights-dir`, `--include-embeddings`).

### Rules-bundle loader and signed-tarball release

- New `sdk/rules/bundle.go` — `LoadFingerprintBundle(path) ([]FingerprintRule, error)` accepts a directory of `*.yaml` files OR a `*.tar.gz` archive. `MergeFingerprintRules(base, override)` merges with same-id-wins semantics, so a hot-fix bundle replaces a broken embedded rule without rebuilding the binary.
- New collector flag `--rules-bundle <path>` (also via `AGENTHOUND_RULES_BUNDLE` env var). Set once at root command init via `rules.SetBundleOverridePath`; transparent to every fingerprinter that calls `rules.LoadFingerprints`.
- New CI workflow `.github/workflows/rules-bundle.yml` with `workflow_dispatch` + `on: push: tags: ['rules-v*']` triggers (no `on: schedule` — bundles are content-driven). Steps: tar `sdk/rules/builtin/fingerprints/`, cosign-sign keyless via OIDC, upload tarball + sha256 + sig + pem as GitHub release assets. Defense-in-depth: every step touching the resolved tag goes through env vars (`TAG`, `TARBALL`, `INPUT_TAG`, `REF_NAME`) instead of direct `${{ }}` interpolation in shell, with regex whitelisting of the tag format.
- See `docs/rules-bundle.md` for the operator guide. Mandatory cosign verification (refuse to load unsigned bundles) is deferred to v0.5 once the release pipeline has cut at least one bundle.

### `agenthound discover` — new CLI verb

- New `protoscan` module (`modules/protoscan/`) implements the v0.3 `Discover` action. Two probe modes:
  - **MCP**: HTTP POST JSON-RPC `initialize` against `/` and `/mcp`; matches on canonical `{"jsonrpc":"2.0","result":{"serverInfo":{...},"capabilities":{...}}}` shape.
  - **A2A**: HTTP GET `/.well-known/agent-card.json` (with legacy `/.well-known/agent.json` fallback); matches on agent-card shape (`name` + (`url` OR `supportedInterfaces`)).
- `agenthound discover <CIDR|host|@file>` — distinct from `agenthound scan` (the AI-service port sweeper). Default ports: MCP {3000, 8000, 8080, 8443}, A2A {80, 443, 3000, 8080}. `--mcp` / `--a2a` flags scope to one protocol; default is both.
- Reuses `modules/networkscan/expand.go` for CIDR safety gates AND `requireAuthorizedPrompt` from `scan.go` — same `--allow-public-targets`, `--allow-large-cidr`, `--authorization-file` controls.
- New action constant `action.Discover` in `sdk/action/action.go`. Two registered modules: `mcp.discover`, `a2a.discover`. See `docs/discover.md`.

### Risk-breakdown panels for v0.2 emitters

- `server/ui/src/components/inspector/RiskBreakdown.tsx` adds `OllamaInstance` and `LiteLLMGateway` to `COMPONENT_KEYS`, eliminating the "Risk breakdown not available" fallback for the v0.2 AI-service kinds. Component values land on the node via the v0.3+ RiskScore post-processor extension; until that lands, values surface as 0 (honest signal — "we know the kind, no computed risk yet").

### UI palette finalization

- All eight v0.3+ AI-service stroke colors finalized in `server/ui/src/theme/tokens.ts` and synced to `server/ui/src/lib/explorer/hex-config.ts`. LangServeApp moved to chartreuse `#9CCC65` to clear the prior collision with the AIService umbrella `#7E57C2`. JupyterServer moved to deep orange `#F57C00` to clear the prior collision with `MCPPrompt #FB923C`.
- New `:AIModel` palette entry — deep purple `#6A1B9A`, `Boxes` icon, column 3, group "AI Models". Distinct from MCPResource red, A2AAgent purple, and AIService umbrella purple.

### Demo lab

- New `docker/demo/docker-compose.yml` adds vLLM stub, Open WebUI stub (proxying to the v0.2 Ollama service), Jupyter stub, and an MCP discovery target on subnet 172.30.0.0/24 (distinct from v0.2's 172.20.0.0/24 so both labs coexist).
- `scripts/seed-demo.sh` drives the full v0.3 demo arc: scan + discover + LiteLLM loot + Ollama loot, with a preloaded `support-agent-v3` fine-tune for the modelfile-leak narrative beat.
- DEF CON 35 main-stage CFP abstract draft in `docs/cfp/defcon-35-abstract.md`.

### Hardening

- `archive/tar` and `os/user` (transitively pulled by the rules-bundle loader) added to `scripts/collector-allowlist.txt` after audit — both are stdlib with no outbound network calls.
- Collector linux/amd64 stripped binary stays well within the +10% size cap (~9.6 MiB vs. 9.4 MiB baseline).

## v0.2.0

Offensive primitives milestone — turns AgentHound's credential-chain pitch from theory into a recordable demo. The architecture seam this introduces (multi-label nodes, `value_hash` cross-collector merge, fingerprinter dispatch via the rules engine) is the substrate every v0.3+ collector and Looter builds on.

### Network scanner

- New `agenthound scan <CIDR|host|@file>` mode — TCP port sweep against a fixed AI-service port set (Ollama 11434, LiteLLM 4000, vLLM/LangServe 8000, Qdrant 6333, MLflow 5000, Jupyter 8888, Open WebUI 3000) with a fixed-size worker pool (default 50). Implemented in `modules/networkscan/`.
- Safety controls: `--allow-public-targets` with interactive AUTHORIZED prompt; `--allow-large-cidr` for CIDRs above /16; `--authorization-file` watermark recorded in scan-output `meta.extra`. Link-local and multicast addresses refused unconditionally.
- CIDR/host expansion via `net/netip` — handles IPv4 + IPv6, single hosts, file-of-hosts, DNS names. Cancellation via `ctx.Done()` produces partial output rather than aborting empty.
- See `docs/scanner.md` for the operator guide.

### Two new fingerprinters

- **Ollama fingerprinter** (`modules/ollamafp/`) — GET `/api/version` returning `{"version": "X.Y.Z"}`. Captures version into the emitted node.
- **LiteLLM fingerprinter** (`modules/litellmfp/`) — GET `/health/liveliness` returning `"I'm alive!"`.
- Both emit multi-label nodes (`:OllamaInstance:AIService`, `:LiteLLMGateway:AIService`) per the new Option B schema.
- Backed by the new `sdk/rules/fingerprint.go` HTTP probe orchestrator with six matcher types: `http_status`, `http_header`, `body_equals`, `body_contains`, `body_regex`, `json_path` (minimal subset: `$`, `$.field`, `$.field.subfield`).
- YAML rule files at `sdk/rules/builtin/fingerprints/{ollama,litellm}.yaml`.

### LiteLLM Looter — first concrete `Looter`

- `agenthound loot <host> --type litellm --master-key sk-...` extracts upstream provider credentials via three GET-only probes: `/model/info` (upstream provider keys), `/key/list` (virtual keys), plus the master key Credential itself. Implemented in `modules/litellmloot/`.
- All emitted Credentials carry `value_hash` — the cross-collector merge primitive. Same secret seen as an env var by the Config Collector lights up the new `cross_service_credential_chain` post-processor finding without code changes downstream.
- AUTHORIZED prompt + `~/.agenthound/loot-acknowledged` sentinel on first invocation. `--engagement-id <id>` recorded on every emitted edge's evidence map and slog line. Master key never appears in slog output (8-char prefix redaction; regression test `redaction_test.go` enforces).
- GET-only contract enforced by `get_only_test.go`. Looter is read-only by design — any future POST-emitting probe is a Poisoner, not an addition here.
- See `docs/loot-litellm.md` for the audit-trail residue caveat.

### Schema additions

- 9 new node kinds: 8 per-service (`OllamaInstance`, `VLLMInstance`, `QdrantInstance`, `MLflowServer`, `LiteLLMGateway`, `JupyterServer`, `LangServeApp`, `OpenWebUIInstance`) + `AIService` umbrella label that every per-service node also carries (multi-label).
- 2 new edge kinds in BOTH `AllowedEdgeKinds` AND `RawEdgeKinds`: `EXPOSES` (reserved for v0.3 Open WebUI → Ollama backend) and `EXPOSES_CREDENTIAL` (LiteLLM Looter emits this).
- New `UmbrellaLabels` map in `sdk/ingest/kinds.go` so the schema-init loop in `server/internal/graph/schema.go` skips uniqueness constraints on `:AIService` (the umbrella is multi-labeled — constraining it would falsely collide between distinct per-service nodes).
- New `value_hash` property on `:Credential` — populated by every Credential emitter (Config Collector, LiteLLM Looter). Cross-collector merge primitive computed via `sdk/common.HashCredentialValue` (SHA-256). Documented as load-bearing for the credential-chain demo.

### Multi-label writer

- `server/internal/graph/writer.go` rewritten to group nodes by full `(primary, sortedExtras)` tuple instead of just `Kinds[0]`. Each tuple gets its own cached Cypher template that MERGEs on the per-kind label and SETs the umbrella label(s). The original single-label writer code path is preserved for backward compat.

### `cross_service_credential_chain` post-processor

- New post-processor (`server/internal/analysis/processors/cross_service_credential_chain.go`) joins on `Credential.value_hash` between Config Collector emissions (`MCPServer-[HAS_ENV_VAR]->Credential`) and LiteLLM Looter emissions (`LiteLLMGateway-[EXPOSES_CREDENTIAL]->Credential`), then emits `(:AgentInstance)-[:CAN_REACH]->(:Credential)` for every upstream provider Credential the gateway exposes.
- Dependencies: `["has_access_to", "can_reach"]`. Runs in the analysis pipeline after the existing `CanReach` processor.
- New pre-built query `litellm-credential-leak` in the `Critical Paths` category surfaces the finding via `GET /api/v1/analysis/prebuilt/litellm-credential-leak`. Total prebuilt query count goes 17 → 18.

### CLI surface

- Real `agenthound loot` cobra command replacing the v0.1 stub. `agenthound loot <host> --type <kind>` dispatches via `module.GetByTarget(target, action.Loot)`. Three remaining stubs (`extract`, `poison`, `implant`) preserved — those are v0.4.
- `agenthound scan` extended with the network-scan positional argument while preserving v0.1 `--config / --mcp / --a2a` flag behavior.

### Demo lab

- New `docker/demo/docker-compose.yml` — Ollama + LiteLLM stub + operator container with a Claude Desktop config that references the LiteLLM master key by env var. `scripts/seed-demo.sh` drives the full lab end-to-end (scan + config + loot → ingest → cross-collector chain finding).

### Hardening

- Allowlist enforcement on collector deps via `scripts/deps-check.sh` — every new module in this milestone added explicitly.
- UI placeholder color + icon plumbing for all 8 service kinds (Ollama and LiteLLM final; six others stubbed for v0.3/v0.4).

## v0.2.0-pre (post-v0.1 trunk consolidation)

The post-v0.1 trunk reshaped AgentHound around a two-binary split and a single-user analysis posture before the v0.2 offensive primitives shipped. The most consequential changes:

### Two-binary split

- AgentHound now ships as `agenthound` (lean field collector, ~9 MiB stripped on linux/amd64) and `agenthound-server` (Neo4j-backed analysis server with embedded React UI). See `docs/adr/0001-two-binary-split.md`.
- The collector links no Neo4j driver, no Postgres driver, no chi router, and no `server/internal/` code. CI gates the boundary via `scripts/deps-check.sh` and the linux/amd64 stripped size via `scripts/size-check.sh` (baseline + 10%).
- Collector writes scan JSON to a file or stdout. Three ingest paths to the server: file copy + `agenthound-server ingest <file>`, stdin pipe (`agenthound scan --output - | ssh op-box 'agenthound-server ingest -'`), or UI drag-drop import.

### Authentication removed at the application layer

- Removed: bcrypt password hashing, JWT sessions, `ah_`-prefixed API tokens, RBAC (admin/analyst/viewer), first-run admin user, audit logging, all `users` / `api_tokens` / `audit_log` Postgres tables, and the corresponding API endpoints (`/api/v1/auth/login`, `/auth/tokens`, `/auth/users`, `/audit/*`).
- Replaced with: a single 32-byte localhost bearer token, auto-generated at first server start, persisted to `~/.agenthound/server.token` (0o600), gating only the seven mutating endpoints (`POST /ingest`, `POST /query`, `POST /scans`, `DELETE /scans/{id}`, `POST /analysis/shortest-path`, `POST /analysis/all-paths`, `POST /analysis/weighted-path`). Path is overridable via `AGENTHOUND_TOKEN_PATH` or `XDG_CONFIG_HOME`.
- Read endpoints remain open. CORS uses `AllowCredentials: false` so a hostile origin cannot exfiltrate the token via a credentialed fetch.
- The 127.0.0.1 default bind is the security control. See `docs/security.md`.

### Rate limiting removed

- All rate limiting (httprate-based 100/min general, 20/min ingest, 10/min raw Cypher) was removed (commit `e97e043`). Single-user posture; the network layer is the access control.

### Frontend stack migrated to React Flow + ELK

- Graph visualization migrated from Sigma.js + graphology + ForceAtlas2 to `@xyflow/react` 12.6 + `elkjs` 0.9.3. DOM-based, suitable for the small-to-medium graphs typical in attack-path views.
- Dashboard reworked: ByteArmor-inspired dark theme; new widgets (exposure score, credential gauge, cross-protocol stat); risk distribution replaced with findings-by-category treemap; added Top Risky Entities; per-widget info tooltips.

### Detection rules engine

- Detection logic migrated from hardcoded Go functions to a YAML-based rules engine. 30 builtin rules in `sdk/rules/builtin/*.yaml` covering capability classification, credential extraction, prompt-injection patterns, instruction-file poisoning, and resource-sensitivity. Rules wired through every collector.
- New CLI: `agenthound rules list|validate|test`.
- New API: `GET /api/v1/rules`, `GET /api/v1/rules/{id}`.
- New UI page: Detection Rules viewer.

### CLI surface

- `agenthound collect config|mcp|a2a` was unified into a single `agenthound scan` verb with collector-selection flags (`--config`, `--mcp`, `--a2a`).
- Stub verbs `agenthound loot|extract|poison|implant` added — print "not yet implemented" today, reserve the verb space for the v0.2 offensive-primitives milestone.

### Hardening

- CSRF lockdown via the localhost-token gate; OpenAPI spec at `server/internal/api/handlers/openapi.yaml` reconciled against the actual route map (CI-checked via `diff`).
- Race fix in the collector pipeline; UUID scan IDs.
- EDR-bait test fixtures moved out of the runtime `//go:embed builtin` path to `sdk/rules/builtin_tests/` so attacker-shaped strings never ship in production binaries.
- Loopback-bind enforced on the standard Docker image.

### Infrastructure

- GoReleaser v2 with cosign keyless signing and syft SBOMs. Two builds, two Homebrew formulas (`agenthound`, `agenthound-server`), multi-arch Docker images.
- `install.sh` with checksum + cosign verification, atomic temp-rename install.
- Three Docker images: `Dockerfile.agenthound` (collector, no UI/DB clients), `Dockerfile.agenthound-server` (server with embedded UI), `Dockerfile.standard` (legacy single-binary, being phased out).
- CI: `golangci-lint` (errcheck + gofmt), `govulncheck`, `go-licenses` (allow-list: `Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, Unlicense, Zlib`), Dockerfile validation per PR, deps + size gates.
- UI placeholder at `server/internal/api/ui/dist/.gitkeep` + fallback page at `server/internal/api/ui/fallback/index.html` so `go build` works on a fresh clone before `make ui-build`.

---

## v0.1.0 (2026-04-08)

Historical record of the original single-binary AgentHound release. **Several capabilities listed below have since been removed or reshaped in the post-v0.1 trunk** — see the Unreleased section above for what ships today. Specifically: the multi-user authentication system, RBAC roles, audit logging, and rate limiting were removed; the Sigma.js frontend was replaced with React Flow + ELK.

Initial release. AgentHound is a BloodHound-style security tool for AI agent infrastructure.

### Collectors

- **Config Collector** — parses 12 MCP client configuration formats (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Continue, Zed, Cline, JetBrains, Kiro, Amazon Q, Augment) to discover agent-server trust relationships, credentials, instruction files, and host information
- **MCP Collector** — connects to MCP servers via stdio and Streamable HTTP transports using the official Go SDK (v1.5.0), enumerates tools/resources/prompts, classifies capability surfaces, detects injection patterns and cross-references
- **A2A Collector** — fetches A2A Agent Cards (v0.3.0 and v1.0) via HTTP, verifies JWS signatures (RFC 7515), scores auth posture, supports domain discovery (`--discover-domain`)

### Graph engine

- Neo4j 4.4+ with auto-detected schema syntax (4.4 `ON...ASSERT` / 5.x `FOR...REQUIRE`)
- 14 node labels (12 collector-produced + 2 synthetic), 13 raw edge kinds, 8 composite edge kinds (21 total in `AllowedEdgeKinds`)
- Deterministic content-based SHA-256 node IDs for cross-collector merge
- Batch MERGE writes with UNWIND (1000 ops/txn)
- APOC Dijkstra with non-APOC fallback for weighted pathfinding

### Ingest pipeline

- JSON schema validation, camelCase-to-snake_case normalization, deduplication by objectid
- Rug pull detection via description_hash tracking across scans
- Stale composite edge cleanup scoped to source collector

### Post-processors (10)

- HAS_ACCESS_TO — capability surface to URI scheme matching
- CAN_EXECUTE — shell/code execution tool to host mapping
- SHADOWS — cross-server tool shadowing detection
- POISONED_DESCRIPTION — injection pattern detection in tool descriptions
- POISONED_INSTRUCTIONS — suspicious pattern detection in instruction files
- CAN_REACH — transitive agent-to-resource access paths
- CAN_EXFILTRATE_VIA — sensitive data access + outbound channel combination
- CAN_IMPERSONATE — TF-IDF cosine similarity on A2A skill descriptions
- Cross-protocol CAN_REACH — A2A-to-MCP boundary traversal via host correlation
- RiskScore — weighted scores for agents, servers, and tools (0-100)

### 17 pre-built queries

Mapped to OWASP MCP Top 10 and OWASP Agentic Top 10:
- Critical Paths: agents-shell-access, shortest-to-database, cross-protocol-paths, exfiltration-routes, credential-chain
- Vulnerabilities: poisoned-tools, tool-shadowing, no-auth-servers, no-auth-a2a, rug-pull
- Supply Chain: unpinned-packages, instruction-poisoning, unsigned-cards, high-entropy-secrets
- Chokepoints: chokepoint-servers, chokepoint-tools
- Combined: unpinned-shell

### REST API (v0.1.0 — see Unreleased for current state)

- Full CRUD for graph nodes/edges
- Pathfinding: shortest-path, all-paths, weighted-path (Dijkstra)
- Findings endpoint with severity filtering
- Pre-built query execution
- Scan history and management
- ~~Rate limiting (100/min general, 20/min ingest, 10/min raw Cypher)~~ — removed post-v0.1.

### Authentication and authorization (v0.1.0 — REMOVED post-v0.1)

The original v0.1.0 release included bcrypt-hashed passwords, JWT tokens, `ah_`-prefixed API tokens, admin/analyst/viewer RBAC, first-run admin creation, and audit logging. **All removed in the post-v0.1 trunk** in favor of a single localhost bearer token gating only mutating endpoints. See the Unreleased section above and `docs/adr/0001-two-binary-split.md`.

### Frontend (v0.1.0 — REPLACED post-v0.1)

The v0.1.0 frontend used Sigma.js 3 (WebGL) + graphology + ForceAtlas2 for graph rendering, with JWT-based login and session management. **Replaced in the post-v0.1 trunk** with React Flow (`@xyflow/react`) + ELK (`elkjs`); login flow removed.

### Infrastructure

- Docker Compose: Neo4j 4.4 + PostgreSQL 16 + AgentHound
- Multi-stage Dockerfile (golang:1.25-alpine build, alpine:3.19 runtime)
- Non-root container user (UID 1001)
- Makefile: build, test, lint, docker, ui-build, seed
- CI: golangci-lint, tests with Neo4j+PG services, build verification
