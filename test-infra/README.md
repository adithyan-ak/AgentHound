# Real-infrastructure collector compatibility harness

This manual harness answers one question: **does the current collector work
against the real implementations it claims to support?** It is deliberately
not a collector regression mock suite. The upstream topology is validated
without using AgentHound, then the collector is run against that fixed truth.
Collector output never changes the fixtures or expectations.

The harness is intentionally outside CI for now. A run is local/offline in the
sense that every target is isolated on a disposable Docker bridge and no
production or cloud service is contacted. The first run still needs network
access to pull pinned images, npm packages, and model artifacts.

## Safety and interpretation

The runner has two distinct failure classes:

1. **Harness invalid:** an image, seed operation, checksum, protocol handshake,
   authenticated control, or exact upstream inventory is wrong. Collector
   scenarios do not start.
2. **Collector incompatible:** independent upstream truth passed, but a
   collector command exited non-zero, leaked raw credential material, or
   disagreed with an exact oracle. Every remaining scenario still runs and the
   failures are aggregated in `artifacts/<run-id>/summary.json`.

A collector-incompatible result is the intended way to identify drift. Do not
change this harness to make such a result pass. Investigate and fix the
collector in a separate change, then rerun the same pinned truth set.

All destructive scenarios are restricted to the Compose project. The seed
scripts refuse destructive inventory reconciliation if their service URL is
changed from the fixed Compose hostname. Never repoint this harness or its
fixture scripts at production.

## Requirements

- macOS with Docker Desktop/Engine, Compose v2, and Linux containers (the
  native Claude Desktop path lane deliberately depends on the host platform)
- Bash, Go 1.25.12 or newer, `curl`, and `jq`
- Approximately 16 GiB available to Docker and 25 GiB free disk on a cold run
- Network access for the initial immutable downloads

No AgentHound server, Neo4j, cloud account, external API key, or GPU is needed.
vLLM uses its official CPU image. PostgreSQL is internal to the LiteLLM target.

## Run

From the repository root:

```bash
bash test-infra/run-tests.sh
```

Keep the topology after completion or a collector-incompatible result:

```bash
bash test-infra/run-tests.sh --keep
```

The runner performs these phases in order:

1. downloads the pinned official GGUF and verifies its SHA-256 and standard
   byte magic;
2. builds the current collector without modifying it;
3. starts only pinned upstream images or services authored with official SDKs;
4. seeds data through upstream public APIs;
5. proves exact upstream truth, authentication controls, MCP handshakes, signed
   A2A cards, and inventories without invoking AgentHound;
6. runs all collector features and exact assertions, continuing after each
   collector failure;
7. emits a machine-readable summary that separates harness validity from
   collector compatibility.

## Real topology

No target implements an endpoint invented for the collector.

- Ollama with one real model and the opt-in embedding path
- vLLM's official CPU OpenAI server with a pinned Hugging Face model revision
- a real LangServe application
- Qdrant with exact collections and points seeded through its REST API
- MLflow with a real experiment, run, registered model, and model version
- LiteLLM with PostgreSQL, provider definitions, and a generated virtual key
- token-protected Jupyter Server with a recursive real Contents API tree
- authenticated Open WebUI with Ollama and OpenAI-compatible upstream config
- a second real LiteLLM process on port 8000 as a vLLM near-miss control
- the official MCP `server-everything` package over stdio, Streamable HTTP, and
  SSE
- IBM ContextForge v1.0.5 with real login, catalog API token, management API,
  virtual server, tool, resource, MCP authentication gate, poison/revert
  target, and campaign target
- an A2A Python SDK agent plus conformant current and legacy cards served by
  nginx, with the current card genuinely ES256-signed
- current client config paths and formats for Claude Code, Cursor, VS Code,
  Windsurf, Continue, Zed, Cline, Junie, Kiro, Amazon Q, and Augment
- a host-native macOS Claude Desktop path lane, instead of pretending Claude
  Desktop's macOS path exists in the Linux workstation

The exact releases, digests, source revisions, checksums, and refresh rules are
in [UPSTREAMS.md](UPSTREAMS.md).

## Feature coverage

The collector phase covers:

- config discovery, current instruction/rules paths, credential hashing, and
  host-native platform discovery;
- direct MCP enumeration and config-driven stdio/HTTP/SSE enumeration;
- multi-agent A2A parsing, legacy fallback, offline JWKS verification, skills,
  and delegation inference;
- protocol discovery and AI-service network fingerprinting with a near-miss
  negative control;
- every registered looter, including Ollama embeddings, Qdrant point sampling,
  authenticated Jupyter, authenticated Open WebUI, and raw-secret redaction;
- embedding extraction against a real official GGUF;
- credential-reach against a genuinely credential-gated MCP resource;
- ContextForge tool-description poison/revert and campaign round-trip against
  the actual GA management API;
- instruction poison/revert and MCP config implant/revert using a launchable
  official MCP stdio command;
- rules and version smoke paths.

The current `main` registration surface maps to the harness as follows. Module
IDs are grouped only when one scenario exercises the same real target through
the shared network dispatcher.

| Registered surface | Harness scenario | Real implementation |
|---|---|---|
| `config.enumerate` | `scan-config`, `scan-config-host` | Native client files on Linux plus the macOS Claude Desktop path |
| `mcp.enumerate` | `scan-mcp`, `scan-mcp-configured` | MCP Everything over HTTP/SSE/stdio and ContextForge MCP |
| `a2a.enumerate` | `scan-a2a` | A2A SDK v1 agent and signed current/unsigned legacy static cards |
| `network.scan` and all eight `*.fingerprint` modules | `scan-network` | Ollama, vLLM, LangServe, Qdrant, MLflow, LiteLLM, Jupyter, and Open WebUI |
| All six `*.loot` modules | `loot-*` | Authenticated/public APIs of those six upstream services |
| `embedding.extract` | `extract-embedding` | Official, checksum-pinned GGUF artifact |
| `mcp.poison` | `poison-mcp` | ContextForge v1.0.5 management API |
| `instruction.poison` | `poison-instruction` | Real instruction file with exact restore oracle |
| `mcp.config.implant` | `implant-mcp-config` | Cursor config plus launchable MCP Everything stdio entry |
| Campaign registry | `campaign-cred-reach`, `campaign-mcp-roundtrip` | Credential-gated ContextForge resource and reversible real tool mutation |
| Protocol discovery, rules, and version CLI surfaces | `discover`, `rules-list`, `version` | Live MCP/A2A discovery plus local smoke checks |

## Artifacts and debugging

Each run writes a new directory under `test-infra/artifacts/`. Important files:

- `summary.json`: final harness/collector classification and every scenario
- `results.ndjson`: append-only scenario results used to build the summary
- `upstream-truth.json` (under `fixtures/`): independent exact truth record
- `<scenario>.json`: collector output
- `<scenario>.stderr`: diagnostics, with raw-secret checks applied

Inspect a retained stack:

```bash
docker compose -f test-infra/docker-compose.yml ps
docker compose -f test-infra/docker-compose.yml logs --tail=200 SERVICE
docker compose -f test-infra/docker-compose.yml exec workstation sh
```

Remove only this harness's containers, network, and named volumes:

```bash
docker compose -f test-infra/docker-compose.yml down -v --remove-orphans
```

## Controlled refresh

Upstream refreshes are never inferred from a collector failure. Follow the
review procedure in `UPSTREAMS.md`, update the immutable reference and its
truth assertion together, run the complete harness, and review any newly
exposed collector findings independently.
