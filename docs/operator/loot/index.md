# Looting

Looters are read-only credential extractors. They probe discovered AI services via HTTP and emit `Credential` nodes into the ingest graph without modifying target state.

## Contract

Every Looter implements `sdk/action.Looter` and adheres to:

- **GET-only by default.** No POST/PUT/DELETE unless explicitly flag-gated and documented as a read-only-in-effect exception (e.g., Ollama's `/api/embeddings` probe).
- **No state change on target.** If an action would modify the target, it belongs in a Poisoner, not a Looter.
- **`value_hash` on every Credential.** SHA-256 of the raw credential value, computed via `sdk/common.HashCredentialValue`. This is the cross-collector merge primitive that enables credential-chain findings. **Exception:** when a Looter cannot observe the raw value (e.g. LiteLLM's `/model/info` strips upstream provider `api_key` via `remove_sensitive_info_from_deployment`), it may synthesize a stable identity via `SHA-256("provider:name")` and mark the node `merge_key: "identity"`. The `cross_service_credential_chain` post-processor explicitly filters identity-marked nodes out of value_hash joins (see `server/internal/analysis/processors/cross_service_credential_chain.go`).
- **Engagement-ID correlation.** Every emitted edge carries `engagement_id` in its evidence map.
- **Partial failure tolerance.** Individual endpoint failures land in `LootResult.PartialErrors`; the Looter continues and emits whatever it can.
- **Real coverage on the loot envelope.** The emitted ingest envelope carries a `coverage` manifest derived from the observed probe counters (`EndpointsProbed` / `PartialFailures` / `PartialErrors`), never a hand-authored or absent one: all probes succeeded → `complete`, some failed → `partial` (with a failed method outcome per `PartialError`), all failed → `failed`, nothing probed → `unknown`. An empty loot artifact is treated as clean only when every probe completed, so a `/key/list` 401 keeps the posture explicitly partial rather than coalescing into an all-clear.

## Common flags

| Flag | Required | Default | Notes |
|------|----------|---------|-------|
| `--type <module>` | Yes | -- | Module dispatcher key (`litellm`, `ollama`, `mlflow`, `qdrant`, `openwebui`, `jupyter`) |
| `--engagement-id <id>` | Recommended | empty | Correlation key for IR coordination. Recorded on every edge and slog line. |
| `--include-credential-values` | No | `false` | Emit raw `value` property alongside `value_hash`. Default is hash-only. |
| `--max-items <n>` | No | (per-Looter default, see below) | Cap on the enumerated resource per Looter — semantics vary by module |
| `--output <path>` | No | `./loot-<scan_id>.json` | Use `-` for stdout |
| `--timeout <duration>` | No | 30s | Per-probe HTTP timeout |

Per-Looter `--max-items` defaults and semantics:

- `litellm`   — default `1000`; caps Credential nodes per category (upstream, virtual)
- `mlflow`    — default `1000`; caps experiments/runs enumerated per page-loop; also bounds Model Registry probes
- `openwebui` — default `1000`; caps Credential nodes emitted by the recursive secret walker
- `qdrant`    — default `1000`; caps enumerated collection names (per-collection points are capped separately via `--points-per-collection` when `--include-points` is set)
- `jupyter`   — default `500`; caps notebook/file entries returned from the recursive tree walk
- `ollama`    — default `1000`; caps models enumerated from `/api/tags`

## Safety gate

The first `agenthound loot` invocation on a machine triggers an interactive `AUTHORIZED` prompt. Typing `AUTHORIZED` writes a sentinel to `~/.agenthound/loot-acknowledged`; subsequent invocations skip the prompt. Pipe `echo "AUTHORIZED"` for scripted use in controlled labs.

## Available Looters

| Module | Target | Key extraction |
|--------|--------|----------------|
| [`litellm`](litellm.md) | LiteLLM gateway (port 4000) | Master key, upstream provider keys, virtual keys |
| [`ollama`](ollama.md) | Ollama instance (port 11434) | Model inventory, modelfiles, system prompts |
| `mlflow` | MLflow tracking server (port 5000) | Experiment + run inventory + registered models + version storage URIs (`:MCPResource` with sensitivity heuristic) — anonymous by default |
| `qdrant` | Qdrant vector DB (port 6333) | Collection inventory (anonymous, GET-only, no Credential nodes); flag-gated payload sampling via `--include-points` emits one `:MCPResource` per scrolled point |
| `openwebui` | Open WebUI (port 3000) | With `--api-key`: upstream OpenAI + Ollama provider keys, RAG embedding/config keys (recursive extraction). Anonymous config posture (signup, auth) otherwise. |
| `jupyter` | Jupyter Server (port 8888) | Active sessions + notebook/file inventory (anonymous, GET-only, recursive walk bounded by `--max-depth`; emits one `:MCPResource` per notebook or file discovered under `/api/contents`; no Credential nodes) |

See the [CLI reference](../../reference/cli.md) for the full per-module flag set of each looter.

## Typical workflow

```bash
# 1. Discover the target via network scan
agenthound scan 10.0.0.0/24 --output - | agenthound-server ingest -

# 2. Loot discovered services
agenthound loot 10.0.0.20:4000 --type litellm \
    --master-key sk-... --engagement-id ENG-001 --output - | agenthound-server ingest -

# 3. Credential-chain findings appear automatically via post-processing
agenthound-server query --prebuilt credential-chain
```
