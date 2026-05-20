# Looting

Looters are read-only credential extractors. They probe discovered AI services via HTTP and emit `Credential` nodes into the ingest graph without modifying target state.

## Contract

Every Looter implements `sdk/action.Looter` and adheres to:

- **GET-only by default.** No POST/PUT/DELETE unless explicitly flag-gated and documented as a read-only-in-effect exception (e.g., Ollama's `/api/embeddings` probe).
- **No state change on target.** If an action would modify the target, it belongs in a Poisoner, not a Looter.
- **`value_hash` on every Credential.** SHA-256 of the raw credential value, computed via `sdk/common.HashCredentialValue`. This is the cross-collector merge primitive that enables credential-chain findings.
- **Engagement-ID correlation.** Every emitted edge carries `engagement_id` in its evidence map.
- **Partial failure tolerance.** Individual endpoint failures land in `LootResult.PartialErrors`; the Looter continues and emits whatever it can.

## Common flags

| Flag | Required | Default | Notes |
|------|----------|---------|-------|
| `--type <module>` | Yes | -- | Module dispatcher key (`litellm`, `ollama`) |
| `--engagement-id <id>` | Recommended | empty | Correlation key for IR coordination. Recorded on every edge and slog line. |
| `--include-credential-values` | No | `false` | Emit raw `value` property alongside `value_hash`. Default is hash-only. |
| `--max-items <n>` | No | 1000 | Cap emitted Credential nodes per category |
| `--output <path>` | No | `./loot-<scan_id>.json` | Use `-` for stdout |
| `--timeout <duration>` | No | 30s | Per-probe HTTP timeout |

## Safety gate

The first `agenthound loot` invocation on a machine triggers an interactive `AUTHORIZED` prompt. Typing `AUTHORIZED` writes a sentinel to `~/.agenthound/loot-acknowledged`; subsequent invocations skip the prompt. Pipe `echo "AUTHORIZED"` for scripted use in controlled labs.

## Available Looters

| Module | Target | Key extraction |
|--------|--------|----------------|
| [`litellm`](litellm.md) | LiteLLM gateway (port 4000) | Master key, upstream provider keys, virtual keys |
| [`ollama`](ollama.md) | Ollama instance (port 11434) | Model inventory, modelfiles, system prompts, weights |

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
