# `agenthound loot --type ollama` -- Ollama Looter

Ollama is the default anonymous-loot target: no authentication by default, model inventory and modelfiles available via simple HTTP. The Looter extracts model metadata, system prompts, and (optionally) raw weights without modifying any state on the target.

## What it extracts

| Data | Endpoint | Method | Default |
|------|----------|--------|---------|
| Model inventory (names, digests, sizes) | `/api/tags` | GET | Always |
| Modelfile, template, system prompt, family, parameters | `/api/show` | POST | Always (per model) |
| Embedding capability confirmation | `/api/embeddings` | POST | `--include-embeddings` only |
| Raw model weights | `/api/blobs/<digest>` | GET | `--include-weights` only |

Each model emits an `:AIModel` node joined to the `:OllamaInstance` via a `PROVIDES_MODEL` edge. Fine-tunes (detected by `SYSTEM` or `ADAPTER` directives in the modelfile) are flagged with `is_finetune: true`.

## Probe levels

### Level 1: Anonymous inventory (default)

```bash
agenthound loot 10.0.0.10:11434 --type ollama \
    --engagement-id ENG-001 --output -
```

Issues `GET /api/tags` for the model list, then `POST /api/show` per model. Despite `/api/show` being a POST, it is read-only-in-effect (Ollama requires a body to specify which model to inspect). This is the baseline probe -- quiet, fast, and surfaces modelfile content including leaked system prompts.

Emits per model:
- `name`, `digest`, `size_bytes`, `family`, `parameters`, `is_finetune`
- `value_hash` = `SHA-256(modelfile content)` -- the cross-collector merge primitive
- `has_system_prompt` = boolean
- `modelfile_size_bytes`

### Level 2: Embedding probe (`--include-embeddings`)

```bash
agenthound loot 10.0.0.10:11434 --type ollama \
    --include-embeddings \
    --engagement-id ENG-001 --output -
```

Issues a single `POST /api/embeddings` against the first available model with a benchmark prompt. Confirms the inference compute path is consumable. This is the documented GET-only contract exception: it consumes operator-billed compute on the target but changes no state.

Sets `embedding_capability_confirmed: true|false` on the `OllamaInstance` node.

### Level 3: Weight extraction (`--include-weights`)

```bash
agenthound loot 10.0.0.10:11434 --type ollama \
    --include-weights --weights-dir ./extracted-weights \
    --engagement-id ENG-001 --output -
```

Streams `GET /api/blobs/<digest>` for each model to local disk. Multi-GiB per model. Bandwidth-heavy and highly visible in network monitoring.

- `--weights-dir` is mandatory with `--include-weights`
- Files written as `<model-name>-<digest-prefix>.bin` (mode 0600)
- Capped at 32 GiB per blob (defensive ceiling)
- Adds `weight_artifact_path`, `weight_artifact_sha256`, `weight_artifact_bytes` to the AIModel node

Use this when the engagement requires proving model exfiltration is possible or when the fine-tune itself is the target artifact.

## value_hash semantics

The `value_hash` on each `AIModel` node is `SHA-256(modelfile_content)`. This serves two purposes:

1. **Cross-run stability.** The same model on the same Ollama instance produces the same hash across loot runs, enabling diff detection (rug-pull detection for model artifacts).
2. **Cross-collector joins.** If another collector surfaces the same modelfile content (e.g., a config collector finds a modelfile on disk), the `cross_service_credential_chain` post-processor can join on `value_hash`.

## --include-credential-values

By default, modelfile content, templates, and system prompts are NOT included in the emitted JSON -- only their hashes and metadata. Pass `--include-credential-values` to populate the raw `modelfile`, `template`, and `system_prompt` properties on each AIModel node.

Use this for engagements where the deliverable includes the actual leaked content (red-team report appendix, evidence package for remediation).

## Demo example

```bash
# Against the demo lab Ollama (preloaded with tinyllama + support-agent-v3)
echo "AUTHORIZED" | bin/agenthound loot 172.30.0.10:11434 \
    --type ollama \
    --engagement-id DEMO-LOCAL \
    --include-credential-values \
    --output /tmp/loot-ollama.json

# Ingest and check findings
bin/agenthound-server ingest /tmp/loot-ollama.json
bin/agenthound-server query "MATCH (o:OllamaInstance)-[:PROVIDES_MODEL]->(m:AIModel) RETURN m.name, m.is_finetune, m.has_system_prompt"
```

Expected output: two models -- `tinyllama` (stock, `is_finetune: false`) and `support-agent-v3` (fine-tune with system prompt, `is_finetune: true`).

## Flags

| Flag | Default | Notes |
|------|---------|-------|
| `--include-embeddings` | `false` | POST exception; consumes target compute |
| `--include-weights` | `false` | Multi-GiB downloads; requires `--weights-dir` |
| `--weights-dir <path>` | -- | Local directory for extracted weight blobs |
| `--include-credential-values` | `false` | Emit raw modelfile/template/system_prompt |
| `--max-items <n>` | 1000 | Cap on models enumerated from `/api/tags` |
| `--engagement-id <id>` | empty | Correlation key on all edges |
| `--timeout <duration>` | 30s | Per-probe HTTP timeout |

## See also

- [Loot overview](index.md) -- contract and common flags
- [LiteLLM Looter](litellm.md) -- credential extraction from LiteLLM gateways
- [Attack paths](../attack-paths.md) -- how loot output feeds credential-chain findings
