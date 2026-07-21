# `agenthound loot --type ollama` -- Ollama Looter

Ollama is the default anonymous-loot target: no authentication by default, model inventory and modelfiles available via simple HTTP. The Looter extracts model metadata and system prompts without modifying any state on the target.

## What it extracts

| Data | Endpoint | Method | Default |
|------|----------|--------|---------|
| Model inventory (names, digests, sizes) | `/api/tags` | GET | Always |
| Modelfile, template, system prompt, family, parameters | `/api/show` | POST | Always (per model) |
| Embedding capability confirmation | `/api/embeddings` | POST | `--include-embeddings` only |

Each model emits an `:AIModel` node joined to the `:OllamaInstance` via a `PROVIDES_MODEL` edge. Fine-tunes (detected by `SYSTEM` or `ADAPTER` directives in the modelfile) are flagged with `is_finetune: true`.

> **Note on raw weights.** The Ollama HTTP API does not expose a raw-weight download endpoint — `/api/blobs/<digest>` accepts only `HEAD` (existence check) and `POST` (upload for the create-model flow) per the [upstream API docs](https://github.com/ollama/ollama/blob/main/docs/api.md). Raw weight blobs live at `~/.ollama/models/blobs/sha256-<digest>` and require filesystem access on the target host to retrieve. AgentHound therefore has no `--include-weights` flag.

## Probe levels

### Level 1: Anonymous inventory (default)

```bash
agenthound loot 10.0.0.10:11434 --type ollama \
    --engagement-id ENG-001 --output -
```

Issues `GET /api/tags` for the model list, then `POST /api/show` per model. Despite `/api/show` being a POST, it is read-only-in-effect (Ollama requires a body to specify which model to inspect). This is the baseline probe -- quiet, fast, and surfaces modelfile content including leaked system prompts.

Emits per model:
- `name`, `digest`, `size_bytes`, `family`, `parameters`, `is_finetune`
- `value_hash` = `SHA-256(modelfile content)` -- stable model-content identity
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

## Getting raw weights (out-of-band)

The Looter does not attempt raw weight extraction — Ollama's HTTP API does not support it. If the engagement needs the actual GGUF weight file (e.g. as input to `agenthound extract --type embedding-invert`), obtain it out-of-band:

- **Filesystem access to a compromised host.** Ollama stores weights as content-addressed blobs at `~/.ollama/models/blobs/sha256-<digest>`. `ollama show <model> --modelfile` on the host prints the `FROM` line with the blob's absolute path. `cp` the blob to a `.gguf` filename and any llama.cpp-compatible tool (including `agenthound extract`) loads it directly.
- **Model registry / HuggingFace.** If the model name matches a public release, the weights are downloadable at source.
- **Manifests as a shopping list.** `~/.ollama/models/manifests/` lists every layer digest per installed model — useful for enumerating what's on disk before physical acquisition.

## value_hash semantics

When `/api/show` returns a non-empty modelfile, the `AIModel` node carries `value_hash = SHA-256(modelfile_content)`. Models whose `/api/show` returns no modelfile (rare — private, unbuilt, or pre-migration models) omit the property, per the validator contract (`value_hash` is required only on `Credential` nodes; `AIModel` is optional).

The hash provides cross-run content stability and supports model-artifact diffing.
No current post-processor joins `AIModel.value_hash`; in particular,
`cross_service_credential_chain` matches only `Credential` nodes.

## Level-2 keep_alive semantics

The `--include-embeddings` probe sends `keep_alive: 0` in its request body. This tells Ollama's scheduler to evict THIS runner immediately after the request completes (verified against Ollama `server/sched.go:389-398`: when `runner.sessionDuration <= 0`, the finished-request handler sends the runner to `expiredCh` on `refCount` drop). If the target had insufficient VRAM to load the runner, other runners may have been evicted DURING load — this is standard scheduler behavior for any request and is independent of `keep_alive`.

On Ollama versions predating the `keep_alive` field, the field is ignored and the newly-loaded runner stays warm for the default 5 minutes (`envconfig.KeepAlive()`).

## --include-credential-values

By default, modelfile content, templates, and system prompts are NOT included in the emitted JSON -- only their hashes and metadata. Pass `--include-credential-values` to populate the raw `modelfile`, `template`, and `system_prompt` properties on each AIModel node.

Use this for engagements where the deliverable includes the actual leaked content (red-team report appendix, evidence package for remediation).

## Example

```bash
# Against an authorized Ollama instance
echo "AUTHORIZED" | bin/agenthound loot 10.0.0.10:11434 \
    --type ollama \
    --engagement-id MY-ENGAGEMENT \
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
| `--include-credential-values` | `false` | Emit raw modelfile/template/system_prompt |
| `--max-items <n>` | 1000 | Cap on models enumerated from `/api/tags` |
| `--engagement-id <id>` | empty | Correlation key on all edges |
| `--timeout <duration>` | 30s | Per-probe HTTP timeout |

## See also

- [Loot overview](index.md) -- contract and common flags
- [LiteLLM Looter](litellm.md) -- credential extraction from LiteLLM gateways
- [Attack paths](../attack-paths.md) -- how loot output feeds credential-chain findings
