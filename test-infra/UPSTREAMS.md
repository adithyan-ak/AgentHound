# Pinned upstream truth set

This file is the human-reviewed lock manifest for the collector compatibility
harness. Tags provide auditability; digests/revisions/checksums provide
immutability. Floating references without an immutable digest, floating
branches, response captures, and endpoints invented for AgentHound are
prohibited.

Reviewed: 2026-07-18.

## Container images

| Target | Immutable image |
|---|---|
| Ollama | `ollama/ollama:0.12.0@sha256:14def4e0b9ac8c91b3ec6f7fa7684c924ffe244541d5fd827d9b89035cc33310` |
| vLLM CPU | `vllm/vllm-openai-cpu:latest@sha256:6b301f040db8152dfb8ff55e06fd348aa5d0d9a311f58118160c7058262c8628` |
| Qdrant | `qdrant/qdrant:v1.15.5@sha256:0fb8897412abc81d1c0430a899b9a81eb8328aa634e7242d1bc804c1fe8fe863` |
| MLflow | `ghcr.io/mlflow/mlflow:v3.5.0@sha256:1ef270be615bdfeecb1b65e6c557a14cd2f1d811204fe9c8e34c3bb0408fe550` |
| LiteLLM | `ghcr.io/berriai/litellm-database:v1.92.0@sha256:64d3547e0b131bf4638342e52c12bc46d6f1d9b8498e4b731ff31be5ab316ea9` |
| PostgreSQL | `postgres:16.14-alpine3.24@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777` |
| Neo4j analysis projection | `neo4j:4.4-community@sha256:b0efe93722d27bc050908810650939380d989b1936fc5dd02ad1d7bf1c87a13b` |
| Jupyter | `quay.io/jupyter/base-notebook:2025-08-25@sha256:e9222d8476431543c605f1f203654ef8f89f573cb169c2065e6b1aff8bbfa5b9` |
| Open WebUI | `ghcr.io/open-webui/open-webui:v0.10.2@sha256:9fcea9c6e32ab60b0498f3986c6cdf651ddbe61db48d2213a3d28048ddd673d4` |
| ContextForge | `ghcr.io/ibm/mcp-context-forge:v1.0.5@sha256:fda7f025a21dd7df75afde0576432e28d39880e1914301c93b323aaf4bfcfcf0`; upstream git commit `af178ee146f262326ae38a572f21260f3a28945b` |
| Node base | `node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Python base | `python:3.12-slim@sha256:c3d81d25b3154142b0b42eb1e61300024426268edeb5b5a26dd7ddf64d9daf28` |
| nginx base | `nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de` |

The vLLM repository does not publish a versioned CPU tag for this release
line. Its `latest` label is therefore paired with and locked by the immutable
multi-architecture manifest digest above; the independent preflight also
requires the real `/v1/models` inventory.

Official sources:

- <https://github.com/ollama/ollama>
- <https://github.com/vllm-project/vllm>
- <https://github.com/qdrant/qdrant>
- <https://github.com/mlflow/mlflow>
- <https://github.com/BerriAI/litellm>
- <https://github.com/jupyter/docker-stacks>
- <https://github.com/open-webui/open-webui>
- <https://github.com/IBM/mcp-context-forge>

## Package and SDK releases

| Component | Pin |
|---|---|
| MCP Everything reference server | `@modelcontextprotocol/server-everything@2026.7.4`; npm integrity `sha512-ydMW/M6rk9tK23b+U38trsNLHhd5eF+ntiv2Vr+RPMDhbiKY/IKrZU25ukvSXVPUBvy7TxTPWpeV4KcYcXg72w==`; upstream git head `6dd0a683e198783e30feabf7abaf42f925bd18b1` |
| A2A Python SDK | `a2a-sdk[http-server]==1.1.0` |
| LangServe | `langserve[server]==0.3.3` |
| Independent GGUF reader | llama.cpp `gguf==0.17.1` (`gguf-py`) |

The MCP package is the Model Context Protocol project's official client-test
server and supplies real tools, resources, resource templates, prompts,
pagination, and three transports. Source:
<https://github.com/modelcontextprotocol/servers/tree/main/src/everything>.
The two local gates are protocol-transparent enforcing proxies, not MCP
fixtures: missing or incorrect credentials stop at `401`, while exact controls
must reach the pinned Everything Server and receive its independent protocol
response. The cross-service gate's bearer uses the same Compose YAML anchor as
LiteLLM's real master key, and the client config is rendered only inside the
disposable workstation.

The A2A service is built with the official SDK and route constructors. Its v1
lane uses the native protobuf card and dispatcher; its v0.3 lane uses the
SDK's `to_compat_agent_card` converter and compatibility dispatcher. The
protected lane is a local API-key gate in front of the same official request
handler, while the ambiguous control serializes the SDK's canonical
`VersionNotSupportedError`. Counted SDK executors and `InMemoryTaskStore`
wrappers expose only aggregate safety counters, allowing the harness to prove
that collection never executed an agent or mutated task state. No additional
Python dependency or upstream pin is introduced. Source:
<https://github.com/a2aproject/a2a-python>.

Every Python transitive dependency is exact-versioned and hash-locked in the
adjacent `requirements.lock`; Docker installs with `--require-hashes`. Both MCP
images use `npm ci` against committed lockfiles. The workstation's necessary
Debian utilities resolve only from the immutable `20250715T000000Z` Debian and
Debian Security snapshots; the A2A signer has no apt dependency.

## Model artifacts

| Purpose | Immutable artifact |
|---|---|
| vLLM runtime model | `HuggingFaceTB/SmolLM2-135M-Instruct`, revision `12fd25f77366fa6b3b4b768ec3050bf629380bac`; Apache-2.0 safetensors Llama model, 269,060,552-byte weights |
| Embedding extractor GGUF | `ggml-org/models`, commit `499bc8821c6b12b4e53c5bffcb21ec206f212d81`, path `tinyllamas/stories260K.gguf`, size `1,185,376`, SHA-256 `270cba1bd5109f42d03350f60406024560464db173c0e387d91f0426d3bd256d` |
| Ollama runtime model | upstream registry name `qwen2:0.5b`; content digest `sha256:6f48b936a09f7743c7dd30e72fdb14cba296bc5861902e4d0c387e8fb5050b39` |

The GGUF downloader verifies both the checksum and the standard on-disk bytes
`47 47 55 46` (`GGUF`) before the collector is allowed to see it. Source:
<https://huggingface.co/ggml-org/models/tree/499bc8821c6b12b4e53c5bffcb21ec206f212d81/tinyllamas>.
The vLLM model revision is published at
<https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct/tree/12fd25f77366fa6b3b4b768ec3050bf629380bac>.
The exact extraction inventory is recomputed on every run with llama.cpp's
hash-locked official `gguf-py` reader before AgentHound executes.

## Client configuration provenance

Fixtures use current documented locations and native shapes. Important primary
references include:

- Amazon Q current global/local IDE paths (`default.json`):
  <https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/mcp-ide.html>
- Augment persistent `~/.augment/settings.json` and direct `mcpServers` map:
  <https://docs.augmentcode.com/cli/integrations>
- MCP client examples and the official reference server:
  <https://modelcontextprotocol.io/quickstart/user>

Platform-only paths are exercised on their native host lane. In particular,
macOS Claude Desktop uses
`~/Library/Application Support/Claude/claude_desktop_config.json`; it is not
fabricated inside the Linux workstation.

## Refresh procedure

1. Open the upstream release notes, image manifest, source tag/commit, and
   protocol/config documentation. Do not begin from an AgentHound failure.
2. Select a released version that supports the harness architecture. Record
   both tag and immutable digest/revision/integrity here.
3. Update only the upstream deployment and independent truth verifier first.
4. Prove the updated upstream without AgentHound. Save the exact inventories,
   authentication controls, and protocol handshakes.
5. Update the corresponding exact collector oracle to that reviewed truth.
6. Run every harness scenario. Treat differences as collector findings; do not
   add compatibility aliases, alternate fake endpoints, captured responses, or
   relaxed `partial` acceptance to make them disappear.
7. Review the diff for `latest`, floating Git branches, unpinned package specs,
   collector-specific target handlers, and synthetic protocol/model bytes.
