<div align="center">

<img src="docs/readme-assets/agenthound-banner.png" alt="AgentHound" width="100%">

### The offensive security framework for AI agent infrastructure

**MCP · A2A · model gateways · inference servers · vector stores · MLOps · notebooks · 12 agent clients**

[![DEF CON 34 · Red Team Village](https://img.shields.io/badge/🎤_DEF_CON_34-Red_Team_Village-E4002B?style=for-the-badge)](https://redteamvillage.io/)

[Quickstart](#-quick-start) ·
[Capabilities](#-capabilities) ·
[Lifecycle](#-the-offensive-lifecycle) ·
[Graph Model](https://docs.agenthound.io/reference/graph-model/) ·
[Docs](https://docs.agenthound.io) ·
[Safety](#-safety--authorization)

[![CI](https://github.com/adithyan-ak/agenthound/actions/workflows/ci.yml/badge.svg)](https://github.com/adithyan-ak/agenthound/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/adithyan-ak/agenthound?logo=github)](https://github.com/adithyan-ak/agenthound/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/adithyan-ak/agenthound)](https://goreportcard.com/report/github.com/adithyan-ak/agenthound)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![cosign](https://img.shields.io/badge/releases-cosign%20signed-0b7285)](https://docs.agenthound.io/getting-started/install/)

</div>

> **Authorized use only.** AgentHound ships read-only discovery **and** active exploitation modules. Run it only against infrastructure you own or are written-authorized to assess. See [Safety & Authorization](#-safety--authorization).

**AgentHound is an open-source offensive security framework for AI agent infrastructure.** It runs the full engagement - recon, fingerprinting, credential looting, **modelfile / system-prompt / fine-tune inventory**, model inversion, tool and instruction poisoning, and config-implant persistence - across every layer of the modern agentic stack, then merges every fact into one Neo4j graph and proves the attack paths that tie it all together. Agenthound is BloodHound for the agentic stack.

## ⚡ Capabilities

<table>
<tr>
<td width="50%" valign="top">

🌐 **Full-spectrum agentic attack surface**<br/>
One framework attacks every layer - MCP, A2A, model gateways, inference servers, vector stores, MLOps, notebooks, and 12 agent clients. The whole estate is one target set.

</td>
<td width="50%" valign="top">

🔓 **Credential looting across the gateway & service plane**<br/>
Hand the LiteLLM looter one master key and get back every upstream provider key it brokers - OpenAI, Anthropic, Bedrock - plus virtual keys and spend. Secrets fuse across services by `value_hash`.

</td>
</tr>
<tr>
<td width="50%" valign="top">

🧬 **Modelfile, system-prompt & fine-tune inventory**<br/>
Enumerate every model on an unauthenticated Ollama - names, digests, sizes, modelfiles, templates, and system prompts. Fine-tunes (SYSTEM / ADAPTER directives) get flagged; each `:AIModel` node carries `value_hash` so a leaked prompt matches across collectors.

</td>
<td width="50%" valign="top">

🔬 **Model inversion / training-data residue extraction**<br/>
A pure-Go GGUF parser runs statistical inversion on the embedding matrix of any weight file you feed it to recover likely **fine-tune vocabulary tokens** - surfacing what a model was trained on as graph nodes.

</td>
</tr>
<tr>
<td width="50%" valign="top">

☠️ **Active exploitation - tool/instruction poisoning + config implant**<br/>
Rewrite the tool description the LLM reads, inject `CLAUDE.md` / `.cursorrules`, or implant a malicious MCP server for persistence. Every mutation is dry-run by default and byte-exact reversible.

</td>
<td width="50%" valign="top">

🗄️ **RAG, vector-store & notebook attack surface**<br/>
Inventory Qdrant collections and Jupyter sessions and notebook trees - the data-layer surfaces that ship unauthenticated by default.

</td>
</tr>
<tr>
<td width="50%" valign="top">

🕸️ **Cross-protocol & credential-chain attack paths**<br/>
15 post-processors compute the routes raw facts can't show - credential chains, cross-protocol pivots, exfiltration paths - up to 6 hops, across MCP and A2A.

</td>
<td width="50%" valign="top">

🧪 **Indirect prompt injection, modeled as data-flow**<br/>
Prompt injection treated as taint propagation: untrusted-input tools → tainted siblings → high-impact sinks, traced as real graph edges.

</td>
</tr>
<tr>
<td width="50%" valign="top">

📊 **Detection & standards intelligence**<br/>
19 prebuilt attack-path queries, 35 detection rules, 0–100 risk scoring, and retest-as-diff - crosswalked to OWASP MCP / Agentic Top 10 and MITRE ATLAS.

</td>
<td width="50%" valign="top">

🧩 **Write your own attacks**<br/>
A new attack against a new AI service is one module away - implement an action interface, drop a `register.go`, blank-import it. Same SDK, same lifecycle, same graph.

</td>
</tr>
</table>

<p align="center">
  <img src="docs/readme-assets/agenthound-attack-surface.png" alt="AgentHound attack-surface graph" width="900">
</p>

## 🎯 Every plane of the stack is a target

| Plane | What AgentHound attacks | Modules |
|---|---|---|
| **Agent client** | 12 MCP client configs + instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`) | `config` |
| **Protocol** | MCP servers (stdio + HTTP/SSE), A2A agents (agent cards, JWS, delegation) | `mcp`, `a2a`, `protoscan` |
| **Model gateway** | LiteLLM - one master key → the whole upstream provider keyring | `litellmfp`, `litellmloot` |
| **Inference** | Ollama, vLLM - model inventory, modelfiles, system prompts, fine-tune detection | `ollamafp`, `ollamaloot`, `vllmfp` |
| **Vector / RAG** | Qdrant collections | `qdrantfp`, `qdrantloot` |
| **MLOps** | MLflow experiments + runs | `mlflowfp`, `mlflowloot` |
| **Notebook** | Jupyter sessions + notebook tree | `jupyterfp`, `jupyterloot` |
| **Frontend** | Open WebUI (RAG docs, upstream keys), LangServe | `openwebuifp`, `openwebuiloot`, `langservefp` |

## 📦 By the numbers

- **23 module packages** - 22 self-registering attack modules + the `protoscan` discovery engine
- **7 offensive CLI verbs** - `scan` · `discover` · `loot` · `extract` · `poison` · `implant` · `revert` (`enumerate` + `fingerprint` run inside `scan`)
- **8 fingerprinters · 6 looters · 1 model-inversion extractor · 2 poisoners · 1 implanter**
- **Graph:** 25 node labels · 30 edge kinds (18 raw + 12 composite) · **15 post-processors**
- **Intelligence:** 35 detection rules + 8 fingerprint rules · 19 prebuilt attack-path queries · OWASP MCP Top 10 + OWASP Agentic Top 10 + **7 MITRE ATLAS techniques**
- **One static collector binary (~9.9 MiB, no DB/UI/server deps, offline by default).** Apache-2.0, cosign-signed releases with SBOM.

## 🚀 Quick start

Prerequisites: Docker + Compose v2. No Go, no Node, no `git clone`.

```bash
# 1. Start the analysis server (Neo4j + Postgres + UI, binds 127.0.0.1:8080)
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/docker/docker-compose.public.yml | docker compose -f - -p agenthound up -d --wait

# 2. Install the collector (single static binary, ~9.9 MiB → ~/.local/bin)
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

# 3. Scan your own machine - offline, read-only, secrets hashed - and stream it in
agenthound scan --config --output - | curl --data-binary @- -H "Content-Type: application/json" http://127.0.0.1:8080/api/v1/ingest

# 4. Open the graph
open http://127.0.0.1:8080   # xdg-open on Linux
```

Prefer a reproducible, pinned install? Every release is cosign-signed with an SBOM:

```bash
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/v0.8.0/install.sh | sh
```

Also available via Homebrew (`brew install agenthound agenthound-server`), `go install`, and signed release binaries - see the [installation guide](https://docs.agenthound.io/getting-started/install/).

<p align="center">
  <img src="docs/readme-assets/agenthound-dashboard.png" alt="AgentHound dashboard" width="900">
</p>

## 🔪 The offensive lifecycle

One binary runs the whole offensive lifecycle. Every stage emits the same ingest envelope, so results land in the same graph. Active verbs (`loot`, `extract`, `poison`, `implant`) require an interactive `AUTHORIZED` confirmation; `extract`, `poison`, and `implant` are dry-run until `--commit` and are undone by `agenthound revert` - see [Safety & Authorization](#-safety--authorization).

**1. Recon** - find the AI estate:

```bash
agenthound scan 10.0.0.0/24
agenthound discover 10.0.0.0/24 --mcp --a2a
```

**2. Loot** - pull latent credentials and model metadata, read-only (GET/HEAD):

```bash
agenthound loot 10.0.0.20:4000 --type litellm --master-key sk-... --engagement-id ENG-1 --output -
agenthound loot 10.0.0.10:11434 --type ollama --include-credential-values --engagement-id ENG-1
```

Looter types: `litellm`, `ollama`, `openwebui`, `mlflow`, `qdrant`, `jupyter`.

**3. Extract** - invert a locally-available GGUF weight file to recover fine-tune residue:

```bash
agenthound extract <model-id> --type embedding-invert --artifact /path/to/model.gguf --commit --engagement-id ENG-1
```

**4. Exploit + persist** - sanctioned, reversible offensive actions:

```bash
agenthound poison 10.0.0.30:8080 --type mcp.tool.description --target-id support_lookup --inject "Ignore prior instructions." --commit --engagement-id ENG-1
agenthound implant --type mcp.config.malicious-server --target-id ~/.cursor/mcp.json --inject "..." --commit --engagement-id ENG-1
agenthound revert ENG-1
```

**5. Analyze** - pathfind and gate:

```bash
agenthound-server query --prebuilt litellm-credential-leak
agenthound-server query --findings --fail-on critical
```

See the full [CLI reference](https://docs.agenthound.io/reference/cli/) for every verb, flag, and module.

## 🔎 What AgentHound finds

AgentHound's findings are built around the questions red teams and defenders ask when they need to understand reachability, blast radius, and pathing risk.

| Finding | What it means | Question it answers |
|---|---|---|
| **Credential-chain paths** | The same secret appears in multiple contexts, letting trust cross service boundaries. | Which reused credential gives an agent access it never explicitly had? |
| **Reachability** | Agents, MCP servers, tools, resources, prompts, A2A skills, and AI services are joined into one graph. | What can this agent actually reach if trust edges are followed? |
| **Execution paths** | An agent can reach shell-like, database, network, or other high-impact tools. | Which agents have a path to command execution, data-plane control, or production impact? |
| **Exfiltration paths** | An agent can read sensitive data and also reach an outbound channel. | Where can sensitive data leave the environment? |
| **Cross-protocol pivots** | MCP, A2A, host context, and AI-service infrastructure combine into one reachable path. | Can one agent protocol become a bridge into another trust domain? |
| **Tool poisoning** | Tool descriptions, prompts, or instruction files contain suspicious model-steering content. | Which tools or instructions could influence model behavior in unsafe ways? |
| **Tool shadowing** | A lookalike tool mimics a trusted capability or name. | Which tool could intercept or hijack an expected action? |
| **Rug pulls** | A tool's description, schema, or server instructions changed between scans. | What changed since the last known-good graph, and did it create a new risk path? |
| **Unauthenticated servers or agents** | MCP servers or A2A agents are reachable without expected authentication. | Which exposed agent surfaces need immediate review? |
| **Risk hotspots** | Nodes and paths are prioritized with risk scores and prebuilt graph queries. | Where should investigation or remediation start first? |

See [Detection Rules](https://docs.agenthound.io/reference/detection-rules/) and [Risk Scoring](https://docs.agenthound.io/reference/risk-scoring/) for the full catalog.

## 🔗 Path primitives

AgentHound doesn't just list findings - it creates graph edges you can chain, query, and report:

- **`CAN_REACH`**: an agent can traverse trust, credential, host, or protocol relationships to reach a target.
- **`CAN_EXECUTE`**: an agent can reach a tool capable of command, database, network, or code execution.
- **`CAN_EXFILTRATE_VIA`**: an agent can read sensitive data and send it through an outbound channel.
- **`CAN_IMPERSONATE`**: an agent or identity can act as another trust principal.
- **`SHADOWS`**: a tool mimics a trusted tool closely enough to hijack expected behavior.
- **`POISONED_DESCRIPTION` / `POISONED_INSTRUCTIONS`**: tool or instruction text contains model-steering content.

These edges turn AI-agent infrastructure into something you can pathfind instead of manually reason about.

## 🗺️ Example path

```mermaid
flowchart LR
  Agent["AgentInstance<br/>claude-desktop"]
  Notes["MCPServer<br/>internal-notes"]
  Cred["Credential<br/>value_hash: a3f9..."]
  Gateway["LiteLLMGateway<br/>prod"]
  Providers["LLM providers<br/>OpenAI / Anthropic / Bedrock"]

  Agent -- TRUSTS_SERVER --> Notes
  Notes -- HAS_ENV_VAR --> Cred
  Gateway -- EXPOSES_CREDENTIAL --> Cred
  Agent -- CAN_REACH --> Gateway
  Gateway -- PROVIDES_MODEL --> Providers
```

No single config file declares this path. AgentHound computes it once collector output lands in the same graph.

## 🛡️ Safety & authorization

Built to be run under authorization, with the controls this audience checks for:

- **Read-only looter contract** - GET/HEAD only (narrow idempotent-search carve-outs), each guarded by a `get_only_test.go` regression test.
- **Destructive verbs dry-run by default** - `poison` / `implant` / `extract` do nothing mutating without `--commit`.
- **Compile-time-mandatory reverter** - `Poisoner` / `Implanter` embed `Reverter`; a module that can't undo itself won't build.
- **Receipt before mutation** - the undo receipt is persisted to disk *before* the write lands.
- **AUTHORIZED gates + `--engagement-id`** - interactive first-run prompts; every receipt and edge threaded for IR coordination.
- **Recon guardrails** - public-IP targets require opt-in + an authorization-file watermark; link-local/multicast refused outright.

**It is explicitly not** a C2, not an evasion implant (EDR will flag a binary named `agenthound`), and not a multi-user SaaS. It is an authorized-assessment framework, and the design says so.

Read the [security posture guide](https://docs.agenthound.io/operator/security/) and [offensive actions guide](https://docs.agenthound.io/operator/offensive-actions/).

## 📚 Docs · Contributing · License

[Quickstart](https://docs.agenthound.io/getting-started/quickstart/) · [CLI](https://docs.agenthound.io/reference/cli/) · [Graph Model](https://docs.agenthound.io/reference/graph-model/) · [Detection Rules](https://docs.agenthound.io/reference/detection-rules/) · [Security](https://docs.agenthound.io/operator/security/)

Write your own attack: implement an action interface, drop a `register.go`, blank-import it - see [CONTRIBUTING.md](CONTRIBUTING.md) and the [module authoring guide](https://docs.agenthound.io/contributing/modules/). Found a vulnerability in AgentHound itself? See [SECURITY.md](SECURITY.md).

AgentHound is licensed under the [Apache License 2.0](LICENSE).
