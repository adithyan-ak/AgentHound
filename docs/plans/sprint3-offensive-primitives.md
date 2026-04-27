# Sprint 3 — Offensive primitives (network scanner + first Looter)

> **Status:** Draft for design review.
> **Authors:** AgentHound architect (research + plan).
> **Date:** 2026-04-23.
> **Audience:** Adithyan AK + future contributors.
> **Scope of this document:** research-grounded plan for AgentHound's "ship the offensive surface" milestone (v0.2). **This is a plan, not an implementation.** No code in this repo changes as a result of this document beyond its own creation.

---

## 1. Context and strategic framing

### Why this milestone is the project's pivot point

The architect review of AgentHound's posture concluded that the project **wins if the next 6 months ship offensive surface, loses otherwise**. Today's collector is honest about what it does — it parses configs, queries MCP servers, fetches A2A agent cards, and emits a graph. That's a credible v0.1 for a security analysis tool. But the pitch — "BloodHound for AI agent infrastructure" — is doing a lot of heavier lifting than the binary actually delivers. BloodHound's value comes from active discovery (SharpHound walks AD, dumps trust data, maps reachability) and the cross-domain insight that follows. AgentHound's equivalent of "active discovery" is currently confined to a tiny address space: read configs on the operator's own host, and reach a known-good MCP/A2A endpoint. There is no story for *finding* AI infrastructure on a network you don't already have credentials for.

The credential-chain re-pitch — "we already detect the multi-hop CAN_REACH that traverses shared credentials, including the cross-protocol variant no other tool does" — only delivers value if the graph contains nodes worth chaining through. Today the graph is whatever the operator's own MCP clients trust. To make the credential-chain pitch land in a CFP submission or a customer demo, the graph must contain **services discovered on the network**: an Ollama exposed on a build agent, a LiteLLM gateway holding aggregated provider keys, a Qdrant vector store leaking customer embeddings, an MLflow tracker with model files an attacker can swap. The credential chain becomes interesting when the chain reaches those services.

This sprint delivers two concrete primitives that turn the credential-chain pitch from theory into a demo:

1. A **network scanner** that maps eight specific AI/ML services on a CIDR range. Narrow scope, narrow output. Not a Nuclei or Nmap competitor — a focused fingerprinter for AI infrastructure on standard ports.
2. A **first concrete Looter** for LiteLLM. The LiteLLM proxy aggregates provider API keys — a single master key compromise yields OpenAI, Anthropic, AWS Bedrock, Azure, and Cohere keys at once. Highest-leverage credential target in this entire space; the right place to start.

Together these turn the existing `Looter` SDK stub into a real interface with a real consumer, validate the v0 `Target` shape against an actual workflow, and produce demo data the credential-chain detector can fire against.

### What "shipped" means for v0.2

Concrete deliverables, ranked by load-bearing-ness:

1. **`agenthound scan <cidr|host|host-list>`** — CIDR/host expansion + bounded port sweep + AI-service fingerprinting. v0.2 commits to **2 services** (Ollama + LiteLLM); the remaining 6 fingerprinters slip to v0.3+ per the scope-creep correction in §9.8. Output: ingest JSON containing per-service nodes (e.g. `:OllamaInstance:AIService`, `:LiteLLMGateway:AIService`), `Host` nodes (already exists), and `RUNS_ON` edges (already exists).
2. **`agenthound loot <host> --type litellm [--master-key sk-...]`** — LiteLLM looter. Output: ingest JSON containing extracted `Credential` nodes with provenance (`source: 'litellm'`, `provider: 'openai'`, etc.), plus `EXPOSES_CREDENTIAL` edges from the LiteLLM gateway node to those credentials.
3. **Ten new node kinds** (8 per-service + `AIService` umbrella + `AIModel` reservation per §3.5 Option B multi-label) and **two new edge kinds** (`EXPOSES`, `EXPOSES_CREDENTIAL`) wired through the ingest schema, the validator (including the SHIP-BLOCKER fix at `server/internal/ingest/validator.go:80` per §6), the writer, and the UI.
4. **Demo seed file** (`testdata/demo/scan_lab.json`) showing a credential chain that reaches a LiteLLM-extracted OpenAI key. Generated from a real run of the §8.5 docker-compose lab plus an anonymization pass — NOT hand-fabricated.
5. **One submitted talk** to DEF CON 34 Demo Labs (May 1, 2026 deadline) + BSidesLV breaking-ground (May 8, 2026 verified deadline). DEF CON main-stage is intentionally NOT a v0.2 target — see §7's critical-scheduling-tension and §8.2 for reasoning. Aim DEF CON 35 (2027) main-stage with Phase 5+6 results. ([Demo Labs CFP](https://defcon.org/html/defcon-34/dc-34-cfdl.html))

What's *not* in v0.2: the other six action interfaces (`Extractor`, `Poisoner`, `Implanter`, `Reverter` for non-trivial cases). The three other concrete Looters (Ollama, Jupyter, MLflow). The template ecosystem split. Per-action binaries. Those are v0.3+ and outside this plan.

---

## 2. Target service deep-dive

The eight services below were chosen because they are: (a) the most-deployed self-hosted AI infrastructure in 2025–2026; (b) anonymous-by-default or weakly-defaulted; (c) hold loot that becomes interesting graph nodes (credentials, model files, embedding collections, customer prompts).

For each service this section documents what it is, how to fingerprint it anonymously, what loot it carries, and the known CVE history. All facts cited inline. Where I could not verify a specific claim I label it `unverified — needs operator confirmation`.

### 2.1 Ollama — local LLM inference server

**What it is.** Ollama is the most-deployed self-hosted LLM inference server. It bundles an HTTP API on top of llama.cpp-style inference, manages model downloads via an OCI-compatible registry, and ships with no built-in authentication. Operators run it locally for development, on shared inference boxes for teams, and increasingly on public cloud VMs they accidentally expose.

**Default port.** `11434/tcp`. Bind defaults to `127.0.0.1`; operators commonly change to `0.0.0.0` to enable remote access, at which point the API is unauthenticated to anyone with network reach. ([ollama API docs](https://github.com/ollama/ollama/blob/main/docs/api.md))

**Authentication model.** None. There is no built-in auth at all. The maintainers have a long-running issue thread debating whether to add it. ([Ollama issue #11941 — "Secure Mode"](https://github.com/ollama/ollama/issues/11941))

**Known unauthenticated endpoints.**
| Path | Returns |
|---|---|
| `GET /api/version` | `{"version": "0.5.1"}` (or current). Single field. |
| `GET /api/tags` | `{"models": [{"name": "...", "model": "...", "modified_at": "...", "size": ..., "digest": "...", "details": {...}}]}` — full inventory of locally-stored models, including custom fine-tunes. |
| `GET /api/ps` | Currently-loaded models with VRAM/RAM use. |
| `POST /api/show` | Model-card metadata: license, parameters, modelfile, template. |
| `POST /api/generate` / `/api/chat` | Inference. Anonymous. Compute resource consumed by the attacker, billed to the operator. |
| `POST /api/pull` | Pull arbitrary model from registry. **CVE-2024-37032 (Probllama)**: CVSS 8.8 HIGH — path-traversal in the digest field allowed arbitrary file write → RCE in versions before v0.1.34. CVSS technically lists `PR:L` (low privileges required), but since Ollama's default ships with no authentication at all, the privileges-required field is a distinction without a difference: any caller reaching the API is "privileged" by Ollama's definition. Effectively unauthenticated. ([NVD CVE-2024-37032](https://nvd.nist.gov/vuln/detail/CVE-2024-37032)) |
| `POST /api/embeddings` | Embed text. Anonymous. |

**Fingerprint signature.** Single GET to `/api/version` returns valid JSON `{"version": "X.Y.Z"}` with `Content-Type: application/json`. Highly specific — no other service emits exactly that shape on a `/api/version` path.

**Common loot.**
- Model inventory (custom fine-tunes leak training data signals — the model name often reveals the use case: `support-agent-v3`, `coder-internal:latest`).
- Modelfile content via `/api/show` (system prompts, custom templates — often leak product copy and customer data conventions).
- Free GPU compute via `/api/generate`.
- The model weights themselves via `/api/blobs/<digest>` — proprietary fine-tunes weighing tens of GiB, transferred over plain HTTP.

**Common config weaknesses.**
- `OLLAMA_HOST=0.0.0.0:11434` set without a reverse proxy.
- Default install on a Coolify/Railway/Render box, exposed by the platform's auto-egress.
- Behind a reverse proxy that strips auth on a `/v1` rewrite but forwards everything else.

**Fingerprinting difficulty.** Trivial. One GET, deterministic JSON, no authentication challenge. Easiest fingerprint of the eight.

**Looting difficulty.** Trivial. Model inventory, modelfile, and embeddings are all anonymous. Model weight extraction is rate-limited only by network bandwidth.

**OPSEC notes.** GET `/api/version` is so cheap and noiseless that it generates no anomaly signal in any AI-aware EDR I am aware of (assumption — this is the kind of thing a defender would not yet alert on). However: pulling weights via `/api/blobs/<digest>` is *very* loud — multi-GiB transfers, sequential range requests. Loot phase needs operator authorization.

**Real-world prevalence.** Public scanning in early 2026 found **12,269 Ollama instances** exposed on the public internet with no authentication, holding everything from `llama3.3:latest` to proprietary fine-tunes. ([LeakIX 2026 Ollama exposure report](https://blog.leakix.net/2026/02/ollama-exposed/))

**Representative fingerprint curl:**
```bash
curl -s --max-time 3 http://10.0.0.42:11434/api/version
# {"version":"0.5.1"}
```

**Representative loot curl (anonymous):**
```bash
curl -s http://10.0.0.42:11434/api/tags | jq '.models[].name'
# "llama3.3:latest"
# "support-agent-v3:latest"
# "coder-internal:7b"
```

---

### 2.2 vLLM — high-throughput LLM inference server

**What it is.** vLLM is the high-throughput inference server that ships an OpenAI-compatible HTTP API. It's the default choice for teams running self-hosted production inference behind a load balancer. Unlike Ollama, vLLM is not pitched as a developer-laptop tool — its presence on a network signals real production AI workloads.

**Default port.** `8000/tcp`. ([vLLM docs](https://docs.vllm.ai/en/stable/serving/openai_compatible_server/))

**Authentication model.** Optional via `--api-key <KEY>` flag. **No authentication is enabled by default.** Operators must explicitly pass an API key on the command line to require one. ([vLLM OpenAI server docs](https://docs.vllm.ai/en/stable/serving/openai_compatible_server/))

**Known unauthenticated endpoints (when `--api-key` not set).**
| Path | Returns |
|---|---|
| `GET /v1/models` | OpenAI-compatible model list — `{"object":"list","data":[{"id":"...","object":"model",...}]}`. |
| `POST /v1/completions` | OpenAI-compatible completion. |
| `POST /v1/chat/completions` | OpenAI-compatible chat. |
| `GET /health` | Liveness. |
| `GET /metrics` | Prometheus metrics — leaks request counts, model names, GPU utilization, queue depth. |
| `GET /version` | Version string (typically `"vllm-X.Y.Z"`). |

**Fingerprint signature.** `GET /v1/models` with no auth header returning a 200 JSON body containing `"object":"list"` and a `data` array where each entry has `"object":"model"`. Combined with a path of `/v1/models` (not `/api/models` or `/models`), this strongly indicates an OpenAI-compatible gateway. To distinguish vLLM from LiteLLM/llama.cpp's server/etc., probe `/version` or look for the vLLM-specific Prometheus metric names at `/metrics` (e.g. `vllm:request_success_total`).

**Common loot.**
- The list of models served — high-signal because production deployments often serve fine-tunes named after the use case.
- Free production GPU compute.
- If `/metrics` is exposed: GPU memory, queue depth, request rate — operational intel for a live op.
- Prompt logs if the operator left request logging on (`unverified — depends on operator config`).

**Common config weaknesses.**
- No `--api-key`.
- `--enable-auto-tool-choice` exposing tool-calling APIs to unauthenticated callers.
- Custom chat templates (`--chat-template`) that import from a path traversable by a malicious request body — see CVE-2025-61620.

**Known CVEs (2024–2026).**
- **CVE-2025-62164** (CVSS 8.8 HIGH; vector `AV:N/AC:L/PR:L/UI:N`) — RCE via PyTorch deserialization in `prompt_embeds` in the Completions API. **Affected version range: `>= 0.10.2, < 0.11.1`.** Privileges-required is **LOW** (an authenticated API caller), not None — so this is *not* "anonymous RCE" by CVSS. In practice, vLLM's default deployment does not set `--api-key`, which means any caller is "authenticated" and the bug is effectively unauthenticated. Anyone framing this as "anonymous RCE" on a CFP slide will be corrected by a sharp reviewer; frame it precisely as "RCE via PyTorch deserialization, exploitable by any API caller, and effectively unauthenticated in the default `--api-key`-not-set deployment." ([NVD CVE-2025-62164](https://nvd.nist.gov/vuln/detail/CVE-2025-62164), [GHSA-mrw7-hf4f-83pf](https://github.com/advisories/GHSA-mrw7-hf4f-83pf))
- **CVE-2025-61620** (medium) — Jinja2 template DoS via `chat_template`/`chat_template_kwargs`. ([Miggo CVE-2025-61620](https://www.miggo.io/vulnerability-database/cve/CVE-2025-61620))
- **CVE-2025-66448** (high) — RCE via `auto_map` in model config. Attacker publishes a benign-looking frontend model that points to a malicious backend repo; victim loads frontend, backend code executes silently. Affects vLLM <0.11.1. ([ZeroPath summary](https://zeropath.com/blog/cve-2025-66448-vllm-rce-automap))
- **CVE-2025-9141** (high) — RCE in the Qwen3-Coder tool-call parser. **Affected version range: `>= 0.10.0, < 0.10.1.1`.** Requires both `--enable-auto-tool-choice` AND `--tool-call-parser qwen3_coder` flags to be set on the vLLM process; without both, the vulnerable code path is not reachable. ([GitLab advisories](https://advisories.gitlab.com/pkg/pypi/vllm/CVE-2025-9141/))

**Fingerprinting difficulty.** Easy. `GET /v1/models` reveals it deterministically.

**Looting difficulty.** Trivial when no API key is set. The mere fact that the service exists and is unauthenticated is the loot — production inference for free, model identity disclosed.

**OPSEC notes.** `/v1/models` requests look like ordinary OpenAI client traffic. `/metrics` scraping is louder if the operator has Prometheus alerting on unfamiliar scrapers.

**Representative fingerprint curl:**
```bash
curl -s --max-time 3 http://10.0.0.42:8000/v1/models
# {"object":"list","data":[{"id":"meta-llama/Meta-Llama-3.1-8B-Instruct","object":"model",...}]}
```

---

### 2.3 Qdrant — vector database

**What it is.** Qdrant is a Rust-based vector database used as the embedding store for RAG pipelines. It's the most common self-hosted vector DB in 2025–2026 — competes with Weaviate, Milvus, Chroma. Holds the embedding side of every RAG-based AI app it backs.

**Default port.** REST `6333/tcp`, gRPC `6334/tcp`. ([Qdrant security docs](https://qdrant.tech/documentation/guides/security/))

**Authentication model.** **API key auth is OFF by default in self-hosted deployments.** Qdrant Cloud is secure by default; the open-source Docker image ships with no auth. Operators must set `service.api_key` in `config.yaml` to require one. ([Qdrant security docs](https://qdrant.tech/documentation/guides/security/))

**Known unauthenticated endpoints (when `api_key` not set).**
| Path | Returns |
|---|---|
| `GET /` | Welcome banner with version. |
| `GET /collections` | List of collection names. Each name often reveals the use case (`customer-support-prod`, `internal-docs`, `pii-redacted-v2`). |
| `GET /collections/<name>` | Schema, vector dimension, indexed metadata fields. |
| `POST /collections/<name>/points/scroll` | **Scroll through embedded points** — including the original payload metadata (often the source URL, the document ID, sometimes the original text). |
| `POST /collections/<name>/points/search` | Vector search. |
| `GET /telemetry` | Cluster + uptime info. |
| `GET /metrics` | Prometheus metrics. |
| `GET /readyz`, `GET /healthz` | Liveness. |

**Fingerprint signature.** `GET /collections` returning JSON shaped like `{"result":{"collections":[{"name":"..."}]},"status":"ok","time":...}` is a Qdrant-specific response shape. The presence of `time` as a top-level float field is distinctive.

**Common loot.**
- Collection names → reveals AI use cases by inventory.
- Point payloads via `/points/scroll` → original document IDs, source URLs, sometimes the raw indexed text. High likelihood of customer data exposure.
- Vector embeddings themselves (less interesting to a typical attacker, but valuable for embedding-inversion attacks).

**Common config weaknesses.**
- Self-hosted deployment without `api_key`.
- TLS off (`api_key` over plaintext leaks the key on first request).

**Known CVEs.** No high-impact CVEs publicly documented as of 2026-04-23 (`unverified — needs operator confirmation` against NVD). The dominant security failure mode is misconfiguration (no API key), not protocol-level vulns.

**Fingerprinting difficulty.** Easy.

**Looting difficulty.** Trivial when no API key is set. The collection list and point payloads are anonymous reads.

**OPSEC notes.** `/points/scroll` paginated reads at full speed are loud — Qdrant logs them and a defender with log review will see the access pattern.

**Representative fingerprint curl:**
```bash
curl -s --max-time 3 http://10.0.0.42:6333/collections
# {"result":{"collections":[{"name":"customer-support-prod"},{"name":"internal-docs"}]},"status":"ok","time":0.0004}
```

**Representative loot curl (anonymous):**
```bash
curl -s -X POST http://10.0.0.42:6333/collections/customer-support-prod/points/scroll \
  -H 'Content-Type: application/json' \
  -d '{"limit":10,"with_payload":true,"with_vector":false}'
# {"result":{"points":[{"id":1,"payload":{"doc_id":"DOC-12345","source":"https://internal.example.com/tickets/12345"}}]},...}
```

---

### 2.4 MLflow — ML experiment tracker

**What it is.** MLflow is the dominant open-source ML experiment tracker. Stores runs, parameters, metrics, model artifacts. Used by data science teams to coordinate model development. Often left exposed on internal networks because operators consider experiment metadata "low-sensitivity" — until an attacker finds the model artifacts that the experiments produced.

**Default port.** `5000/tcp`. Bind defaults to `localhost`. ([MLflow tracking server docs](https://mlflow.org/docs/latest/ml/tracking/server/))

**Authentication model.** None by default. MLflow ships an optional `basic-auth` plugin (`mlflow server --app-name basic-auth`) that adds HTTP Basic Auth, but it must be explicitly enabled. ([MLflow basic auth docs](https://mlflow.org/docs/latest/self-hosting/security/basic-http-auth/))

**Known unauthenticated endpoints.**
| Path | Returns |
|---|---|
| `GET /` | MLflow web UI HTML. The HTML title `<title>MLflow</title>` is highly distinctive. |
| `GET /api/2.0/mlflow/experiments/search` | List experiments. |
| `GET /api/2.0/mlflow/runs/search` | List runs — parameters, metrics, tags. |
| `GET /api/2.0/mlflow/registered-models/search` | Registered models with version + artifact paths. |
| `GET /api/2.0/mlflow/artifacts/<path>` | **Download model artifacts** — often pickled model files. |
| `GET /version` | Version. |

**Fingerprint signature.** `GET /` returns HTML with `<title>MLflow</title>` and `<meta name="generator" content="mlflow">` (`unverified — needs operator confirmation that the meta tag is present in current versions`). Reliable secondary fingerprint: `GET /api/2.0/mlflow/experiments/search?max_results=1` returning JSON `{"experiments":[...]}`.

**Common loot.**
- Experiment metadata: hyperparameters often leak the model architecture, the dataset shape, the tuning history.
- Run logs: training-time stack traces sometimes contain credentials embedded in environment variable dumps.
- **Model artifacts**: pickled `.pkl` files that the operator may unpickle into production. Pickled file in an attacker-writable artifact store is RCE waiting to happen — and basic-auth-less MLflow makes the artifact store attacker-writable.
- Tag values: teams often tag runs with the dataset URL, the model registry URL, the deployment environment. High-value reconnaissance data.

**Common config weaknesses.**
- No basic-auth.
- Artifact store is a local filesystem path that the MLflow process can write to (so an attacker who can POST runs can drop arbitrary files into the artifact store).
- Database backend (`--backend-store-uri`) is a connection string that may itself leak credentials in error messages.

**Known CVEs.**
- **CVE-2024-27132** (CVSS 9.6 CRITICAL; vector `AV:N/AC:L/PR:N/UI:R`) — Reflected/DOM-based XSS in MLflow recipes due to lack of template-variable sanitization (NOT stored XSS — earlier framing was incorrect). PR:N means the attacker is truly unauthenticated; UI:R means the victim must click a crafted recipe link. When the victim loads the page in a Jupyter context, XSS in that context is equivalent to RCE on whichever machine hosts the Jupyter server. Affects MLflow ≤2.9.2. ([NVD CVE-2024-27132](https://nvd.nist.gov/vuln/detail/CVE-2024-27132), [JFrog research](https://research.jfrog.com/vulnerabilities/mlflow-untrusted-recipe-xss-jfsa-2024-000631930/))
- JFrog's "MLOps to MLOops" report documents an additional family of MLflow vulnerabilities around path traversal in artifact uploads. ([JFrog blog](https://jfrog.com/blog/from-mlops-to-mloops-exposing-the-attack-surface-of-machine-learning-platforms/))

**Fingerprinting difficulty.** Easy — the unauthenticated `/api/2.0/mlflow/experiments/search` is a deterministic fingerprint.

**Looting difficulty.** Easy when basic-auth is off. The artifact-download endpoint is anonymous; pickled files are downloadable directly.

**OPSEC notes.** Artifact-list and metadata reads are normal MLflow client traffic — quiet. Artifact downloads of multi-GB pickles are loud.

**Representative fingerprint curl:**
```bash
curl -s --max-time 3 'http://10.0.0.42:5000/api/2.0/mlflow/experiments/search?max_results=1'
# {"experiments":[{"experiment_id":"0","name":"Default",...}]}
```

---

### 2.5 LiteLLM — LLM gateway / proxy (FIRST LOOTER TARGET)

**What it is.** LiteLLM is the dominant open-source multi-provider LLM gateway. It accepts OpenAI-compatible requests and routes them to whichever provider an operator configures — OpenAI, Anthropic, Azure, AWS Bedrock, Cohere, Vertex AI, Mistral, dozens more. **Operators store the underlying provider keys in LiteLLM's config or database, and a single LiteLLM master key gates access to all of them.** This is why LiteLLM is the highest-leverage credential target in the entire AI infrastructure space.

A compromised LiteLLM master key is one HTTP request away from leaking every provider key the gateway aggregates. That is the credential chain we want to demo.

**Default port.** `4000/tcp`. The README, getting-started guides, and config examples all reference `http://0.0.0.0:4000`. ([LiteLLM README](https://github.com/BerriAI/litellm))

**Authentication model.** Two-tiered:
- **Master key** (`LITELLM_MASTER_KEY` env var, format `sk-<anything>`, must start with `sk-`). Required for all `/key/*`, `/user/*`, `/team/*` admin endpoints. Set via env var or `general_settings.master_key` in `config.yaml`. ([virtual_keys docs](https://docs.litellm.ai/docs/proxy/virtual_keys))
- **Virtual keys** (`sk-<random>`, generated via `/key/generate`). Used for normal `/v1/chat/completions` traffic. Stored in the LiteLLM Postgres backend.

**Known unauthenticated endpoints.**
| Path | Auth | Returns |
|---|---|---|
| `GET /health/liveliness` | **Anonymous** | `"I'm alive!"` (literal string). ([LiteLLM health docs](https://docs.litellm.ai/docs/proxy/health)) |
| `GET /health/readiness` | **Anonymous** | Readiness probe. ([LiteLLM health docs](https://docs.litellm.ai/docs/proxy/health)) |
| `GET /health` | Master key required | Calls every configured model — leaks the full model list AND model health to anyone with the master key. |
| `GET /` | Anonymous | Server info / Swagger UI redirect. |
| `GET /docs`, `GET /redoc` | Anonymous (FastAPI default unless explicitly disabled) | **The full OpenAPI spec for the LiteLLM proxy** — every admin endpoint enumerated. Massive recon win. |
| `POST /v1/chat/completions` | Virtual key required | OpenAI-compatible chat. Returns 401 without a key. |
| `GET /v1/models` | `unverified — depends on no_auth_endpoint config` | Often anonymous, often returns the configured-model list. |

**Master-key-required endpoints (the real loot).**
| Path | Method | Returns |
|---|---|---|
| `POST /key/generate` | POST | Generate a virtual key. |
| `GET /key/info?key=sk-...` | GET | Key metadata: `{"key": "sk-...", "spend": 12.34, "expires": "...", "models": ["gpt-4o", "claude-3-5-sonnet"], "team_id": "...", "user_id": "...", "metadata": {...}}`. |
| `GET /key/list` | GET | All virtual keys (paginated). |
| `POST /user/new`, `POST /team/new` | POST | User/team admin. |
| `GET /model/info` | GET | **All configured models AND the upstream provider configuration** — including, depending on version, the upstream `api_base`, `api_key` reference, model parameters. This is the credential leak surface. |
| `GET /model_group/info` | GET | Model group routing. |
| `POST /config/update` | POST | Live-update the proxy config — write access. |

**Fingerprint signature.** Multiple highly-specific options:
1. `GET /health/liveliness` returning the literal body `"I'm alive!"` (with quotes — JSON-encoded string). No other service emits exactly this response.
2. `GET /` returning a redirect or HTML referencing `litellm` in the title.
3. `GET /docs` returning a Swagger UI page with `LiteLLM API` in `<title>`.
4. The presence of `/v1/chat/completions` returning `401 {"error":{"message":"Authentication Error...","type":"auth_error"}}` with the exact LiteLLM error envelope.

**Common loot when master key is leaked.**
- **Provider API keys** for every configured upstream — OpenAI, Anthropic, AWS Bedrock, Azure OpenAI, Vertex, Mistral, Cohere, Together, Replicate, DeepInfra, etc. These keys are the actual high-value loot.
- All virtual keys via `/key/list` — useful for billing fraud or impersonating downstream applications.
- User/team metadata — names, emails, spend limits.
- Routing config — reveals which provider serves which model, useful for downstream targeting.
- Audit log access (in versions that ship it) — request histories with prompts in some configurations.

**Loot when master key is NOT leaked but the deployment has known weaknesses.**
- SSRF (CVE-2024-6587) — set `api_base` in a `/v1/chat/completions` request to your own server, capture the OpenAI key as it forwards. **Version note: NVD lists `berriai/litellm` version 1.38.10 as vulnerable; the GHSA confirms the issue is patched in 1.44.8.** Earlier framing of "fixed in 1.38.10" was incorrect — that is a vulnerable version, not the patched version. ([NVD CVE-2024-6587](https://nvd.nist.gov/vuln/detail/CVE-2024-6587), [GHSA-g26j-5385-hhw3](https://github.com/advisories/GHSA-g26j-5385-hhw3))
- Log-leak (CVE-2024-9606) before 1.44.12 — masking only redacted the first 5 chars of API keys; the rest leaked into logs. ([feedly CVE feed](https://feedly.com/cve/vendors/litellm))
- Langfuse secret leak (CVE-2025-0330) — full Langfuse project access via parsed team settings. ([same CVE feed](https://feedly.com/cve/vendors/litellm))
- 2026 supply-chain incident: malicious litellm 1.82.7/1.82.8 published via compromised CI. ([LiteLLM March 2026 security update](https://docs.litellm.ai/blog/security-update-march-2026))

**Common config weaknesses.**
- Master key with low-entropy suffix (`sk-1234`, `sk-litellm-prod`, `sk-master`).
- `/docs` left enabled in production — leaks the full admin API.
- Master key checked into git (we already detect this with the high-entropy-secrets rule).
- Stored in env file at a predictable path (`/app/.env`, `/etc/litellm/config.yaml`).

**Fingerprinting difficulty.** Trivial. `GET /health/liveliness` is a one-shot deterministic fingerprint.

**Looting difficulty.** Anonymous loot is limited to enumeration of the admin surface (via `/docs`). Real loot requires master-key compromise, which the operator supplies via `--master-key` flag at loot time. We do NOT attempt to brute-force or guess the master key — that's a separate Looter (or never; we're a transparent assessment tool, not a brute forcer).

**OPSEC notes.** Authenticated `/key/list` and `/model/info` calls look like routine admin operations. They will appear in LiteLLM's request log if logging is enabled. Defenders watching the LiteLLM Prometheus metrics will see a small request burst.

**Representative fingerprint curl:**
```bash
curl -s --max-time 3 http://10.0.0.42:4000/health/liveliness
# "I'm alive!"
```

**Representative loot curl (with master key):**
```bash
# 1. Enumerate all virtual keys.
curl -s -H "Authorization: Bearer ${MASTER_KEY}" \
  http://10.0.0.42:4000/key/list

# 2. Get the upstream model configuration.
curl -s -H "Authorization: Bearer ${MASTER_KEY}" \
  http://10.0.0.42:4000/model/info
# Returns the full configured-model list. Depending on LiteLLM version,
# `litellm_params.api_key` is exposed in the response or referenced by env-var name.
```

---

### 2.6 Jupyter — Notebook + Lab + Hub

**What it is.** Three related products. Jupyter Notebook (legacy) and JupyterLab (current) are single-user interactive Python environments. JupyterHub provides multi-user authentication and spawning. All run a web server that hosts arbitrary code execution by design — running a notebook cell is equivalent to executing arbitrary Python on the host.

**Default port.** `8888/tcp` (Notebook/Lab default), `8000/tcp` (Hub default).

**Authentication model.** Token-based by default. On startup, Jupyter Server logs a URL like `http://127.0.0.1:8888/?token=<random>` — the token is the credential. The token can be disabled with `--ServerApp.token=''` (strongly discouraged but commonly done in tutorials, container images, and CI). ([Jupyter security docs](https://jupyter-server.readthedocs.io/en/latest/operators/security.html))

**Known unauthenticated endpoints (when token is empty or leaked).**
| Path | Returns |
|---|---|
| `GET /` | The Jupyter Lab/Notebook UI. |
| `GET /api` | Jupyter Server version. |
| `GET /api/contents/<path>` | **List + read every file** under the notebook root. |
| `POST /api/sessions` + WebSocket to `/api/kernels/<id>/channels` | Spawn a kernel and execute arbitrary code. |
| `GET /tree` | File tree UI. |
| `GET /files/<path>` | Direct file download. |

**Fingerprint signature.** `GET /api` returns `{"version":"X.Y.Z"}` with `Server: TornadoServer/X.Y.Z` header. Unique enough when combined with the path.

**Common loot.**
- The full notebook directory — source code, datasets, secrets in `.env` files, SSH keys cached in `~/.ssh` (if running as a user with that home dir mounted).
- Arbitrary code execution if the token is missing or known. RCE-by-design.
- Kernel state — variables in memory often hold credentials, customer data, model weights.

**Common config weaknesses.**
- `--ServerApp.token=''` and `--ServerApp.password=''` together with `--ServerApp.ip='0.0.0.0'` — the unholy trinity of "I just want it to work".
- Token leaked in logs that are mounted to a public S3 bucket or syslog forwarded.
- Token in browser history shared via a screenshot.
- Default Docker images (`jupyter/datascience-notebook`) where the operator forgets to inject a token.

**Known CVEs (2024–2026).**
- **CVE-2024-28179** (high) — Jupyter Server Proxy websocket proxying did not enforce auth before 3.2.3 / 4.1.1. Anyone with network reach to the Jupyter endpoint could hit a proxied websocket service unauthenticated, leading to RCE in many real deployments. ([NVD CVE-2024-28179](https://nvd.nist.gov/vuln/detail/CVE-2024-28179), [GHSA-w3vc-fx9p-wp4v](https://github.com/advisories/GHSA-w3vc-fx9p-wp4v))
- **CVE-2023-39968** + **CVE-2024-22421** — chained token-leak via cross-origin issue + a Chromium bug. ([xss.am writeup](https://blog.xss.am/2023/08/cve-2023-39968-jupyter-token-leak/))

**Fingerprinting difficulty.** Easy. The Tornado server header + `/api` response is a clean signal.

**Looting difficulty.** If the token is empty: trivial. If a token is set: requires the operator to provide it (analogous to LiteLLM master key).

**OPSEC notes.** A kernel spawn shows up in Jupyter's audit log. File downloads of `.ipynb` files at scale are loud.

**Representative fingerprint curl:**
```bash
curl -s --max-time 3 http://10.0.0.42:8888/api
# {"version":"2.10.1"}
```

---

### 2.7 LangServe — LangChain serving framework

**What it is.** LangServe wraps any LangChain Runnable in a FastAPI app. Used by teams that built a prototype on LangChain and want to deploy it as an HTTP service. The deployed service ships with a `/playground/` UI that reveals the chain's prompt and tools.

**Default port.** Inherits from FastAPI / Uvicorn — `8000/tcp` is conventional. ([LangServe README](https://github.com/langchain-ai/langserve))

**Authentication model.** None by default. LangServe is a framework — operators add auth via FastAPI middleware or a reverse proxy. Most prototype deployments ship with no auth at all.

**Known unauthenticated endpoints.**
| Path | Returns |
|---|---|
| `GET /docs` | **FastAPI auto-generated Swagger UI** — full API surface enumerated. |
| `GET /redoc` | Alternative API docs. |
| `GET /openapi.json` | Machine-readable OpenAPI spec. |
| `GET /<chain>/playground/` | **Interactive playground for the chain** — exposes the prompt template, the tools, the input schema. |
| `POST /<chain>/invoke` | Execute the chain. |
| `POST /<chain>/batch` | Execute the chain on a batch. |
| `POST /<chain>/stream` | Stream chain output. |
| `POST /<chain>/stream_log` | **Streams every intermediate step including the system prompt and tool inputs** — leaks the chain's internals. |

**Fingerprint signature.** `GET /docs` returning a Swagger UI titled with the chain name + `GET /openapi.json` containing paths matching `/<chain>/(invoke|batch|stream)`. Highly distinctive — no other framework emits exactly the LangServe path pattern.

**Common loot.**
- The chain's prompt template (via `/playground/` or `/openapi.json` schema).
- Tool list and tool schemas (via `/openapi.json`).
- Free use of the chain's downstream LLM provider, billed to the operator.
- `/stream_log` leaks intermediate tool calls and tool outputs — high-value reconnaissance for a downstream attack.

**Common config weaknesses.**
- No auth middleware.
- `/docs` enabled in production.
- Chain names that reveal the use case (`/internal-pii-redactor/`, `/customer-support-bot/`).

**Known CVEs.** No high-severity LangServe-specific CVEs as of 2026-04-23 (`unverified — needs operator confirmation`). The dominant security failure mode is the framework's lack of opinionated auth defaults, not protocol vulnerabilities. LangChain itself has accumulated CVEs around tool-execution sinks; those manifest in LangServe deployments.

**Fingerprinting difficulty.** Easy via `/openapi.json` shape.

**Looting difficulty.** Anonymous loot is plentiful when no auth middleware is configured.

**OPSEC notes.** `/playground/` accesses look like developer traffic. `/stream_log` is loud (long-polled HTTP).

**Representative fingerprint curl:**
```bash
curl -s --max-time 3 http://10.0.0.42:8000/openapi.json | jq -r '.paths | keys[]' | head -5
# /chat/invoke
# /chat/batch
# /chat/stream
# /chat/stream_log
# /chat/playground
```

---

### 2.8 Open WebUI — chat front-end with RAG

**What it is.** Open WebUI is the most-deployed open-source chat front-end for self-hosted LLMs. Backs onto Ollama, OpenAI-compatible APIs, or LiteLLM. Adds RAG (vector store + document upload), conversation history, multi-user accounts, OAuth, an admin panel.

**Default port.** Container port `8080/tcp`. Most docker run examples map host port `3000:8080`. ([Open WebUI quickstart](https://docs.openwebui.com/getting-started/quick-start/))

**Authentication model.** Sign-up + login by default. **First account created becomes admin.** This is the standard setup pitfall: an operator deploys, forgets to sign up first, an attacker reaches the instance, signs up first, and inherits admin. The `WEBUI_AUTH=False` env var disables auth entirely (also commonly set in tutorials). ([Open WebUI quick-start](https://docs.openwebui.com/getting-started/quick-start/))

**Known unauthenticated endpoints (when no admin account exists yet, or when `WEBUI_AUTH=False`).**
| Path | Returns |
|---|---|
| `GET /` | Login/signup page. |
| `GET /api/version` | `{"version":"X.Y.Z"}`. Anonymous. |
| `GET /api/config` | Front-end config. Anonymous. Reveals which auth methods are enabled. |
| `POST /api/v1/auths/signup` | Create an account. **First account becomes admin.** |
| `GET /api/v1/auths/admin/details` | Admin email if set. |

**Fingerprint signature.** `GET /api/config` returning `{"name": "Open WebUI", ...}` is a clean signal. Alternatively `GET /` returning HTML containing `Open WebUI` in `<title>`.

**Common loot (post-signup-as-admin).**
- All chat histories of all users.
- Uploaded documents (the RAG corpus).
- Configured model providers — including upstream API keys (depending on Open WebUI version, the admin panel exposes keys in plaintext).
- OAuth tokens for connected services.

**Common config weaknesses.**
- Deployed but never signed up — first-arrival wins.
- `WEBUI_AUTH=False` in env.
- `ENABLE_SIGNUP=true` (default in older versions) on a public-facing instance.
- Direct Connections feature enabled (CVE-2025-64496 — see below).

**Known CVEs (2025).**
- **CVE-2025-64496** (CVSS 7.3 HIGH; vector includes `PR:L` and `UI:R`) — Open WebUI ≤0.6.34 with Direct Connections enabled. SSE event handling allows JS execution in the user's browser → token theft from localStorage → account takeover; with admin-level Direct Connections, RCE on backend. Fixed in 0.6.35. **Important caveat: Direct Connections is disabled by default** — exploitation requires both (a) an admin to have explicitly enabled the feature and (b) a victim user to be tricked into a malicious Direct Connection (UI:R). PR:L means an authenticated user is also required. The compounded preconditions mean this CVE is *much* less broadly exploitable than the 7.3 score suggests on its own. ([Cato CTRL writeup](https://www.catonetworks.com/blog/cato-ctrl-vulnerability-discovered-open-webui-cve-2025-64496/), [GHSA-cm35-v4vp-5xvx](https://github.com/advisories/GHSA-cm35-v4vp-5xvx))
- **CVE-2025-63681** (CVSS 4.0/2.1 LOW) — Incorrect access control. **Trivial impact** — DoS only: an authenticated user can stop other users' tasks. This is essentially a permissions bug, not an exploitable vulnerability that yields data, code execution, or privilege escalation. Mention it for completeness; do not pitch it as load-bearing. ([GHSA-frv8-gffc-37px](https://github.com/advisories/GHSA-frv8-gffc-37px))

**Fingerprinting difficulty.** Easy.

**Looting difficulty.** Highly variable: trivial when `WEBUI_AUTH=False` or no admin signed up; hard when properly configured.

**OPSEC notes.** Sign-up creates a user record visible to any future admin. Loot phase will be visible in audit logs.

**Representative fingerprint curl:**
```bash
curl -s --max-time 3 http://10.0.0.42:8080/api/config | jq -r '.name'
# "Open WebUI"
```

---

### 2.9 Cross-cutting summary

| Service | Anonymous fingerprint | Anonymous loot? | Best loot |
|---|---|---|---|
| Ollama | `GET /api/version` | Yes — full models, weights, modelfile | Custom fine-tunes + free GPU |
| vLLM | `GET /v1/models` | Yes (when `--api-key` not set) | Production model identities |
| Qdrant | `GET /collections` | Yes (when `api_key` not set) | Embedded payloads + URLs |
| MLflow | `GET /api/2.0/mlflow/experiments/search` | Yes (when basic-auth not set) | Pickled model artifacts |
| LiteLLM | `GET /health/liveliness` | Limited — `/docs`, `/health/liveliness` | Provider keys (with master key) |
| Jupyter | `GET /api` | If token empty: full RCE | Arbitrary code execution |
| LangServe | `GET /openapi.json` | Yes | Chain internals + tool schemas |
| Open WebUI | `GET /api/config` | Sign-up-as-admin race | Chat histories + provider keys |

The pattern: **six of the eight services are anonymous-by-default for high-value loot**. LiteLLM and Open WebUI are the exceptions, and even those have well-known auth-bypass paths.

---

## 3. Network scanner architecture

### 3.1 Goals and non-goals

**Goals:**
- CIDR/host/file-of-hosts expansion to a target list.
- Bounded-concurrency port sweep — only the eight ports above by default, configurable.
- Service fingerprinting via the rules engine (extended with HTTP-aware matchers).
- Emit a graph patch — `Host` nodes (existing), `AIService` nodes (new), `EXPOSES` edges (new), `RUNS_ON` edges (existing).

**Non-goals:**
- Full TCP port scan. We probe specific ports.
- OS detection, banner grabbing for non-AI services. Not our domain.
- Replacement for Nmap or Nuclei. We do NOT compete with those tools.
- Vulnerability scanning. We fingerprint services and let the post-processors flag risk.
- Brute-forcing master keys, tokens, or API keys. We are a transparent assessment tool. The operator brings credentials at loot time.

### 3.2 CIDR / target expansion

Three input modes:

| Input | Expansion |
|---|---|
| `agenthound scan 10.0.0.0/24` | All 254 host addresses. /32 = single host. /128 = single IPv6 host. |
| `agenthound scan 10.0.0.42` | Single host. |
| `agenthound scan --targets-file hosts.txt` | One host per line. `#` comments allowed. |
| `agenthound scan vllm.example.internal` | DNS resolution → A/AAAA records. |
| `agenthound scan 10.0.0.0/24 --ports 11434,8000,8888` | Override the default port list. |

Bounds:
- **CIDR size cap.** Default refuse anything larger than /16 (65 K hosts). Override via `--allow-large-cidr` to acknowledge the operator knows what they're asking for. A /8 unbounded would generate 16 M × 8 ports = 134 M probes — that's not a scanner, that's a DDoS.
- **IPv6 caps.** Refuse anything wider than /112 (65 K hosts) without the override flag.
- **Sanity check on private vs public ranges.** Default deny scans against public IP space without `--allow-public-targets` flag. This is the legal/ethics guard.

Implementation note: Go's `net/netip` package (preferred over `net.IP` for new code in 2026) handles both v4 and v6 cleanly. Target expansion produces an iterator, not a slice — a /16 has 65 K addresses and we should not materialize them all.

### 3.3 Port sweep

For each target host, probe each configured port with a TCP connect (no SYN scan — we are not raw-socket-privileged, and connect scans are sufficient for our threat model). Bounded concurrency via a semaphore — default 50 in-flight connections, override `--scan-concurrency`. Connection timeout 3 seconds (the rule-of-thumb for "is this port open"). Failed connections are dropped silently.

For each open port, dispatch to the appropriate fingerprinter for that port (the registry maps port → fingerprinter module).

```
host=10.0.0.42 → port 11434 OPEN → ollama fingerprinter
                → port 8000  OPEN → vllm fingerprinter (also tried: langserve)
                → port 4000  OPEN → litellm fingerprinter
                → port 6333  OPEN → qdrant fingerprinter
                → port 8888  CLOSED
                → port 5000  CLOSED
                → port 8080  OPEN → open-webui fingerprinter
```

Port-to-fingerprinter mapping is many-to-many: port 8000 might be vLLM or LangServe. The fingerprinter is responsible for emitting "no match" when its specific signal isn't there. We fan out to all candidate fingerprinters per port; the first one to return a positive match wins.

### 3.4 Fingerprint matching — extending `sdk/rules`

The current `sdk/rules` engine matches against text inputs (tool descriptions, instruction files). HTTP-aware fingerprinting needs three new matcher types per `docs/future-modules.md`:

| New matcher type | Spec field | Example |
|---|---|---|
| `http_status` | `expected: 200` | Match HTTP response status. |
| `http_header` | `name: "Server", pattern: "TornadoServer"` | Match a header name against a regex. |
| `json_path` | `path: "$.version", pattern: "^0\\..*"` | JSONPath extraction + regex match on the value. |

These extensions land behind a `MatcherSpec.Version: 2` boundary so existing rules don't silently re-interpret. (This is the same approach `docs/future-modules.md` calls out.)

A fingerprint rule for Ollama would look like:

```yaml
# rules/builtin/fingerprints/ollama.yaml
id: fingerprint.ollama
version: 2
service_kind: ollama          # routing tag — used by the dispatcher,
                              # also stored on the node as a property
                              # for unified-query convenience.
match_strategy: any           # NEW — at least one matcher must match
probes:
  - method: GET
    path: /api/version
    timeout: 3s
matchers:
  - type: http_status
    expected: 200
  - type: json_path
    path: $.version
    pattern: '^\d+\.\d+\.\d+$'
emits:
  node_kinds: ["OllamaInstance", "AIService"]   # multi-label per §3.5 Option B
  properties:
    service_kind: ollama
    version_extractor: $.version
```

The rules-engine extension is the most architecturally significant piece of this sprint. It transforms the rules engine from a text-pattern matcher into an HTTP-fingerprinting engine reusable for future template-ecosystem work.

### 3.5 Output — node and edge model

**Decision: per-service node kinds, optionally with multi-label `:AIService` for unified queries. (REVISED — see callout below.)**

The earlier draft of this plan recommended a single `AIService` node kind with `service_kind` as a property. Two independent verification reviews flagged this as inconsistent with the existing codebase. Re-examining:

- `sdk/ingest/kinds.go:4-17` enumerates 12 distinct labels (`MCPServer`, `MCPTool`, `A2AAgent`, `Credential`, etc.) — every existing service-like entity has its own label, not a `kind: "MCPServer"` property on a generic `Service` node.
- Every post-processor matches by label. `server/internal/analysis/processors/has_access_to.go:20` opens with `MATCH (s:MCPServer)`; the same pattern is in every other processor file. Switching to `MATCH (s:AIService {service_kind: "ollama"})` for AI services and keeping `MATCH (s:MCPServer)` for MCP servers introduces inconsistency without solving any problem the existing codebase has.
- UI dispatches on `kinds[0]` label in `server/ui/src/lib/node-styles.ts:9-14`, `server/ui/src/theme/tokens.ts:5-21`, and `server/ui/src/lib/explorer/hex-config.ts:37-150`. The hex-config map is keyed by Neo4j label. A property-based discriminator would force a runtime branch in UI code that today is a clean lookup.

The "schema simplicity" argument for a single `AIService` kind is correct in the abstract, but the existing codebase has already paid the per-label cost 12 times. Adding eight more labels keeps the codebase consistent; using a single `AIService` kind makes it inconsistent.

**Two viable options. Recommend option B.**

**Option A — per-service kinds only.**

Eight new labels: `OllamaInstance`, `VLLMInstance`, `QdrantInstance`, `MLflowServer`, `LiteLLMGateway`, `JupyterServer`, `LangServeApp`, `OpenWebUIInstance`. UI dispatches on the label, post-processors `MATCH (s:LiteLLMGateway)`. Schema grows by 8 labels + 8 constraints + N indexes. New services later require a schema change.

**Option B — per-service kinds + multi-label `:AIService` for unified queries (RECOMMENDED).**

Neo4j supports multiple labels per node natively. Every node we emit carries BOTH labels: `:OllamaInstance:AIService`, `:LiteLLMGateway:AIService`, etc. Best of both:

- Per-kind dispatch where it matters: UI hex-config, per-service post-processors, per-service riskscore weights — all key on the specific label.
- Unified queries: `MATCH (s:AIService) WHERE s.is_anonymous_loot = true RETURN s` works across every service kind. Credential-chain processor matches `(svc:AIService)-[:EXPOSES_CREDENTIAL]->(c:Credential)` without enumerating 8 labels in an OR.
- Schema growth: 8 per-kind labels + the umbrella `AIService` label. Same constraint count as Option A (constraints go on the per-kind label since `objectid` uniqueness is per-kind). One additional Neo4j label for the umbrella; no constraint or index needed on `:AIService` directly.
- Cypher consistency: post-processors that care about service kind still get the clean `MATCH (s:LiteLLMGateway)` syntax they would have under Option A. Generic processors get `MATCH (s:AIService)` instead of `MATCH (s) WHERE s:OllamaInstance OR s:VLLMInstance OR ...`.

**Recommendation: Option B.** It preserves the existing per-label dispatch convention AND gives the credential-chain processor a clean unified-query target. Multi-label nodes are a Neo4j-idiomatic pattern; the existing schema already uses single labels but the writer can emit multi-labels with no API changes (the writer's edge-kind-Cypher map can remain per-kind; node writes accept a `kinds[]` array).

**Concrete schema (Option B):**

```go
// sdk/ingest/kinds.go — additions
var AllowedNodeKinds = map[string]bool{
    // ... existing 12 ...
    "OllamaInstance":    true,  // NEW
    "VLLMInstance":      true,  // NEW
    "QdrantInstance":    true,  // NEW
    "MLflowServer":      true,  // NEW
    "LiteLLMGateway":    true,  // NEW
    "JupyterServer":     true,  // NEW
    "LangServeApp":      true,  // NEW
    "OpenWebUIInstance": true,  // NEW
    "AIService":         true,  // NEW — umbrella label, multi-label companion
    "AIModel":           true,  // NEW — for model artifacts surfaced via Looter
}

var AllNodeLabels = []string{
    // ... existing 14 ...
    "OllamaInstance", "VLLMInstance", "QdrantInstance", "MLflowServer",
    "LiteLLMGateway", "JupyterServer", "LangServeApp", "OpenWebUIInstance",
    "AIService", "AIModel",
}
```

Each emitted node carries `kinds: ["OllamaInstance", "AIService"]` (per-service first for primary dispatch, umbrella second). The writer `MERGE`s on the per-service label and applies both labels to the merged node.

Per-kind node properties (common to all `:AIService` nodes):

| Property | Example | Source |
|---|---|---|
| `endpoint` | `http://10.0.0.42:11434` | Scanner |
| `version` | `0.5.1` | Fingerprint rule extractor |
| `auth_method` | `none` / `apikey` / `oauth` / `token` / `basic` | Fingerprint rule heuristic |
| `is_anonymous_loot` | `true` (when fingerprinted as anonymously-readable) | Fingerprint rule emit |
| `tls` | `true` / `false` | Scanner (was the connection https) |
| `last_seen` | ISO 8601 | Standard edge property |

Per-kind ID: `SHA-256("<KindName>:" + endpoint)` — e.g. `SHA-256("OllamaInstance:http://10.0.0.42:11434")`.

### 3.6 New edges

Two new edge kinds:

| Edge | Source | Target | Meaning |
|---|---|---|---|
| `EXPOSES` | `AIService` | `AIService` (or other resource) | An AI service exposes another resource — e.g., `OpenWebUI EXPOSES Ollama` (UI → backend), `LiteLLM EXPOSES OpenAI-virtual-credential`. |
| `EXPOSES_CREDENTIAL` | `AIService` | `Credential` | An AI service holds a credential reachable through the service's API — produced by Looter, e.g., LiteLLM master key compromise yields N OpenAI keys. |

These compose with existing edges:
- `AIService RUNS_ON Host` — reuses existing `RUNS_ON`.
- `Credential` nodes use the existing `Credential` node kind.
- The credential-chain detector then fires `CAN_REACH AIService → AIService → Credential` paths.

### 3.7 Integration with the existing graph

The scanner is structurally a third collector source. The collector emits `IngestData` with `Meta.Collector = "scan"`, the same wire shape as `mcp` / `a2a` / `config`. The server's ingest pipeline (validate → normalize → deduplicate → write → post-process) handles it without changes — the only schema additions are the new node kind, edge kinds, and matcher version bump.

The post-processors gain a small new `cross_service_credential_chain` job that fires on the new edge shape:

```cypher
MATCH p = (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)
              -[:HAS_ENV_VAR]->(c1:Credential)
              <-[:EXPOSES_CREDENTIAL]-(svc:LiteLLMGateway)
              -[:EXPOSES_CREDENTIAL]->(c2:Credential)
WHERE c2.provider IN ["openai", "anthropic", "aws_bedrock"]
RETURN p
```

Note the per-kind label `:LiteLLMGateway` (Option B in §3.5). The same node also carries the `:AIService` umbrella label, so a more general processor that should fire for any service holding upstream credentials would `MATCH (svc:AIService)` instead.

This path — `Agent → MCPServer → Env-var-cred → LiteLLM Gateway → Provider key` — is the demo we want.

### 3.8 CLI surface

```bash
# Discover AI services on a CIDR.
agenthound scan 10.0.0.0/24

# Single host.
agenthound scan 10.0.0.42

# File of targets.
agenthound scan --targets-file hosts.txt

# Specific ports only.
agenthound scan 10.0.0.0/24 --ports 11434,8000,4000

# Specific service kinds only.
agenthound scan 10.0.0.0/24 --services ollama,litellm

# Output to stdout for pipeline.
agenthound scan 10.0.0.0/24 --output - | agenthound-server ingest -
```

How this composes with today's `agenthound scan --config --mcp --a2a`: cleanly, by promoting `scan` from "config + mcp + a2a" to "config + mcp + a2a + network". Today's flags (`--config`, `--mcp`, `--a2a`) keep working — they're now sub-flags of the broader `scan` verb. The new positional argument (CIDR/host) is the trigger for network mode. When no positional argument and no module flags are passed, the existing default behavior (config + mcp) holds.

Backwards-compatibility note: existing scripts running `agenthound scan` keep working. Existing scripts running `agenthound scan --config` keep working. The new mode is additive.

### 3.9 Code sketch — Scanner skeleton

The earlier draft of this section spawned `len(hosts) * len(ports)` goroutines eagerly. For a /16 × 8 ports = 524,288 goroutines at ~8 KiB each = ~4 GiB resident memory before any TCP connect happens — OOM on any operator laptop. Both verification reviewers flagged this as a ship-blocker. The corrected pattern is a **fixed-size worker pool consuming from a buffered task channel**: goroutine count is `O(workers)`, default 50, regardless of target count. The pool also cleanly handles `ctx.Done()` cancellation (each worker exits its receive loop) and panic isolation (each task is wrapped in `defer recover()`).

```go
// modules/networkscan/scanner.go
//
// Conforms to sdk/action.Scanner.
// Self-registers via modules/networkscan/register.go.

package networkscan

import (
    "context"
    "fmt"
    "log/slog"
    "net"
    "net/netip"
    "sync"
    "time"

    "github.com/adithyan-ak/agenthound/sdk/action"
)

type Scanner struct {
    ports           []int           // default ports for our 8 services
    workers         int             // fixed worker pool size (default 50)
    connectTimeout  time.Duration   // 3s
    cidrCap         int             // refuse > this many hosts
}

func NewScanner(opts ...Option) *Scanner {
    s := &Scanner{
        ports:          defaultPorts, // 11434, 8000, 4000, 6333, 5000, 8888, 8080
        workers:        50,
        connectTimeout: 3 * time.Second,
        cidrCap:        65536, // /16 v4 default
    }
    for _, o := range opts {
        o(s)
    }
    return s
}

// task is the unit a worker consumes — one (host, port) probe.
type task struct {
    host netip.Addr
    port int
}

// Scan implements sdk/action.Scanner.
func (s *Scanner) Scan(ctx context.Context, cidr string) ([]action.Target, error) {
    hosts, err := expandTargets(cidr, s.cidrCap)
    if err != nil {
        return nil, fmt.Errorf("expand %q: %w", cidr, err)
    }

    // Buffered task channel sized to the worker pool — backpressure if the
    // producer outruns the workers, no unbounded queue.
    tasks := make(chan task, s.workers*2)

    var (
        targets  []action.Target
        targetMu sync.Mutex
    )

    var wg sync.WaitGroup
    wg.Add(s.workers)

    // Worker pool — fixed goroutine count, regardless of target count.
    for i := 0; i < s.workers; i++ {
        go func() {
            defer wg.Done()
            // Panic isolation — a panic in probeOpen or a downstream
            // fingerprint match must NOT take down the process. Log and
            // continue; the worker stays alive for subsequent tasks.
            for t := range tasks {
                func(t task) {
                    defer func() {
                        if r := recover(); r != nil {
                            slog.Error("scan worker panic",
                                "host", t.host.String(),
                                "port", t.port,
                                "err", r)
                        }
                    }()
                    if !s.probeOpen(ctx, t.host, t.port) {
                        return
                    }
                    out := action.Target{
                        Kind:    "host",
                        Address: net.JoinHostPort(t.host.String(), fmt.Sprintf("%d", t.port)),
                        Meta: map[string]string{
                            "discovered_via":  "network_scan",
                            "candidate_kinds": candidateKindsForPort(t.port),
                        },
                    }
                    targetMu.Lock()
                    targets = append(targets, out)
                    targetMu.Unlock()
                }(t)
            }
        }()
    }

    // Producer — checks ctx BEFORE every send. On Ctrl-C, no new tasks
    // enter the channel; the workers drain what's already buffered and exit.
    producerLoop:
    for host := range hosts { // iterator, not slice
        for _, port := range s.ports {
            select {
            case tasks <- task{host: host, port: port}:
                // queued
            case <-ctx.Done():
                break producerLoop
            }
        }
    }
    close(tasks)
    wg.Wait()

    if err := ctx.Err(); err != nil {
        return targets, err // partial results + the cancellation cause
    }
    return targets, nil
}

func (s *Scanner) probeOpen(ctx context.Context, host netip.Addr, port int) bool {
    d := net.Dialer{Timeout: s.connectTimeout}
    conn, err := d.DialContext(ctx, "tcp",
        net.JoinHostPort(host.String(), fmt.Sprintf("%d", port)))
    if err != nil {
        return false
    }
    _ = conn.Close()
    return true
}

// expandTargets handles CIDR / host / file inputs and returns an iterator
// of netip.Addr. The cidrCap is the hard ceiling on number of hosts; >cap
// returns an error unless the caller passed --allow-large-cidr.
func expandTargets(input string, cap int) (<-chan netip.Addr, error) { /* ... */ }
```

Properties of this pattern:
- **Bounded memory.** `O(workers)` goroutines + `O(workers)` buffered tasks. A /16 scan uses the same memory as a /24 scan.
- **Cancellation-clean.** `ctx.Done()` checked before every `tasks <-` send. On Ctrl-C, the producer exits, `close(tasks)` lets workers drain, `wg.Wait()` returns, partial results returned with the cancellation error.
- **Panic-isolated.** Each task body is wrapped in a deferred `recover()` that logs and returns. A panic in a fingerprint match (e.g. a JSONPath extractor on a malformed body) does not crash the scan.

The `Scanner` returns `[]action.Target` per the existing interface in `sdk/action/scanner.go`. The CLI then drives a separate fingerprinting pass over those targets — see §5 for the proposed `Fingerprinter` shape.

---

## 4. LiteLLM Looter design

### 4.1 Why LiteLLM first

Three reasons, in priority order:

1. **Highest credential leverage.** LiteLLM is a multi-provider gateway. Compromising one master key yields every upstream key the gateway aggregates: OpenAI, Anthropic, AWS Bedrock, Azure, Cohere, Vertex, Mistral, Together, Replicate, DeepInfra, etc. No other AI infrastructure service offers a 10:1 credential leverage ratio in a single hop.
2. **Concrete demo for the credential chain pitch.** The CFP narrative is "we already detect the multi-hop CAN_REACH that traverses shared credentials." LiteLLM is the canonical example of a real-world credential aggregation point. A demo showing `Agent → trusts → MCPServer → has-env-var → LiteLLM master key → exposes → Anthropic prod key` is the slide that sells the talk.
3. **Most existing CVE diversity.** LiteLLM has accumulated more disclosed CVEs (SSRF, log-leak, supply-chain) than any other AI gateway in the same period — the security research community already has eyes on it. Our findings dovetail with existing research.

### 4.2 Discovery flow

```
agenthound scan 10.0.0.0/24
  → port 4000 open on 10.0.0.42
  → fingerprinter dispatches GET /health/liveliness
  → response body equals literal "I'm alive!"
  → LiteLLMGateway node emitted (multi-labeled :LiteLLMGateway:AIService),
    endpoint=http://10.0.0.42:4000

[operator obtains master key out-of-band — phishing, env-leak, git history,
 instruction-file poisoning detection from existing AgentHound]

agenthound loot 10.0.0.42 --type litellm --master-key sk-...
  → LiteLLM Looter authenticates with master key
  → enumerates /key/list, /model/info, /user/list
  → emits Credential nodes + EXPOSES_CREDENTIAL edges
```

### 4.3 Loot endpoints

When the operator supplies the master key, the Looter probes (in this order, lowest-privilege first):

| Path | Method | Loot |
|---|---|---|
| `GET /health/liveliness` | GET | Liveness — confirms reachability before authenticating. |
| `GET /v1/models` | GET | Model list (auth typically required, sometimes anonymous). |
| `GET /model/info` | GET | **Full configured-model list.** Returns each model's `litellm_params` — `api_base`, `api_key` (often a reference to an env var), `model` name. The credential leak surface. |
| `GET /key/list?page=1&page_size=100` | GET | All virtual keys, paginated. Each entry: `{"key": "sk-...", "spend": ..., "models": [...], "user_id": ..., "team_id": ..., "created_at": ...}`. |
| `GET /user/list` | GET | Users. Maps virtual keys to people. |
| `GET /team/list` | GET | Teams. |
| `GET /spend/keys?startTime=...&endTime=...` | GET | Spend audit. Surfaces high-volume keys (high-value targets). |

The Looter does NOT call `POST /chat/completions` or any endpoint that consumes provider credits — that would be both noisy and an actual attack on the upstream provider, beyond the read-only loot scope.

### 4.4 Output format — concrete `LootResult` schema

This is the first concrete usage of the v0 `LootResult` stub in `sdk/action/looter.go`. Proposed shape:

```go
// sdk/action/looter.go — concrete shape (to land with first Looter impl)

// LootOptions carries Looter-specific options.
type LootOptions struct {
    // Per-module credentials. The CLI translates --master-key, --token,
    // etc. into entries in this map keyed by a module-defined key name.
    Credentials map[string]string

    // Paging cap to bound runaway extraction.
    MaxItems int

    // Per-Looter timeout (overrides ctx if smaller).
    Timeout time.Duration

    // IncludeCredentialValues opts into raw credential value capture for
    // audit-mode runs. Default false — credentials are stored as SHA-256
    // hashes only. Field name matches the existing Config Collector
    // convention (--include-credential-values flag).
    IncludeCredentialValues bool
}

// LootResult is the output of Looter.Loot. Carries an ingest patch directly
// so loot folds into the same pipeline as enumeration.
type LootResult struct {
    // The graph patch produced by the loot operation.
    IngestData *ingest.IngestData

    // Loot-level errors (not returned by Loot itself — this captures
    // partial failures, e.g. "got the keys but couldn't reach /user/list").
    PartialErrors []string

    // Provenance — informational summary for CLI display.
    Summary LootSummary
}

type LootSummary struct {
    NodesEmitted     int
    EdgesEmitted     int
    CredentialsFound int
    Endpoints        []string // which endpoints were hit
}

// ToIngest is the contract the server-side ingest CLI expects.
func (r *LootResult) ToIngest() *ingest.IngestData { return r.IngestData }
```

### 4.5 Output — node and edge emissions

For each LiteLLM master-key loot, the Looter emits:

| Node | Properties | Source |
|---|---|---|
| `LiteLLMGateway` (multi-labeled `:LiteLLMGateway:AIService`, already in graph from scan) | `endpoint`, `version`, `auth_method=master_key`, `docs_enabled` | Refresh from loot session |
| `Credential` × N | `type=apiKey`, `name=upstream-<provider>`, `provider=openai\|anthropic\|aws_bedrock\|...`, `is_exposed=true`, `source=litellm`, `evidence_ref=model_info_response_<idx>` | One per upstream provider key found in `/model/info` |
| `Credential` × N | `type=virtual_key`, `name=<virtual_key_id>`, `is_exposed=true`, `source=litellm`, `spend_usd=...`, `models=[...]` | One per entry in `/key/list` |

Edges:

| Edge | Source | Target | Properties |
|---|---|---|---|
| `EXPOSES_CREDENTIAL` | LiteLLM `AIService` | upstream `Credential` | `confidence=1.0`, `evidence={"endpoint":"/model/info","model":"..."}`, `risk_weight=0.1` |
| `EXPOSES_CREDENTIAL` | LiteLLM `AIService` | virtual_key `Credential` | `confidence=1.0`, `evidence={"endpoint":"/key/list"}`, `risk_weight=0.2` |

**Important:** Credential values are NOT stored in the graph by default — only the existence and metadata. The `--include-credential-values` flag (existing convention from Config Collector) opts into raw value capture for audit-mode runs. By default we hash the value and store the hash. This matches the existing safety convention in CLAUDE.md item 9.

### 4.6 CLI surface

```bash
# Loot an already-discovered LiteLLM gateway.
agenthound loot 10.0.0.42 --type litellm --master-key sk-CHANGE_ME

# Multiple master keys via env file.
agenthound loot 10.0.0.42 --type litellm --master-key-env-file keys.env

# Constrain output.
agenthound loot 10.0.0.42 --type litellm --master-key sk-... --max-items 100

# Pipe to server.
agenthound loot 10.0.0.42 --type litellm --master-key sk-... --output - | \
  agenthound-server ingest -
```

The `--master-key` flag is module-specific. It binds via the proposed `Module.Flags()` extension (see §5). Convention: `--<credential-name>` flags are module-scoped — Ollama's looter would use `--auth-token` (none today, future); Jupyter's would use `--token`; Open WebUI's would use `--admin-cookie`.

**Ergonomic alternative** (for the v0 implementation, before `Module.Flags()` lands): the CLI accepts a generic `--credential KEY=VALUE` flag and the module reads `Credentials[KEY]` from `LootOptions`. So `--credential master_key=sk-...` works without per-module flag registration. This is uglier but avoids the SDK extension blocking the first concrete Looter.

### 4.7 Reverter contract

Looting is read-only by design. The first concrete Looter does NOT compose `Reverter`. The `Looter` interface in `sdk/action/looter.go` is correctly minimal — `Reverter` only composes into `Poisoner` and `Implanter`.

For documentation: the LiteLLM Looter must NOT call any state-modifying endpoint:
- ❌ `POST /key/generate` (creates a virtual key — observable side effect)
- ❌ `POST /key/delete` (modifies state)
- ❌ `POST /config/update` (modifies state)
- ❌ `POST /chat/completions` (consumes upstream provider credits — modifies third-party state)

The Looter test suite must include a regression test that asserts only GET methods are issued during a loot session.

### 4.8 Code sketch — LiteLLM Looter skeleton

The earlier draft of this sketch had several CI-failing or interface-violating issues — missing imports for `bytes` and `strings`, ignored `error` returns from `http.NewRequestWithContext` (errcheck-fail), references to a non-existent `LootOptions.IncludeValues` field, a `Name()` method that does not exist on `sdk/module.Module`, missing `Description()` and `Version()` methods that DO exist on the interface, and a comment that promised partial-error recording but didn't actually populate `LootResult.PartialErrors`. The corrected sketch:

```go
// modules/litellmloot/looter.go
//
// Conforms to sdk/action.Looter and sdk/module.Module.
// Self-registers via modules/litellmloot/register.go.

package litellmloot

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log/slog"
    "net/http"
    "strings"
    "time"

    "github.com/adithyan-ak/agenthound/sdk/action"
    "github.com/adithyan-ak/agenthound/sdk/common"
    "github.com/adithyan-ak/agenthound/sdk/ingest"
)

type Looter struct {
    httpClient *http.Client
    timeout    time.Duration
}

func NewLooter(opts ...Option) *Looter {
    return &Looter{
        httpClient: &http.Client{Timeout: 30 * time.Second},
        timeout:    60 * time.Second,
    }
}

// Loot implements sdk/action.Looter.
func (l *Looter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
    masterKey := opts.Credentials["master_key"]
    if masterKey == "" {
        return nil, fmt.Errorf("litellm loot: master_key credential required")
    }

    // Redact the master key in any log line — never log the full value.
    // First 8 chars + "..." is enough for an operator to identify which
    // key was used, without logging anything an attacker tailing the
    // process logs could replay.
    redactedKey := redact(masterKey)
    slog.Info("litellm loot starting",
        "target", t.Address,
        "key_prefix", redactedKey)

    base := t.Address
    if !strings.HasPrefix(base, "http") {
        base = "http://" + base
    }

    var partialErrors []string

    // 1. Liveness check — fail fast if the gateway is unreachable.
    if err := l.probeLiveness(ctx, base); err != nil {
        return nil, fmt.Errorf("liveness: %w", err)
    }

    // 2. Master-key auth probe via /model/info.
    modelInfo, err := l.getModelInfo(ctx, base, masterKey)
    if err != nil {
        return nil, fmt.Errorf("model/info: %w", err)
    }

    // 3. Enumerate virtual keys. Non-fatal — partial results are valuable.
    keyList, err := l.getKeyList(ctx, base, masterKey, opts.MaxItems)
    if err != nil {
        slog.Warn("litellm loot: key/list partial failure",
            "target", t.Address,
            "key_prefix", redactedKey,
            "err", err)
        partialErrors = append(partialErrors,
            fmt.Sprintf("key/list: %v", err))
        keyList = &KeyListResponse{} // empty, not nil — avoid downstream nil deref
    }

    // 4. Build the ingest patch.
    scanID := common.GenerateScanID("litellm-loot")
    data := common.NewIngestData("scan", scanID)

    aiServiceID := ingest.ComputeNodeID("LiteLLMGateway", base)

    // Emit Credential nodes per upstream provider.
    for _, m := range modelInfo.Data {
        cred := buildUpstreamCredential(aiServiceID, m, opts.IncludeCredentialValues)
        data.Graph.Nodes = append(data.Graph.Nodes, cred)
        data.Graph.Edges = append(data.Graph.Edges, ingest.Edge{
            Source: aiServiceID,
            Target: cred.ID,
            Kind:   "EXPOSES_CREDENTIAL",
            Properties: map[string]any{
                "scan_id":      scanID,
                "evidence":     map[string]string{"endpoint": "/model/info", "model": m.ModelName},
                "confidence":   1.0,
                "risk_weight":  0.1,
                "is_composite": false,
            },
        })
    }

    // Emit Credential nodes per virtual key.
    for _, k := range keyList.Keys {
        cred := buildVirtualKeyCredential(aiServiceID, k, opts.IncludeCredentialValues)
        data.Graph.Nodes = append(data.Graph.Nodes, cred)
        data.Graph.Edges = append(data.Graph.Edges, ingest.Edge{
            Source: aiServiceID,
            Target: cred.ID,
            Kind:   "EXPOSES_CREDENTIAL",
            Properties: map[string]any{
                "scan_id":      scanID,
                "evidence":     map[string]string{"endpoint": "/key/list"},
                "confidence":   1.0,
                "risk_weight":  0.2,
                "is_composite": false,
            },
        })
    }

    return &action.LootResult{
        IngestData:    data,
        PartialErrors: partialErrors,
        Summary: action.LootSummary{
            NodesEmitted:     len(data.Graph.Nodes),
            EdgesEmitted:     len(data.Graph.Edges),
            CredentialsFound: len(data.Graph.Nodes), // every node is a Credential here
            Endpoints:        []string{"/health/liveliness", "/model/info", "/key/list"},
        },
    }, nil
}

// HTTP helpers — all GET, all bounded, all error-checked.

func (l *Looter) probeLiveness(ctx context.Context, base string) error {
    req, err := http.NewRequestWithContext(ctx, "GET", base+"/health/liveliness", nil)
    if err != nil {
        return fmt.Errorf("build liveness request: %w", err)
    }
    resp, err := l.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
    if err != nil {
        return fmt.Errorf("read liveness body: %w", err)
    }
    if !bytes.Contains(body, []byte("I'm alive")) {
        return fmt.Errorf("not a litellm liveness response: %q", body)
    }
    return nil
}

func (l *Looter) getModelInfo(ctx context.Context, base, masterKey string) (*ModelInfoResponse, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", base+"/model/info", nil)
    if err != nil {
        return nil, fmt.Errorf("build model/info request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+masterKey)
    resp, err := l.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("model/info: status %d", resp.StatusCode)
    }
    var out ModelInfoResponse
    if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024*1024)).Decode(&out); err != nil {
        return nil, fmt.Errorf("decode model/info: %w", err)
    }
    return &out, nil
}

// ... getKeyList, buildUpstreamCredential, buildVirtualKeyCredential omitted for brevity ...

// redact returns the first 8 characters of s plus "..." — safe to log.
// Asserts in tests that no log line ever contains the full master key.
func redact(s string) string {
    if len(s) <= 8 {
        return "***"
    }
    return s[:8] + "..."
}

// Module interface methods — match sdk/module/module.go EXACTLY.
// (No Name() — Description() serves the human-readable purpose.)
func (l *Looter) ID() string            { return "litellm.loot" }
func (l *Looter) Action() action.Action { return action.Loot }
func (l *Looter) Target() string        { return "litellm" }
func (l *Looter) Description() string   { return "LiteLLM master-key Looter — extracts upstream provider keys and virtual keys" }
func (l *Looter) Version() string       { return "0.1.0" }
func (l *Looter) IsDestructive() bool   { return false }
```

The skeleton is ~150 LOC including comments. The full implementation lands at ~250 LOC for the Looter plus ~150 LOC for the ingest helpers and ~250 LOC for tests (the test budget grows because of the GET-only assertion + the master-key-redaction assertion).

**Mandatory unit test — credential redaction in logs.** The Looter test suite must assert that NO `slog` output contains the full master key. The pattern:

```go
// modules/litellmloot/looter_redaction_test.go
func TestMasterKeyNeverLoggedRaw(t *testing.T) {
    var buf bytes.Buffer
    handler := slog.NewJSONHandler(&buf, nil)
    prevDefault := slog.Default()
    slog.SetDefault(slog.New(handler))
    defer slog.SetDefault(prevDefault)

    masterKey := "sk-supersecretmastervalue-do-not-log-12345"
    looter := NewLooter()
    // ... run loot against a stub server with masterKey ...

    if strings.Contains(buf.String(), masterKey) {
        t.Fatalf("master key leaked in logs: %s", buf.String())
    }
    // The redacted prefix MAY appear; the full key MUST NOT.
}
```

---

## 5. SDK shape evolution

Building the network scanner + LiteLLM Looter exposes the right shape for several SDK stubs that today are empty structs. The proposals below are **not for this sprint to land** — the sprint ships against the existing stubs. The proposals are recorded so when the sprint lands and we have consumer feedback, the SDK changes are straightforward.

### 5.1 `Scanner.Scan()` return shape

Today: `Scan(ctx, cidr) ([]Target, error)`.

After v0.2: keep the signature. The flat `Target` shape (Kind, Address, Meta) is sufficient for the network scanner. The `Meta` map carries discovery hints: `discovered_via=network_scan`, `candidate_kinds=ollama,vllm` (the fingerprinters to dispatch).

The `target.go` doc comment already says typed sub-structs may land in v1. After the network scanner, my recommendation is to **keep `Target` flat**. The cost of typed sub-structs (HostTarget, ConfigTarget, URLTarget, etc.) is type-switch boilerplate at every consumer site; the benefit is small when the discriminator field already does the routing. Defer typed sub-structs until at least three consumers each have non-trivial Meta payloads that would be cleaner as typed fields.

### 5.2 `Fingerprinter.Fingerprint()` return shape

Today: `Fingerprint(ctx, t) (*FingerprintResult, error)` where `FingerprintResult struct{}`.

Proposed concrete shape:

```go
type FingerprintResult struct {
    // Empty when no fingerprinter matched. Caller should check Matched.
    Matched bool

    // Service identification — populated when Matched is true.
    ServiceKind string  // "ollama", "vllm", etc.
    Version     string  // extracted version string, may be ""
    AuthMethod  string  // "none", "apikey", "token", "basic", "oauth"

    // Probe evidence — what HTTP requests were made and what came back.
    // Used by the rules engine for explainability.
    Evidence []ProbeEvidence

    // The graph patch this fingerprint contributes.
    IngestData *ingest.IngestData
}

type ProbeEvidence struct {
    Path       string
    StatusCode int
    Snippet    string  // first 256 bytes of body, redacted
    MatchedRule string // rule ID that fired
}
```

This shape is small enough that the migration from `struct{}` is safe.

### 5.3 `Looter.Loot()` return shape

Already specified in §4.4. Keys: `IngestData *ingest.IngestData`, `PartialErrors []string`, `Summary LootSummary`. The `ToIngest() *ingest.IngestData` method satisfies the contract anticipated in the existing doc comment.

### 5.4 Module-level CLI flags — sidecar interface (NOT a breaking change)

Today: each module bakes its CLI flags into the cobra command in `collector/cli/`. Adding a new module means editing `collector/cli/scan.go`. That works for three modules; it does not scale.

The earlier draft of this section proposed adding `Flags() *pflag.FlagSet` and `Name() string` directly onto the existing `Module` interface, while silently dropping `Description()` and `Version()`. That is a **breaking change** to a load-bearing interface (`Description()` and `Version()` are consumed by registry consumers and module-listing CLI output) and was correctly flagged by both verification reviewers as a non-starter.

The idiomatic Go answer is a **sidecar (optional companion) interface**. Existing modules don't break; new modules opt in via a type assertion at the dispatch site.

```go
// sdk/module/module.go — UNCHANGED. Description() and Version() stay.
type Module interface {
    ID() string            // dotted lowercase, e.g. "mcp.enumerate"
    Action() action.Action // which action this module performs
    Target() string        // service kind targeted, e.g. "mcp", "a2a", "config"
    Description() string   // one-line human-readable summary
    Version() string       // semver of the module
    IsDestructive() bool   // v0 binary; refined at v1 if needed
}

// sdk/module/flags.go (new file).
//
// FlagsModule is an OPTIONAL companion interface. Modules may implement it
// to declare per-module CLI flags. The CLI dispatches via type assertion:
//
//   if fm, ok := m.(FlagsModule); ok {
//       cmd.Flags().AddFlagSet(fm.Flags())
//   }
//
// This is additive — existing modules don't break. New modules opt in.
type FlagsModule interface {
    Module
    Flags() *pflag.FlagSet
}
```

The CLI registers the union of all participating modules' flag sets at command-init time, prefixed with the module ID to avoid collisions (`--ollama.token`, `--litellm.master-key`). Cobra supports this directly via `cmd.Flags().AddFlagSet()`.

The LiteLLM Looter sketch (§4.8) does NOT need to implement `FlagsModule` for v0.2 — the interim generic `--credential KEY=VALUE` flag (see §4.6) covers the first consumer without touching the SDK. Land `FlagsModule` when the second concrete Looter ships and we have two consumers to validate the shape against. Drop the `Name()` proposal entirely — `Description()` already serves the human-readable purpose, and adding `Name()` would be redundant.

### 5.5 State directory for future Reverter persistence — sidecar interface

When a future `Poisoner` or `Implanter` ships, the `Reverter` it composes will need persistent state — the receipt of what was done, where, when, by whom. Today there's no convention.

Same pattern as §5.4 — sidecar interface, additive, no break to existing `Module`:

```go
// sdk/module/state.go (new file)
//
// StatefulModule is an OPTIONAL companion interface. Modules that persist
// state across runs implement it. The CLI / API server dispatches via type
// assertion when it needs to inspect or roll up state:
//
//   if sm, ok := m.(StatefulModule); ok {
//       dir := sm.StateDir()
//       // ... use dir ...
//   }
//
// StateDir returns the canonical per-module state directory:
//
//   $XDG_STATE_HOME/agenthound/<module-id>/
//
// Defaults to $HOME/.local/state/agenthound/<module-id>/ when
// XDG_STATE_HOME is unset. Caller is responsible for creation; this
// function only returns the path.
type StatefulModule interface {
    Module
    StateDir() string
}
```

State directory is created on first use, contains:
- `receipts.jsonl` — append-only log of action receipts.
- `<receipt-id>.json` — per-action evidence file.

Add this when the first `Poisoner` lands — premature for v0.2, but recording the convention here so the future implementer doesn't reinvent.

---

## 6. New ingest schema additions

This sprint introduces (per the Option B multi-label decision in §3.5):

**Ten new node kinds:**

| Kind | Multi-label companion | Properties | Used by |
|---|---|---|---|
| `OllamaInstance` | `:AIService` | `endpoint`, `version`, `auth_method`, `is_anonymous_loot`, `tls` | Ollama fingerprinter, future Ollama looter |
| `VLLMInstance` | `:AIService` | same + `vllm_metrics_exposed` | vLLM fingerprinter |
| `QdrantInstance` | `:AIService` | same + `collection_count` | Qdrant fingerprinter |
| `MLflowServer` | `:AIService` | same + `experiment_count` | MLflow fingerprinter |
| `LiteLLMGateway` | `:AIService` | same + `docs_enabled` | LiteLLM fingerprinter, LiteLLM looter |
| `JupyterServer` | `:AIService` | same + `token_required` | Jupyter fingerprinter |
| `LangServeApp` | `:AIService` | same + `chains` | LangServe fingerprinter |
| `OpenWebUIInstance` | `:AIService` | same + `webui_auth_enabled` | Open WebUI fingerprinter |
| `AIService` | (umbrella label only) | union of common fields | Generic post-processors that span all AI services |
| `AIModel` | none | `name`, `service_id`, `digest`, `family`, `parameters`, `is_finetune` | Future Ollama/MLflow looters (not v0.2; reserved here) |

`AIModel` is included in this PR's schema additions even though no v0.2 Looter emits it, because adding it later requires a schema migration. Adding it now while we're modifying the schema costs nothing.

Every emitted AI-service node carries both labels: e.g. an Ollama node has `kinds: ["OllamaInstance", "AIService"]`. Per-kind label first for primary dispatch (UI hex-config keys on `kinds[0]`); umbrella label second so unified queries can match `(s:AIService)`.

**Two new edge kinds:**

| Edge | Source | Target | Direction meaning |
|---|---|---|---|
| `EXPOSES` | `:AIService` | `:AIService` | One service exposes another (Open WebUI → Ollama, LiteLLM → upstream provider service) |
| `EXPOSES_CREDENTIAL` | `:AIService` | `Credential` | Service holds a credential reachable through its API |

Edge endpoint validation uses the `:AIService` umbrella label so any per-kind node can sit at either end. The post-processor that fires on these edges does not need to enumerate the 8 per-kind labels.

**Schema diff to `sdk/ingest/kinds.go`:**

```go
// AllowedNodeKinds — additions
"AIService": true,
"AIModel":   true,

// AllNodeLabels — additions
"AIService", "AIModel",

// AllowedEdgeKinds — additions
"EXPOSES":             true,
"EXPOSES_CREDENTIAL":  true,

// RawEdgeKinds — additions (REQUIRED — see "Validator update" below).
// EXPOSES and EXPOSES_CREDENTIAL ARE collector-emitted (by the scanner and
// the looter), so they semantically belong in RawEdgeKinds alongside the
// existing 13 raw collector edges.
"EXPOSES":             true,
"EXPOSES_CREDENTIAL":  true,

// AllowedCollectors — addition (conditional)
// "scan" is already in the allowlist, so no change needed.

// EdgeKindEndpoints — additions
"EXPOSES":            {SourceKinds: []string{"AIService"}, TargetKinds: []string{"AIService"}},
"EXPOSES_CREDENTIAL": {SourceKinds: []string{"AIService"}, TargetKinds: []string{"Credential"}},
```

**Validator update (`server/internal/ingest/validator.go:80`) — SHIP-BLOCKER if missed.**

The current ingest validator at `server/internal/ingest/validator.go:80` checks `ingest.RawEdgeKinds[edge.Kind]`, **not** `ingest.AllowedEdgeKinds`. This means any edge kind we add only to `AllowedEdgeKinds` (the broader 21-kind dispatch map) will be **rejected at ingest time** with `invalid edge kind "EXPOSES_CREDENTIAL"`. Without a validator change, every Looter ingest fails before reaching the writer.

Two ways to fix this; pick (a):

- **(a) Recommended — extend `RawEdgeKinds` to include the new collector-emitted edges.** This is structurally consistent with the existing test `TestRawEdgeKindsSubsetOfAllowed` at `sdk/ingest/model_test.go:117` (which asserts `RawEdgeKinds ⊆ AllowedEdgeKinds`). Update both maps; update the test count assertion in `TestAllowedEdgeKindsComplete` (currently `len() == 21`; bumps to 23).
- (b) Alternative — change the validator to allow any kind in `AllowedEdgeKinds` for `collector="scan"`. Cleaner *if* we wanted `RawEdgeKinds` to remain "the 13 historical kinds." But that taxonomy is not load-bearing in any other consumer of `RawEdgeKinds` (the only consumer is this validator), so option (a) is simpler.

Required edits:
- `sdk/ingest/kinds.go` — add `EXPOSES` and `EXPOSES_CREDENTIAL` to BOTH `AllowedEdgeKinds` and `RawEdgeKinds`.
- `sdk/ingest/model_test.go:112` — bump `if len(AllowedEdgeKinds) != 21` to `23`.
- `sdk/ingest/model_test.go:117` — `TestRawEdgeKindsSubsetOfAllowed` continues to pass automatically since we add to both maps.
- New test in `sdk/ingest/model_test.go` — assert `EXPOSES` and `EXPOSES_CREDENTIAL` are present in BOTH maps (regression guard against future drift).

**Neo4j schema additions** (constraints + indexes — version-detected `ON ASSERT` vs `FOR REQUIRE`). Constraints go on the per-kind labels because `objectid` uniqueness is per-kind (an Ollama node and a vLLM node could in principle share an endpoint string; the SHA-256 ID prefixed with the kind name disambiguates them). The umbrella `:AIService` label gets indexes only, no uniqueness constraint.

```cypher
-- Neo4j 4.4 syntax — per-kind constraints
CREATE CONSTRAINT IF NOT EXISTS ON (n:OllamaInstance)    ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS ON (n:VLLMInstance)      ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS ON (n:QdrantInstance)    ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS ON (n:MLflowServer)      ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS ON (n:LiteLLMGateway)    ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS ON (n:JupyterServer)     ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS ON (n:LangServeApp)      ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS ON (n:OpenWebUIInstance) ASSERT n.objectid IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS ON (n:AIModel)           ASSERT n.objectid IS UNIQUE;

-- Indexes on the umbrella label for unified-query post-processors.
CREATE INDEX IF NOT EXISTS FOR (n:AIService) ON (n.is_anonymous_loot);
CREATE INDEX IF NOT EXISTS FOR (n:AIService) ON (n.endpoint);

-- Neo4j 5.x syntax — same content with FOR/REQUIRE.
CREATE CONSTRAINT FOR (n:OllamaInstance)    REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:VLLMInstance)      REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:QdrantInstance)    REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:MLflowServer)      REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:LiteLLMGateway)    REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:JupyterServer)     REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:LangServeApp)      REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:OpenWebUIInstance) REQUIRE n.objectid IS UNIQUE;
CREATE CONSTRAINT FOR (n:AIModel)           REQUIRE n.objectid IS UNIQUE;
CREATE INDEX FOR (n:AIService) ON (n.is_anonymous_loot);
CREATE INDEX FOR (n:AIService) ON (n.endpoint);
```

These statements live in `server/internal/graph/schema.go:13-24` (the existing schema-init helper). The version-detection path that decides between `ON...ASSERT` and `FOR...REQUIRE` already exists; we just add to the per-version Cypher block lists.

**Post-processor wiring (`server/internal/analysis/registry.go:5`)** — the new `cross_service_credential_chain` processor (described in §3.7) must be registered in the `allProcessors()` slice. Verified location: `server/internal/analysis/registry.go:5` (NOT `postprocessor.go` — `postprocessor.go` holds the runner; the slice lives in `registry.go`). Concrete edits:

- Create `server/internal/analysis/processors/cross_service_credential_chain.go` implementing `Name() string` (returns `"cross_service_credential_chain"`), `Dependencies() []string` (returns `[]string{"has_access_to"}`; the chain reads `EXPOSES_CREDENTIAL` edges plus existing `HAS_ACCESS_TO` paths), and `Process(ctx, db, scanID) (ProcessingStats, error)`.
- Edit `server/internal/analysis/registry.go:6-17` to append `&processors.CrossServiceCredentialChain{}` to the slice. Add it after `&processors.CanReach{}` (line 12) since the chain depends on `CanReach`-derived state and must run after it.
- Add a smoke test in `server/internal/analysis/processors/cross_service_credential_chain_test.go`: build a synthetic graph with `(:AgentInstance)-[:HAS_ENV_VAR]->(:Credential)<-[:EXPOSES_CREDENTIAL]-(:LiteLLMGateway:AIService)-[:EXPOSES_CREDENTIAL]->(:Credential {provider:"openai"})`, run the processor, assert it emits the expected `CAN_REACH`-style edge from the agent to the upstream credential.
- The dependency order check in `validateDependencyOrder` (`server/internal/analysis/registry.go` is exported by `postprocessor.go`) will fail-fast if dependencies are wrong.

**UI integration scope.** The CLAUDE.md "Node Visual Encoding" reference in earlier drafts is misleading: CLAUDE.md is stale (it cites `Sigma+graphology` but the actual UI stack per `server/ui/package.json:26,29` is React Flow + ELK). The actual UI files that change for this milestone are:

| File | Change |
|---|---|
| `server/ui/src/theme/tokens.ts` | Add 8 entries to the `NODE_KIND_COLORS` map, keyed by per-kind label (`OllamaInstance`, `VLLMInstance`, etc.) |
| `server/ui/src/lib/explorer/hex-config.ts` (lines 37-150) | Add 8 entries to `HEX_CONFIG`, keyed by per-kind label, each with `strokeColor`, `fillColor`, `icon` (from `lucide-react`), `kindTag`, `column`, `groupLabel`. Suggest column 2 ("Tools & Skills") for the AI services since they sit between agents/servers and resources/credentials |
| `server/ui/src/lib/explorer/layout.ts` | Update the partition column logic if needed — likely a no-op if all 8 fall into an existing column |
| `server/ui/src/lib/node-styles.ts` | Update the size switch — `AIService` (umbrella) size scales with the number of `EXPOSES_CREDENTIAL` edges out (high-leverage gateways stand out). The size dispatch can match on the umbrella label |

Color and icon proposals (per-kind label dispatch in the UI):

| Per-kind label | Color (hex) | lucide-react icon |
|---|---|---|
| `OllamaInstance` | `#FF7043` orange-red | `Sparkles` (placeholder; revise to a llama if available) |
| `VLLMInstance` | `#26A69A` teal | `Rocket` |
| `QdrantInstance` | `#5C6BC0` indigo | `Database` |
| `MLflowServer` | `#42A5F5` blue | `FlaskConical` |
| `LiteLLMGateway` | `#EC407A` pink | `GitFork` (gateway/funnel) |
| `JupyterServer` | `#FF9800` orange | `Notebook` |
| `LangServeApp` | `#7E57C2` purple | `Link2` |
| `OpenWebUIInstance` | `#66BB6A` green | `MessageSquare` |

A separate (out-of-scope for this sprint) follow-up should update CLAUDE.md to reflect the actual frontend stack — that doc claims Sigma+graphology, but `server/ui/package.json:26,29` shows the production stack is React Flow + ELK. Track this as a docs-fix task.

---

## 7. Phased roadmap

**Important: these estimates are 1.5–2.5× optimistic per two independent verification reviews.** The phase-by-phase numbers below show "original (optimistic)" and "realistic" ranges. The realistic total for one full-time engineer is **18–30 weeks (~4.5–7 months)**, not the 8–12 weeks the original draft implied. Re-plan accordingly. The CFP/conference strategy in §8 has been updated to reflect this — DEF CON 34 main-stage is no longer the v0.2 target.

Effort estimates assume one engineer at full focus. Adjust for context-switching, on-call interruptions, and the inevitable rabbit holes that emerge in week 3 of every phase.

### Phase 0 — Design review (week 0, 2026-04-23 → 2026-04-29)
- **Deliverable:** This document, reviewed and approved.
- **Acceptance:** User accepts the multi-label schema decision (§3.5 Option B), the LiteLLM-first prioritization, the CFP target list (DEF CON Demo Labs + BSidesLV; not DEF CON main-stage), the validator update (§6 ship-blocker), and the realistic effort estimates below.
- **Owner:** TBD (likely Adithyan AK with architect feedback loop).
- **Risk:** Schema decision (multi-label) gets pushed back to single `AIService` kind; rework is significant. Mitigation: §3.5 presents both sides; if the user reverses to single-kind, every per-kind processor query rewrites to property predicates, every UI hex-config entry consolidates into a single entry with runtime dispatch, every Neo4j constraint consolidates into one. Mechanical but tedious — ~2 days of cleanup.

### Phase 1 — Scanner skeleton (weeks 1–2, 2026-04-29 → 2026-05-13; **realistic 2–3 weeks**)
- **Deliverables:**
  - `modules/networkscan/scanner.go` — CIDR/host expansion + bounded port sweep.
  - `expandTargets` for IPv4 + IPv6, handles /N CIDRs, single hosts, file-of-hosts, DNS names.
  - CIDR cap enforcement (`--allow-large-cidr` flag).
  - Public-IP guard (`--allow-public-targets` flag).
  - Returns `[]action.Target` with Meta populated. **No fingerprinting in this phase** — Meta carries `candidate_kinds` only.
  - Unit tests for expansion (CIDR sizes, IPv6, edge cases like /32, /31, /128).
  - Unit tests for the public/private classification (reuses `sdk/common/host.go`).
- **Acceptance criteria:**
  - `agenthound scan 10.0.0.0/30` returns 4 targets.
  - `agenthound scan 10.0.0.0/16 --allow-large-cidr=false` errors with the cap explanation.
  - `agenthound scan 1.1.1.1` errors without `--allow-public-targets`.
  - Race-detector-clean tests.
- **Risk:** IPv6 expansion has many edge cases (link-local, unique-local, multicast). Mitigation: refuse multicast and link-local entirely; document the policy.

### Phase 2 — Rules engine v2 + first Fingerprinter: Ollama (weeks 2–3 optimistic; **realistic 4–5 weeks** — the rules-engine extension is architecturally significant)
- **Deliverables:**
  - `sdk/rules/MatcherSpec.Version: 2` extension landed (`http_status`, `http_header`, `json_path` matchers).
  - `rules/builtin/fingerprints/ollama.yaml` shipped.
  - `modules/ollamafp/fingerprinter.go` implementing `sdk/action.Fingerprinter`.
  - Integration test: a stub HTTP server emitting `{"version":"0.5.1"}` is correctly fingerprinted.
  - The CLI dispatcher: `agenthound scan 10.0.0.42` → port sweep → fingerprint dispatch → emit `AIService` node.
  - New `AIService` node kind landed in `sdk/ingest/kinds.go` + Neo4j schema migration + UI rendering.
- **Acceptance criteria:**
  - `agenthound scan <stub-host>` produces ingest JSON containing one node with `kinds: ["OllamaInstance", "AIService"]` (multi-label per §3.5 Option B), `version=0.5.1`.
  - The server ingests the JSON with no validation errors.
  - The UI displays the new node with the orange-red Ollama color.
- **Risk:** Rules-engine extension is the architecturally significant piece. Mitigation: land the `Version: 2` boundary as a separate PR; fingerprint rule depends on it.

### Phase 3 — REVISED: deferred to v0.3. (Was: more Fingerprinters in weeks 3–4. Per the §9.8 scope-creep correction, vLLM / Open WebUI / Jupyter fingerprinters slip to v0.3.)
- **Deliverables:**
  - `rules/builtin/fingerprints/{vllm,openwebui,jupyter}.yaml`.
  - `modules/{vllmfp,openwebuifp,jupyterfp}/` — three more Fingerprinter modules.
  - `EXPOSES` edge kind landed (Open WebUI → Ollama is the canonical example).
- **Acceptance criteria:**
  - `agenthound scan` against a docker-compose lab with all four services (Ollama + vLLM + Open WebUI + Jupyter) produces a graph containing all four `AIService` nodes.
  - Open WebUI's backend connection to Ollama emerges as an `EXPOSES` edge.
- **Risk:** vLLM and LangServe both default to port 8000 — fingerprint dispatch must try both and the first match wins. Mitigation: explicit priority in the fingerprint rule (`priority: 100`).

### Phase 4 — First Looter: LiteLLM (weeks 5–6 optimistic; **realistic 6–8 weeks** — LiteLLM's `/model/info` shape varies across versions and the version-tolerance work is non-trivial)
- **Deliverables:**
  - LiteLLM Fingerprinter (`rules/builtin/fingerprints/litellm.yaml` + `modules/litellmfp/`).
  - LiteLLM Looter (`modules/litellmloot/`).
  - `EXPOSES_CREDENTIAL` edge kind landed.
  - `agenthound loot <host> --type litellm --master-key sk-...` CLI verb wired (replaces today's stub).
  - The first concrete `LootResult` shape — replaces the v0 `struct{}` stub.
  - Integration test: against a stub LiteLLM server (FastAPI with mocked `/model/info` + `/key/list`), looting produces the expected `Credential` nodes + `EXPOSES_CREDENTIAL` edges.
  - GET-only assertion in test suite.
- **Acceptance criteria:**
  - Stub-server loot session emits ≥3 `Credential` nodes (one per fake provider).
  - `EXPOSES_CREDENTIAL` edges connect the LiteLLM `AIService` node to each credential.
  - The credential-chain detector fires on the resulting graph.
  - Server ingests the JSON with no validation errors.
- **Risk:** LiteLLM's `/model/info` response shape differs across versions. Mitigation: parse the response leniently, log unknown shapes as warnings, do not fail-fast on schema drift.

### Phase 5 — REVISED: deferred to v0.4. (Was: Qdrant / MLflow / LangServe fingerprinters in weeks 6–7. Per scope-creep correction, these slip to v0.4.)
- **Deliverables:**
  - Three more Fingerprinter modules + rules.
  - End-to-end docker-compose lab covering all 8 services.
- **Acceptance criteria:**
  - `agenthound scan` against the lab CIDR produces 8 `AIService` nodes — one per service kind.
  - `agenthound query --findings --severity critical` returns ≥1 critical finding involving an `AIService` node.

### Phase 6 — Demo data + docs + UI integration (weeks 7–8 optimistic; **realistic 3–4 weeks**)
- **Deliverables:**
  - `testdata/demo/scan_lab.json` — anonymized real-lab capture (per §10.5 recipe — NOT hand-fabricated) of the v0.2 lab environment + LiteLLM loot + a credential chain. v0.2 lab realistically contains 2 service kinds (Ollama + LiteLLM); §8.5's full 8-service lab is the v0.3+ target.
  - `docs/scanner.md` — operator guide for the network scanner.
  - `docs/loot-litellm.md` — LiteLLM-specific loot guide with master-key safety notes.
  - UI legend updated for the eight new icon variants.
  - The 17 pre-built queries audited for breakage; new pre-built query: `litellm-credential-leak` (LiteLLM AIService with EXPOSES_CREDENTIAL edges).
- **Acceptance criteria:**
  - User clicks "Demo" in the UI, sees a graph with all 8 service kinds.
  - The credential-chain detector fires on the demo data, surfaces in the Findings panel.
  - Two new pre-built queries (network exposure + LiteLLM credential leak) are wired and runnable from CLI + UI.

### Phase 7 — CFP submission + talk prep + lab build (weeks 8–12 optimistic; **realistic 5–7 weeks**)
- **Deliverables:**
  - DEF CON 34 main-stage CFP submission. **Hard deadline: 2026-05-01 23:59 UTC.** ([DEF CON 34 CFP](https://defcon.org/html/defcon-34/dc-34-cfp.html)) **NOTE: This deadline is BEFORE Phase 4 ends.** See §8 for resolution.
  - BSidesLV 2026 CFP submission. ([BSidesLV CFP](https://bsideslv.org/cfp))
  - DEF CON Demo Labs CFP submission (same May 1, 2026 deadline). ([DEF CON 34 Demo Labs CFP](https://defcon.org/html/defcon-34/dc-34-cfdl.html))
  - Slide deck draft.
  - Demo recording for the talk acceptance package.
- **Acceptance criteria:**
  - At least one CFP submitted by deadline.
  - Demo recording captures end-to-end flow: `agenthound scan` → `agenthound loot litellm` → server graph → credential-chain finding.

### Critical scheduling tension — RESOLVED: drop DEF CON main-stage from this cycle

Phase 4 (LiteLLM Looter) finishes ~2026-06-10 under optimistic estimates; **late June or later under realistic estimates**. DEF CON 34 main-stage CFP closes 2026-05-01.

**Submitting a main-stage CFP for work that doesn't exist yet is risky.** Main-stage reviewers favor "this is done now" over "this will be done in August"; an aspirational pitch competes against polished pitches from groups with completed research, and AgentHound is not yet that. Better path:

1. **Drop DEF CON 34 main-stage from this cycle.** Aim for DEF CON 35 (2027) once Phase 5+6 results are real.
2. **Submit DEF CON Demo Labs by 2026-05-01.** Lower bar than main-stage; reviewers expect working-tool walkthroughs, not finished research. We will have scanner skeleton + LiteLLM fingerprinter + LiteLLM Looter (or close) by August. 45-minute interactive slot is the right format.
3. **Submit BSidesLV breaking-ground by 2026-05-08 (verified deadline).** Acceptances roll from week of 2026-05-25; feedback comes early enough to inform Demo Labs prep. Lower stakes than DEF CON; explicitly accepts later-stage tools.
4. **Aim Hexacon 2026 (Oct, Paris) when CFP opens.** Strong fit for offensive-research framing once Phase 5+6 results are in.

Closed venues for context: RSAC 2026 (deadline 2025-08-18); Black Hat USA 2026 main briefings (2026-03-20); Black Hat Arsenal (2026-03-16); BSidesSF 2026 (already happened 2026-03-21–22 — flag for BSidesSF 2027 cycle); fwd:cloudsec NA 2026 (2026-03-20). fwd:cloudsec Europe 2026 still open through 2026-06-12.

---

## 8. CFP / conference strategy

### 8.1 Target conferences (verified deadlines)

| Conference | Dates | CFP closes | Status | Track fit |
|---|---|---|---|---|
| **DEF CON 34 main stage** | 2026-08-06 → 09 | **2026-05-01 23:59 UTC** | Open | Strong fit but timing-risky (see §7 critical scheduling tension). Hacker-research focus, AI security trending. ([DEF CON 34 CFP](https://defcon.org/html/defcon-34/dc-34-cfp.html)) |
| **DEF CON 34 Demo Labs** | 2026-08-06 → 09 | **2026-05-01 23:59 UTC** | Open | **Strongest fit for v0.2.** 45-minute interactive slot, lower bar than main stage — working tool walkthrough is sufficient and exactly what we will have. ([Demo Labs CFP](https://defcon.org/html/defcon-34/dc-34-cfdl.html)) |
| **DEF CON 34 Workshops** | 2026-08-06 → 09 | **2026-05-01 23:59 UTC** | Open | Moderate fit if we can frame a hands-on lab around scanning + pathfinding. Same May 1 deadline as main-stage and Demo Labs. ([DEF CON 34 CFP umbrella](https://defcon.org/html/defcon-34/dc-34-cfp.html)) |
| **DEF CON 34 Policy track** | 2026-08-06 → 09 | **2026-05-01 23:59 UTC** | Open | Weak fit. Policy-oriented. |
| **BSidesLV 2026 (breaking-ground track)** | 2026-08-03 → 05 | **2026-05-08 23:59 PT** (verified) — acceptances rolling from week of 2026-05-25 | Open | Strong fit. Track explicitly seeks "newest attack or defensive research, tools, new and novel approaches." Lower stakes than DEF CON main stage; accepts later-stage tools more readily. ([BSidesLV CFP](https://bsideslv.org/cfp)) |
| **BSidesSF 2026** | 2026-03-21 → 22 | **CLOSED — already happened** | Past | N/A — flag for **BSidesSF 2027** as a future cycle (typical CFP closes in winter; AgentHound v0.3+ would be a stronger fit by then). |
| **Hexacon 2026** | 2026-10-16 → 17 | CFP details TBD as of 2025-10; **monitor** | Likely opens summer 2026 | **Strong fit.** Offensive-research focus, Paris venue, attracts deep technical talks on novel tooling. Track this and submit when CFP opens. |
| **fwd:cloudsec EU 2026** | TBD | **2026-06-12** | Open | Moderate fit if framed as cloud-AI. ([fwd:cloudsec NA 2026](https://fwdcloudsec.org/conference/north-america/cfp.html)) |
| **OWASP Global AppSec EU 2026 (Vienna)** | 2026-06-25 → 26 | **CLOSED 2026-02-03** | Closed | Moderate fit (would have been). |
| **OWASP Global AppSec US 2026 (SF)** | 2026-11-05 → 06 | **2026-04-08 → 06-29 23:59 PDT** | Open | Strong fit. AppSec audience increasingly AI-aware. ([OWASP US 2026 CFP](https://sessionize.com/owasp-global-appsec-us-2026-cfp-SF/)) |
| **Black Hat USA 2026 main briefings** | 2026-08-04 (Vegas summits) / 2026-10-07 → 08 (Toronto briefings) | **CLOSED 2026-03-20** | Closed | N/A — closed. |
| **Black Hat USA 2026 Arsenal (tools)** | 2026-08-04 | **CLOSED 2026-03-16** | Closed | N/A — closed. |
| **RSAC 2026** | 2026-03-23 → 26 | **CLOSED 2025-08-18** | Closed (already happened) | N/A — already happened. |
| **SAINTCON 2026** | 2026-10-27 → 30 | Date `unverified — not in search results` | Unknown | Moderate fit. ([SAINTCON 2026](https://www.saintcon.org/)) |

### 8.2 Recommended submission portfolio

**Realistic stance.** DEF CON 34 main-stage CFP closes 2026-05-01; Phase 4 (LiteLLM Looter) ships ~late June at earliest under realistic 1.5-2.5× estimates (see §7). Submitting a main-stage CFP for work that doesn't exist yet is risky — main-stage reviewers favor "this is done now" over "this will be done in August." Better to drop main-stage from this cycle and aim for it at DEF CON 35 (2027) once Phase 5+6 results are in.

Updated priority order:

1. **DEF CON 34 Demo Labs** — submit by 2026-05-01. **This is the primary v0.2 target.** 45-minute interactive slot. Demo Labs reviewers expect a working tool walkthrough, not finished research; that is exactly what we will have at submission time (Phase 0–2 done, Phase 3+ in flight). Talk title proposal: "AgentHound: A Working Demo of Cross-Protocol Attack-Path Mapping for AI Agent Infrastructure."
2. **BSidesLV 2026 breaking-ground** — submit by **2026-05-08 23:59 PT** (verified). Lower stakes than DEF CON main stage; explicitly accepts later-stage tools. Acceptances roll from the week of 2026-05-25, so feedback comes early enough to inform the Demo Labs prep.
3. **DEF CON 34 Workshops** — submit by 2026-05-01 if we have bandwidth. Hands-on workshop framing: attendees scan a lab CIDR, ingest results, find a credential chain. Higher prep cost than Demo Labs.
4. **Hexacon 2026** (October Paris) — monitor CFP open and submit when available. Strong fit for offensive-research framing once Phase 5+6 results are in.
5. **OWASP Global AppSec US 2026 SF** — submit by 2026-06-29. AppSec audience values the OWASP Top-10 mapping AgentHound already does. Different framing: "OWASP Agentic Top 10 in practice — what we found scanning agent infrastructure".
6. **fwd:cloudsec EU 2026** — submit by 2026-06-12. Cloud-AI angle for the European audience.
7. **DEF CON 35 (2027) main stage** — the *real* main-stage target. By then Phase 5+6+7 have shipped, the lab dataset is mature, and the talk has empirical findings to anchor on. Plan the v0.3 milestone with this in mind.

**Explicitly NOT recommended:** DEF CON 34 main stage. Reasoning above. If you choose to submit anyway as a backup, the abstract must be honest about what is shipped vs. what will ship by August — main-stage reviewers see through aspirational pitches.

### 8.3 Talk angle — "Mapping AI agent attack paths in the wild"

**One-paragraph abstract draft:**

> Self-hosted AI infrastructure has eaten enterprise networks faster than security tooling has kept up. Ollama instances expose model weights to the internet (12,269 found in February 2026 alone). LiteLLM gateways aggregate provider keys behind a single master credential. Vector databases hold customer prompts in plaintext. We built AgentHound — a BloodHound-style attack-path mapper for AI agent infrastructure — and pointed it at consenting environments. This talk shows what we found: cross-protocol credential chains that span agent clients, MCP servers, A2A delegates, and exposed AI gateways, surfaced as graph paths a defender can read in seconds. We will demonstrate the live tool against a representative lab environment, walk through three real findings (anonymized) from authorized engagements, and release the v0.2 build of AgentHound at talk time.

### 8.4 Differentiation pitch — what makes this slot-worthy

1. **Empirical findings, not speculation.** The Ollama exposure number (12,269 instances) is real, recent, and from an authorized scan. Quantified threat data lands harder than threat models.
2. **Cross-protocol is unique.** No other tool models the MCP↔A2A↔gateway boundary as a graph. Every other AI security tool we surveyed (Snyk's Toxic Flow Analysis, Invariant Labs, Promptfoo) is single-protocol or single-runtime.
3. **The credential chain as a unifying concept.** Demonstrate one path that traverses Agent → MCP → env-var → LiteLLM master → upstream OpenAI key. That single slide compresses six different vendor tools into one walkable graph.
4. **Open source, with two binaries shipping.** SharpHound/BloodHound parallel is not subtle; the audience already understands the model. We get acceptance speed by mapping novel territory onto familiar tooling.
5. **Live demo.** The tool is real, it runs, it produces output that fits on a slide.

### 8.5 Lab requirements

To produce demo-quality findings:

- **Authorized lab environment.** Either a controlled VM environment under our own AWS/GCP account, or a customer environment with documented authorization. For DEF CON, a self-hosted lab is sufficient.
- **8 demo VMs**, each running one of the eight target services with intentionally weak configuration:
  - Ollama on `0.0.0.0:11434`, no auth, two custom fine-tunes loaded.
  - vLLM on `0.0.0.0:8000`, no `--api-key`, with vLLM 0.10.2 to demo CVE-2025-62164.
  - Qdrant on `0.0.0.0:6333`, no API key, three collections loaded with synthetic customer data.
  - MLflow on `0.0.0.0:5000`, no basic-auth, with five experiments and a pickled model artifact.
  - LiteLLM on `0.0.0.0:4000`, master key set to a known value (for demo only — operator supplies at loot time), config aggregating four "providers" (mocked).
  - Jupyter on `0.0.0.0:8888`, with `--ServerApp.token=''` for the unsafe-default demo.
  - LangServe on `0.0.0.0:8000` (port collision intentional — demonstrates fingerprint dispatch), one chain exposed.
  - Open WebUI on `0.0.0.0:3000` (host-mapped 8080), `WEBUI_AUTH=False`.
- **MCP client config + agent-card** files installed on a separate "operator" VM that holds the env-var credential bridging the cross-protocol chain.
- **Recorded demo** of the full flow at 1080p, ≤8 minutes, captured in OBS.

---

## 9. Risks and open questions

### 9.1 Legal and ethics

**Issue:** Network scanning AI services without authorization is potentially illegal under CFAA-style laws in many jurisdictions.

**Mitigations:**
- The CLI must default-deny scans against public IP space (`--allow-public-targets` required).
- The README and `docs/scanner.md` must contain an explicit "authorized targets only" warning at the top.
- Demo material must use the controlled lab; any anonymized customer-environment screenshots must be cleared by the customer.
- The talk abstract explicitly mentions "authorized engagements."

The existing CLAUDE.md `OPSEC` section already contains the "transparent assessment tool, not an evasion implant" framing — extend it with explicit scanner warnings.

### 9.2 OPSEC vs. EDR

**Issue:** HTTP probes to LiteLLM admin endpoints will trigger detection in environments running AI-aware monitoring (CrowdStrike Falcon Insight, Wiz, etc. are starting to alert on AI-API anomalies).

**Mitigations:**
- Default scan timing — TCP connect timeout 3s, no rapid-fire HTTP probing per host.
- The fingerprinter does ONE HTTP request per target per port. Not three, not ten.
- Loot phase explicitly logs every endpoint hit so the operator has a defensible record.
- Document in `docs/scanner.md` that the scanner is detectable; this is a feature, not a bug.

### 9.3 Service version drift

**Issue:** LiteLLM's `/model/info` response shape has changed across minor versions. Ollama added/removed fields. Fingerprint rules can stop matching.

**Mitigations:**
- Fingerprint rules use lenient matchers (regex, JSONPath with optional fields) rather than strict schemas.
- Looter parses the response as a `map[string]any` and extracts known fields with `unverified — needs operator confirmation`-style fallbacks rather than hard structural failures.
- The future template ecosystem (per `docs/future-modules.md`) makes rules updateable independent of the binary release cycle.
- Each fingerprint rule carries a `tested_versions` field documenting which upstream versions it was validated against.

### 9.4 Performance — scanning a /16

**Issue:** A /16 = 65,536 hosts × 8 ports = 524,288 TCP probes. At default 50 in-flight connections + 3-second timeout for closed ports, this is ~31,500 seconds (~9 hours) worst case if every port is closed.

**Mitigations:**
- Default port-concurrency is 50; users can raise to 500 for speed.
- Refuse /16+ without `--allow-large-cidr`.
- Connection pool reuse across hosts (Go's `net.Dialer` shares no state today; we'd add a connection-pool layer).
- Document performance expectations in `docs/scanner.md`.
- Recommend operators scope to /24 or smaller for interactive use.

### 9.5 Reverter for Looter — partial obligation, not "N/A"

**Issue.** Earlier framing said "Reverter is N/A — looting is read-only." That is half-true. The Looter does not modify the *target service's data*, but it DOES leave audit-trail entries on the target's observation infrastructure:

- LiteLLM Postgres `audit_log` table (when LiteLLM is configured with audit logging).
- Cloud HTTP access logs — CloudFront, ALB, nginx, ingress-controller — all see and record the requests.
- LangFuse and other structured-logging integrations capture every API call with timestamps, user agents, and source IP.
- Defender SIEMs (Splunk, ELK, Datadog) ingest those logs and alert on unusual patterns.

A Looter cannot un-log endpoint hits. The strict Reverter contract — "every change made on-target can be undone" — is technically violated, even though the target service's *content* is unchanged.

**Mitigation.** Operators using AgentHound for authorized assessment must coordinate with the target's IR team out-of-band to mark audit trails as authorized testing. This is a **process** mitigation, not a code mitigation. Codify it as:

1. A one-time interactive confirmation on first `agenthound loot` invocation: "I have authorization for this engagement and have notified the target's IR/security team. Proceed? [y/N]" — backed by a `~/.agenthound/loot-acknowledged` sentinel file so it doesn't repeat per command.
2. Documentation in `docs/loot-litellm.md` (when written) explaining the audit-trail residue and the operator's notification obligation.
3. A `--engagement-id <ID>` flag the operator sets to a value coordinated with the target's IR team; the Looter records this in every log line, making after-the-fact attribution straightforward.

### 9.6 CFAA exposure via single boolean flag

**Issue.** The current design gates public-IP scanning behind a single `--allow-public-targets` boolean flag. One typo, one shell-history rerun, one alias gone wrong — and the operator is one CTRL-R away from scanning the public internet without authorization. CFAA-style laws don't care that the operator "didn't mean to."

**Mitigations.** Make the gate harder to cross casually:

- **Interactive confirmation** for `--allow-public-targets`. On first use, the CLI prints the IP space being scanned, the count of public addresses, and prompts: "I have written authorization for these targets. Type the word AUTHORIZED to proceed:" — boolean-flag drift cannot satisfy this.
- **Authorization-file alternative.** A `--authorization-file <path>` flag pointing to a signed authorization document. The CLI does not validate the signature (that's not its job) but records the path and the file's SHA-256 in the scan output. This creates a paper trail.
- **Scan-output watermark.** Every ingest JSON produced by a `--allow-public-targets` scan carries a top-level `authorization` block with: a freeform `engagement_id`, a SHA-256 of the authorization-file (if provided), and a timestamp. Downstream analysis tools can refuse to operate on watermark-less public-IP scans.

### 9.7 Maintenance burden — versioned-rules-bundle is REQUIRED before shipping

**Issue.** 8 services × upstream version drift × no template-update path = full-time maintenance just to keep fingerprints current. LiteLLM's `/model/info` shape has already changed across minor versions. Ollama added/removed fields between 0.1 and 0.5. MLflow's API surface is a moving target. Fingerprints that ship in v0.2 will start failing within months unless we have a release path that decouples rule updates from binary releases.

**Resolution.** Commit to a **versioned-rules-bundle** path BEFORE Phase 3 ships, not as a future-template-ecosystem aspiration. Concretely:

- Fingerprint rules are loaded from `rules/builtin/fingerprints/*.yaml` at startup. The directory is `embed.FS`-bundled today (in-tree).
- Add a `--rules-bundle <path>` flag that loads from a tarball or directory at runtime, overlaying or replacing the embedded set.
- Publish a versioned bundle at `https://github.com/adithyan-ak/agenthound/releases/download/rules-vYYYY.MM.DD/rules.tar.gz` on each rule update. Sign the tarball with cosign.
- Document the rule-update cadence (target: monthly) and the deprecation policy (rules removed only after 90 days marked deprecated).

This is the actual mitigation for service version drift. The earlier framing ("future template ecosystem in `docs/future-modules.md`") deferred it; deferring it is what kills the project on Phase 6+.

### 9.8 Scope creep — the "16 modules" math doesn't fit one engineer

**Issue.** 8 services × 2 actions (Fingerprinter + Looter) = 16 modules. Each module is realistically 4–6 weeks for design + implementation + tests + integration + docs. That is **64–96 weeks** of engineering work, or 14–21 months for one full-time engineer. The plan as initially written implies all 16 are within this sprint; reality is **LiteLLM only is the v0.2 deliverable; Ollama and one other service are stretch goals; the remaining services are v0.3+.**

**Mitigations.**

- v0.2 commits to: scanner skeleton, **2** fingerprinters (Ollama + LiteLLM), **1** looter (LiteLLM). Drop the implication of 8 fingerprinters in this milestone.
- v0.3 adds: 3 more fingerprinters (vLLM, Open WebUI, Jupyter). One looter (Ollama).
- v0.4 adds: remaining 3 fingerprinters (Qdrant, MLflow, LangServe). One looter (Jupyter or MLflow).
- The roadmap §7 has been revised to reflect this.

### 9.9 Module-CLI-flag binding

**Issue:** Per-module flags (`--master-key`, `--auth-token`, `--admin-cookie`) need to integrate with cobra cleanly. A naive approach pollutes the global flag namespace.

**Resolution:** For v0.2, use the generic `--credential KEY=VALUE` flag (the looter reads `Credentials[KEY]` from `LootOptions`). Defer the `FlagsModule` sidecar interface (§5.4) until the second concrete Looter lands.

### 9.10 Open question — should the scanner also fingerprint MCP servers and A2A agents on the network?

**Discussion:** The current MCP and A2A modules require known endpoints (config-discovered or operator-supplied). The network scanner could discover MCP HTTP servers (port 3000 is common) and A2A agents (well-known path on any HTTPS host).

**Decision:** Out of scope for v0.2. Adding it doubles the fingerprint surface and the MCP/A2A modules are fundamentally about authenticated enumeration once the endpoint is known. If we add network discovery for MCP/A2A in v0.3, the existing modules absorb the discovered endpoint without rework.

### 9.11 Open question — what's the minimum Postgres data to ship with `agenthound-server` to make the demo reproducible?

**Discussion:** Today the demo seed file lives in `testdata/demo/`. With the new schema, that file grows.

**Resolution:** One file, `testdata/demo/scan_lab.json`, ~5–10 MiB. Loaded via `scripts/seed-demo.sh`. Generated from a real run of the §8.5 docker-compose lab plus an anonymization pass (NOT hand-fabricated). No additional Postgres data needed — the scan-history table is small and gets populated organically by the ingest.

---

## 10. Acceptance criteria for v0.2

The milestone is "shipped" when ALL of the following hold:

### 10.1 Functional acceptance

- [ ] `agenthound scan 10.0.0.0/24` against the demo lab returns ingest JSON containing ≥1 `AIService` node per service kind running in the lab.
- [ ] `agenthound scan 10.0.0.0/24 --allow-large-cidr=false` errors on `/16` or larger.
- [ ] `agenthound scan 1.1.1.1` errors without `--allow-public-targets`.
- [ ] `agenthound loot 10.0.0.42 --type litellm --master-key sk-...` against a stub LiteLLM server returns ingest JSON with ≥3 `Credential` nodes and matching `EXPOSES_CREDENTIAL` edges.
- [ ] The server ingests both scan and loot JSONs with no validation errors.
- [ ] The credential-chain detector fires on the resulting graph and surfaces in `/api/v1/analysis/findings`.

### 10.2 Schema acceptance

- [ ] `sdk/ingest/kinds.go` contains `AIService` and `AIModel` in `AllowedNodeKinds`.
- [ ] `sdk/ingest/kinds.go` contains `EXPOSES` and `EXPOSES_CREDENTIAL` in `AllowedEdgeKinds`.
- [ ] `EdgeKindEndpoints` covers both new edges.
- [ ] Neo4j schema migration runs cleanly on Neo4j 4.4 and 5.x (the existing version-detection path).
- [ ] The validator rejects malformed `AIService` nodes (e.g. missing `service_kind`).

### 10.3 UI acceptance

- [ ] The Graph Explorer renders `AIService` nodes with eight distinct service-kind icons.
- [ ] The Findings panel surfaces the new `litellm-credential-leak` finding.
- [ ] The Inspector shows `service_kind`, `endpoint`, `version`, `auth_method`, `is_anonymous_loot` for `AIService` nodes.
- [ ] The Legend lists the eight service variants.

### 10.4 CLI acceptance

- [ ] `agenthound scan` with no positional argument retains the today behavior (config + mcp).
- [ ] `agenthound scan <cidr|host>` is the new network mode.
- [ ] `agenthound loot <host> --type litellm` replaces the today's stub `agenthound loot` that prints "not yet implemented."
- [ ] Stub verbs `agenthound poison|implant|extract` still print "not yet implemented — see docs/future-modules.md" (unchanged).

### 10.5 Demo acceptance

- [ ] `testdata/demo/scan_lab.json` exists and ingests cleanly. **Generated by running the §8.5 docker-compose lab + capturing real scan output + anonymizing — NOT hand-fabricated.** Concrete recipe (also documented in `scripts/seed-demo.sh`):
  ```bash
  docker compose -f docker/demo/docker-compose.yml up -d
  agenthound scan 172.20.0.0/24 --output testdata/demo/scan_lab.raw.json
  # ... anonymize hostnames, IPs, redact any incidentally captured tokens ...
  scripts/anonymize-scan.sh testdata/demo/scan_lab.raw.json > testdata/demo/scan_lab.json
  rm testdata/demo/scan_lab.raw.json
  ```
- [ ] `make demo` produces a graph with whatever service kinds the v0.2 lab actually exposes (per scope-creep correction in §9.8: this is realistically 2 service kinds at v0.2 — Ollama + LiteLLM — not 8) and ≥1 credential chain finding.
- [ ] A 5-minute screen recording exists showing: scan → loot → graph → finding.

### 10.6 Documentation acceptance

- [ ] `docs/scanner.md` exists with operator guide + legal warning.
- [ ] `docs/loot-litellm.md` exists with master-key safety notes (including the §9.5 audit-trail residue caveat).
- [ ] `README.md` updated to mention the network scanner + LiteLLM Looter.
- [ ] `CLAUDE.md` updated: new node/edge kinds in the Graph Data Model section.
- [ ] `docs/cli-reference.md` updated.

**Note:** "Blog post or CFP submission references this milestone" was previously a release-gate criterion. **Removed from acceptance** — that's marketing fluff, not a release gate. The CFP/blog post is a Phase 7 deliverable (§7), not a v0.2 ship blocker. A working tool that nobody has written about yet is still shipped.

### 10.7 Testing acceptance

- [ ] All new code race-detector-clean.
- [ ] All new modules have unit tests with ≥80% coverage.
- [ ] CIDR expansion tested for IPv4 (/16, /24, /30, /32), IPv6 (/112, /128).
- [ ] Looter test suite asserts only GET methods are issued.
- [ ] CI passes including `gofmt`, `go vet`, `golangci-lint`, `govulncheck`, `go-licenses`, `deps-check`, `size-check`.

### 10.8 Release acceptance

- [ ] `goreleaser` produces signed binaries with the new modules linked.
- [ ] Collector binary stripped size remains within baseline + 10% (the new modules are small).
- [ ] Server Docker image builds with the new schema migrations.
- [ ] CHANGELOG.md updated.
- [ ] Git tag `v0.2.0` exists.

---

## 11. Critical files to modify

For implementer scoping. Every file that changes in this milestone, with phase mapping. Verified against the current repo state on 2026-04-23.

| File | Phase | Change kind | What changes |
|---|---|---|---|
| `sdk/ingest/kinds.go` | 1, 2, 4 | Edit | Add 8 per-kind labels + `AIService` umbrella + `AIModel` to `AllowedNodeKinds` and `AllNodeLabels`. Add `EXPOSES`, `EXPOSES_CREDENTIAL` to BOTH `AllowedEdgeKinds` AND `RawEdgeKinds`. Add edge endpoints in `EdgeKindEndpoints`. |
| `sdk/ingest/model_test.go:112,117` | 1 | Edit | Bump `TestAllowedEdgeKindsComplete` count from 21 → 23. Add regression test asserting both new edges in BOTH maps. |
| `sdk/action/looter.go` | 4 | Edit | Replace v0 stub `LootOptions` and `LootResult` structs with concrete shapes per §4.4. Add `IncludeCredentialValues bool` field. |
| `sdk/module/module.go` | 4 (sidecar) | Unchanged | Existing `Module` interface stays as-is (`Description`, `Version` preserved). |
| `sdk/module/flags.go` | 4 (sidecar) | NEW | Define `FlagsModule` sidecar interface (§5.4). Land only when 2nd Looter exists. |
| `sdk/module/state.go` | future | NEW | Define `StatefulModule` sidecar interface (§5.5). Defer to first Poisoner/Implanter. |
| `sdk/rules/matchers.go` | 2 | Edit | Extend `MatcherSpec` with `Version: 2` matchers (`http_status`, `http_header`, `json_path`). |
| `sdk/rules/engine.go` | 2 | Edit | Add probe orchestrator for HTTP fingerprinting (HTTP request → match against rule probes). |
| `sdk/rules/validate.go` | 2 | Edit | Validate the new matcher types under `Version: 2`. |
| `server/internal/ingest/validator.go:80` | 1 | Edit | Add new edges to RawEdgeKinds (already covered by sdk-side edit; this file's check at line 80 does not need its logic changed if RawEdgeKinds is extended). Confirm with a regression test. |
| `server/internal/graph/schema.go:13-24` | 1 | Edit | Add per-kind constraints + `:AIService` indexes per §6 Cypher block. Both 4.4 and 5.x branches. |
| `server/internal/analysis/registry.go:5` | 4 | Edit | Append `&processors.CrossServiceCredentialChain{}` to `allProcessors()` slice (after `&processors.CanReach{}`). |
| `server/internal/analysis/processors/cross_service_credential_chain.go` | 4 | NEW | New processor: `Name() = "cross_service_credential_chain"`, `Dependencies() = []string{"has_access_to"}` plus `"can_reach"`, `Process()` runs the §3.7 Cypher path query. |
| `server/internal/analysis/processors/cross_service_credential_chain_test.go` | 4 | NEW | Smoke test on a synthetic graph. |
| `collector/cli/scan.go` | 1 | Edit | Add positional CIDR/host argument; dispatch to Scanner module when set; preserve existing flag-based mode for backwards compat. |
| `collector/cli/loot.go` | 4 | NEW | Replace the `stubs.go` loot entry with a real `loot` cobra command. `--type litellm`, `--master-key`, `--credential KEY=VALUE`, `--include-credential-values`. |
| `collector/cli/stubs.go` | 4 | Edit | Remove `loot` from the not-implemented stub list (poison/implant/extract remain). |
| `collector/scanner/scanner.go` | 1 | Edit | Implement worker-pool Scanner per §3.9 sketch. Conform to `sdk/action.Scanner`. |
| `modules/networkscan/` | 1 | NEW (dir) | Scanner module + `register.go` for self-registration. |
| `modules/ollamafp/` | 2 | NEW (dir) | Ollama Fingerprinter module + rule file `rules/builtin/fingerprints/ollama.yaml`. |
| `modules/litellmfp/` | 4 | NEW (dir) | LiteLLM Fingerprinter module + rule file `rules/builtin/fingerprints/litellm.yaml`. |
| `modules/litellmloot/` | 4 | NEW (dir) | LiteLLM Looter module per §4.8 sketch. Tests: GET-only assertion, master-key-redaction assertion. |
| `server/ui/src/theme/tokens.ts` | 6 | Edit | Add 8 entries to `NODE_KIND_COLORS` map keyed by per-kind label. |
| `server/ui/src/lib/explorer/hex-config.ts:37-150` | 6 | Edit | Add 8 entries to `HEX_CONFIG`, keyed by per-kind label. Include `strokeColor`, `fillColor`, `icon`, `kindTag`, `column`, `groupLabel`. |
| `server/ui/src/lib/explorer/layout.ts` | 6 | Edit | Update partition-column logic if columns shift; likely a no-op. |
| `server/ui/src/lib/node-styles.ts` | 6 | Edit | Update size switch — `:AIService` size scales with `EXPOSES_CREDENTIAL` out-degree. |
| `server/ui/src/api/scans.ts` | 6 | Possibly edit | Possible additions for new scan-type filter. Verify when wiring. |
| `docs/loot-litellm.md` | 6 | NEW | LiteLLM-specific loot guide with master-key safety notes + audit-trail residue caveat (§9.5). |
| `docs/scanner.md` | 6 | NEW | Operator guide + legal warning. |
| `testdata/demo/scan_lab.json` | 6 | NEW | Real lab capture, anonymized. NOT hand-fabricated. |
| `scripts/anonymize-scan.sh` | 6 | NEW | Anonymization helper for the lab capture. |
| `docker/demo/docker-compose.yml` | 6 | NEW | The §8.5 docker-compose lab definition. |
| `CLAUDE.md` | 6 | Edit | Add new node kinds + edge kinds to "Graph Data Model" section. Separately: a follow-up should fix the stale Sigma+graphology reference (real stack is React Flow + ELK per `server/ui/package.json`). |

**Stale-doc note (out of scope for this sprint, but tracked).** `CLAUDE.md` claims the frontend uses Sigma 3.0.2 + graphology + @react-sigma/core, but `server/ui/package.json:26,29` shows the actual production stack is `@xyflow/react` (React Flow) + `elkjs` for layout. CLAUDE.md was written before that migration. Anyone reading the doc to set up local dev will be confused. Open a separate PR fixing CLAUDE.md to reflect the real stack.

---

## 12. What this plan is NOT

To avoid scope creep, this plan explicitly excludes:

1. **NOT an implementation.** No code in `cmd/`, `modules/`, `sdk/`, `server/`, or `ui/` changes as a result of this document. The only new file is this document itself.
2. **NOT a refactor of existing SDK interfaces.** The current `sdk/action/*.go` empty stubs ship as-is. The first concrete Looter (LiteLLM) lands against those stubs. The proposed shape evolutions in §5 are recorded but not landed.
3. **NOT a Poisoner / Implanter / Extractor design.** Those are v0.3+. The `Reverter` discussion is bounded to "the LiteLLM Looter does not need it" + "future destructive modules will."
4. **NOT a decision to ship per-action binaries.** Stay monolithic — the collector binary statically links every module. This holds until proven necessary by binary size or operational concerns.
5. **NOT a network-discovery framework competing with Nmap or Nuclei.** The scanner is narrowly scoped to AI services on standard ports. We do not do TCP/UDP fan-out, OS detection, banner grabbing for non-AI services, or vulnerability scanning of non-AI software. Operators who need general-purpose scanning use Nmap; AgentHound starts where Nmap stops.
6. **NOT a replacement for existing MCP / A2A / config collection.** The network scanner is additive. Existing flows (`agenthound scan --config --mcp --a2a`) keep working unchanged.
7. **NOT a brute-force tool.** We do NOT guess master keys, tokens, default passwords. We accept credentials from the operator at loot time. AgentHound is a transparent assessment tool; brute-forcing is a different category.
8. **NOT a template ecosystem split.** The future-templates work in `docs/future-modules.md` is preserved as future work. This sprint extends `sdk/rules` with new matcher types but keeps templates in-tree.
9. **NOT a multi-user feature reintroduction.** The two-binary split (ADR 0001) holds. Authentication remains the network layer's responsibility.

---

## Appendix A — sources cited

### LiteLLM
- [LiteLLM Virtual Keys](https://docs.litellm.ai/docs/proxy/virtual_keys) — master key format, `/key/info`, `/key/generate`.
- [LiteLLM health endpoints](https://docs.litellm.ai/docs/proxy/health) — `/health/liveliness` is anonymous.
- [LiteLLM README on GitHub](https://github.com/BerriAI/litellm) — port 4000 default.
- [LiteLLM March 2026 security update](https://docs.litellm.ai/blog/security-update-march-2026) — supply-chain incident.
- [GHSA-g26j-5385-hhw3](https://github.com/advisories/GHSA-g26j-5385-hhw3) — CVE-2024-6587 SSRF.
- [Snyk on the LiteLLM scanner backdoor](https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/).

### Ollama
- [Ollama API docs](https://github.com/ollama/ollama/blob/main/docs/api.md) — endpoints + default port.
- [Ollama issue #11941 — "Secure Mode"](https://github.com/ollama/ollama/issues/11941) — auth model debate.
- [LeakIX 2026 Ollama exposure report](https://blog.leakix.net/2026/02/ollama-exposed/) — 12,269 instances.
- [NVD CVE-2024-37032](https://nvd.nist.gov/vuln/detail/CVE-2024-37032) — Probllama path traversal.

### vLLM
- [vLLM OpenAI-compatible server](https://docs.vllm.ai/en/stable/serving/openai_compatible_server/) — `--api-key`, port 8000, `/v1/models`.
- [GHSA-mrw7-hf4f-83pf](https://github.com/advisories/GHSA-mrw7-hf4f-83pf) — CVE-2025-62164 deserialization RCE.
- [Miggo CVE-2025-61620](https://www.miggo.io/vulnerability-database/cve/CVE-2025-61620) — Jinja2 DoS.
- [ZeroPath on CVE-2025-66448](https://zeropath.com/blog/cve-2025-66448-vllm-rce-automap) — auto_map RCE.
- [GitLab advisories — CVE-2025-9141](https://advisories.gitlab.com/pkg/pypi/vllm/CVE-2025-9141/).

### Qdrant
- [Qdrant security guide](https://qdrant.tech/documentation/guides/security/) — default unauthenticated, port 6333/6334.

### MLflow
- [MLflow tracking server](https://mlflow.org/docs/latest/ml/tracking/server/) — port 5000, auth model.
- [MLflow basic auth](https://mlflow.org/docs/latest/self-hosting/security/basic-http-auth/) — opt-in basic auth.
- [NVD CVE-2024-27132](https://nvd.nist.gov/vuln/detail/CVE-2024-27132) — XSS → Jupyter RCE.
- [JFrog research on CVE-2024-27132](https://research.jfrog.com/vulnerabilities/mlflow-untrusted-recipe-xss-jfsa-2024-000631930/).
- [JFrog "MLOps to MLOops" report](https://jfrog.com/blog/from-mlops-to-mloops-exposing-the-attack-surface-of-machine-learning-platforms/).

### Jupyter
- [Jupyter Server security](https://jupyter-server.readthedocs.io/en/latest/operators/security.html).
- [NVD CVE-2024-28179](https://nvd.nist.gov/vuln/detail/CVE-2024-28179) — websocket auth bypass.
- [GHSA-w3vc-fx9p-wp4v](https://github.com/advisories/GHSA-w3vc-fx9p-wp4v).
- [xss.am on CVE-2023-39968 token leak chain](https://blog.xss.am/2023/08/cve-2023-39968-jupyter-token-leak/).

### LangServe
- [LangServe README](https://github.com/langchain-ai/langserve).
- [LangServe on PyPI](https://pypi.org/project/langserve/).

### Open WebUI
- [Open WebUI quick start](https://docs.openwebui.com/getting-started/quick-start/) — port 8080 container default.
- [Cato CTRL on CVE-2025-64496](https://www.catonetworks.com/blog/cato-ctrl-vulnerability-discovered-open-webui-cve-2025-64496/).
- [GHSA-cm35-v4vp-5xvx](https://github.com/advisories/GHSA-cm35-v4vp-5xvx) — CVE-2025-64496 Direct Connect RCE.
- [GHSA-frv8-gffc-37px](https://github.com/advisories/GHSA-frv8-gffc-37px) — CVE-2025-63681.

### Conferences
- [DEF CON 34 main stage CFP](https://defcon.org/html/defcon-34/dc-34-cfp.html) — closes 2026-05-01.
- [DEF CON 34 Demo Labs CFP](https://defcon.org/html/defcon-34/dc-34-cfdl.html) — closes 2026-05-01.
- [Black Hat USA 2026 CFP page](https://blackhat.com/call-for-papers.html) — main briefings closed 2026-03-20.
- [BSidesLV CFP](https://bsideslv.org/cfp) — 2026 dates 2026-08-03 to 2026-08-05.
- [fwd:cloudsec NA 2026 CFP](https://fwdcloudsec.org/conference/north-america/cfp.html) — closed 2026-03-20; EU open through 2026-06-12.
- [OWASP Global AppSec EU 2026 CFP](https://sessionize.com/owasp-global-appsec-eu-2026-cfp-wash/) — closed 2026-02-03.
- [OWASP Global AppSec US 2026 CFP](https://sessionize.com/owasp-global-appsec-us-2026-cfp-SF/) — opens 2026-04-08, closes 2026-06-29.
- [RSAC 2026 CFP](https://www.rsaconference.com/usa/call-for-submissions) — already closed (2025-08-18).
- [SAINTCON 2026](https://www.saintcon.org/) — CFP date `unverified`.
- [BSidesSF 2026](https://bsidessf.org/) — past (2026-03-21–22).
- [Hexacon 2026](https://www.hexacon.fr/) — Oct 16–17, 2026; CFP details TBD as of October 2025.
- [BSidesLV 2026 CFP page (verified deadline)](https://bsideslv.org/cfp) — CFP closes 2026-05-08 23:59 PT; acceptances rolling from week of 2026-05-25.

---

## Verification corrections applied

This section records every correction applied to this document on 2026-04-23 against two independent verification reviews. Each correction is a confirmed true positive.

| # | Section | Correction | Source |
|---|---|---|---|
| 1 | §2.2 vLLM CVEs | Reframed CVE-2025-62164 as CVSS 8.8 with `PR:L` (not "anonymous RCE"), corrected affected version range to `>= 0.10.2, < 0.11.1`, cited NVD + GHSA. | verifier #1 + verifier #2 |
| 2 | §2.5 LiteLLM CVEs | Corrected CVE-2024-6587 SSRF: NVD lists 1.38.10 as vulnerable; GHSA confirms patched in 1.44.8. | verifier #1 |
| 3 | §2.2 vLLM CVEs | Added missing version range for CVE-2025-9141: `>= 0.10.0, < 0.10.1.1`, requires both `--enable-auto-tool-choice` and `--tool-call-parser qwen3_coder` flags. | verifier #2 |
| 4 | §2.4 MLflow CVEs | Reclassified CVE-2024-27132 as reflected/DOM-based XSS (NOT stored XSS), CVSS 9.6 CRITICAL with `PR:N`, `UI:R`. | verifier #1 |
| 5 | §2.8 Open WebUI CVEs | Added Direct Connections-disabled-by-default caveat for CVE-2025-64496; CVSS 7.3 with `PR:L` AND `UI:R`. | verifier #2 |
| 6 | §2.8 Open WebUI CVEs | Clarified CVE-2025-63681 is CVSS 4.0/2.1 LOW — DoS only, not load-bearing. | verifier #1 |
| 7 | §2.1 Ollama CVEs | Added Ollama-default-unauthenticated context to CVE-2024-37032's PR:L; in practice effectively unauthenticated. | verifier #2 |
| 8 | §8.1 CFP table | Marked BSidesLV deadline as verified: 2026-05-08, acceptances rolling from week of 2026-05-25. | verifier #1 |
| 9 | §8.1 CFP table | Added DEF CON 34 Workshops & Demo Labs as separate venues alongside main-stage (same May 1, 2026 deadline). | verifier #1 |
| 10 | §8.1 CFP table | Added BSidesSF 2026 (past, March 21–22, 2026) flagged for BSidesSF 2027 future cycle. | verifier #2 |
| 11 | §8.1 CFP table | Added Hexacon 2026 (Oct 16–17, 2026; CFP TBD as of Oct 2025) as candidate. | verifier #2 |
| 12 | §6 Schema | Added explicit "Validator update" subsection — SHIP-BLOCKER. `server/internal/ingest/validator.go:80` checks `RawEdgeKinds`; new edges must be added to BOTH `RawEdgeKinds` and `AllowedEdgeKinds`. Recommendation (a) extends `RawEdgeKinds`. | verifier #1 + verifier #2 |
| 13 | §5.4, §5.5 | Replaced breaking interface change with sidecar pattern: `FlagsModule` and `StatefulModule` are optional companion interfaces. Existing `Module` keeps `Description()` and `Version()` (load-bearing). Drop `Name()` proposal — redundant with `Description()`. | verifier #1 + verifier #2 |
| 14 | §3.9 Scanner sketch | Replaced unbounded goroutine spawn with fixed-size worker pool consuming a buffered task channel. `O(workers)` goroutines, default 50, regardless of target count. | verifier #1 + verifier #2 |
| 15 | §3.9 Scanner sketch | Added `select` checking `ctx.Done()` BEFORE every `tasks <-` send so Ctrl-C does not spawn additional work. | verifier #2 |
| 16 | §3.9 Scanner sketch | Wrapped each worker task body in `defer recover()` for panic isolation; logs and continues. | verifier #1 |
| 17 | §4.8 Looter sketch | Added `bytes` and `strings` imports (used by `bytes.Contains`, `strings.HasPrefix`); also `log/slog` for redaction logging. | verifier #1 |
| 18 | §4.8 Looter sketch | Replaced `Name() string` method with the actual `Module` interface methods: `Description() string` and `Version() string`. ID changed to dotted `"litellm.loot"` per existing convention. | verifier #1 + verifier #2 |
| 19 | §4.8 Looter sketch + §4.4 LootOptions | Renamed `IncludeValues` → `IncludeCredentialValues` to match Config Collector convention; field now exists in `LootOptions`. | verifier #2 |
| 20 | §4.8 Looter sketch | Replaced ignored `error` returns from `http.NewRequestWithContext` with explicit checks: `req, err := ...; if err != nil { return ... fmt.Errorf("build request: %w", err) }`. errcheck-clean. | verifier #1 |
| 21 | §4.8 Looter sketch | Now actually populates `LootResult.PartialErrors` when `getKeyList` fails; logs a warning and falls through with empty result. | verifier #1 + verifier #2 |
| 22 | §4.8 Looter sketch | Added explicit `redact()` helper, slog redaction pattern (`masterKey[:8] + "..."`), and a mandatory unit test asserting the full master key never appears in `slog` output. | verifier #2 |
| 23 | §3.5 Schema decision | Reversed the single-`AIService` recommendation. Rewrote to recommend Option B: per-service kinds (`OllamaInstance`, `VLLMInstance`, etc.) WITH multi-label `:AIService` umbrella for unified queries. Cited evidence: `sdk/ingest/kinds.go:4-17` (12 distinct labels), `server/internal/analysis/processors/has_access_to.go:20` (every processor matches by label), UI dispatches on `kinds[0]` in `server/ui/src/lib/node-styles.ts:9-14`, `theme/tokens.ts:5-21`, `lib/explorer/hex-config.ts:37-150`. | verifier #1 + verifier #2 |
| 24 | §6 Schema additions | Added explicit instruction to wire `cross_service_credential_chain` processor into `allProcessors()` at `server/internal/analysis/registry.go:5` (verified path; the user's correction said `postprocessor.go:15` but the actual location is `registry.go:5`). Declared dependencies, smoke test path. | verifier #1 |
| 25 | §6 UI integration | Replaced misleading reference to CLAUDE.md "Node Visual Encoding" with the actual UI files that change: `server/ui/src/theme/tokens.ts`, `lib/explorer/hex-config.ts`, `lib/explorer/layout.ts`, `lib/node-styles.ts`. Noted that CLAUDE.md is stale (claims Sigma+graphology; actual stack is React Flow + ELK per `server/ui/package.json:26,29`). | verifier #1 + verifier #2 |
| 26 | (multiple) `docs/future-modules.md` | Verified the file exists at `/Users/akoffsec/dev/agenthound/docs/future-modules.md`. References preserved as-is — no action required. | verifier #1 |
| 27 | §9.5 Reverter contract | Rewrote from "Reverter is N/A — looting is read-only" to acknowledge audit-trail residue (LiteLLM Postgres, cloud HTTP logs, LangFuse, defender SIEMs). Added one-time interactive confirmation, `--engagement-id` flag, and `docs/loot-litellm.md` documentation as mitigations. | verifier #1 + verifier #2 |
| 28 | §9.6 (new) | Added CFAA-exposure risk: `--allow-public-targets` is one flag away. Stronger gates: interactive "type AUTHORIZED" confirmation, `--authorization-file` alternative, scan-output watermark. | verifier #1 |
| 29 | §9.7 (new) | Added maintenance-burden risk. Committed to versioned-rules-bundle path BEFORE Phase 3 ships, not as a future-template aspiration. Concrete mechanism: `--rules-bundle <path>` + signed monthly tarball releases. | verifier #1 + verifier #2 |
| 30 | §9.8 (new) | Added scope-creep risk. 8 services × 2 actions × 4–6 weeks = 14–21 months for one engineer. v0.2 commits to scanner + 2 fingerprinters + 1 looter; remaining services slip to v0.3+. | verifier #1 + verifier #2 |
| 31 | §7 Phased roadmap | Added bold note that estimates are 1.5–2.5× optimistic; realistic total 18–30 weeks (~4.5–7 months). Per-phase realistic ranges added. Phases 3 and 5 deferred to v0.3 / v0.4. | verifier #1 + verifier #2 |
| 32 | §7 Critical scheduling tension + §8.2 portfolio | Dropped DEF CON 34 main-stage from this cycle. Primary v0.2 target: DEF CON 34 Demo Labs (May 1) + BSidesLV breaking-ground (May 8). Aim DEF CON 35 (2027) main-stage with Phase 5+6 results. | verifier #1 + verifier #2 |
| 33 | §10.6 Documentation acceptance | Removed "Blog post or CFP submission references this milestone" from acceptance criteria — marketing fluff. Moved to Phase 7 deliverable. | verifier #1 |
| 34 | §10.5 Demo acceptance | Tightened: demo data is GENERATED via the §8.5 docker-compose lab + real scan capture + anonymization, NOT hand-fabricated. Concrete recipe added. Filename changed to `testdata/demo/scan_lab.json`. | verifier #2 |
| 35 | §11 (new) | Added "Critical files to modify" table enumerating every file that changes per phase, verified against current repo. Original §11 ("What this plan is NOT") renumbered to §12. | verifier #1 + verifier #2 |
