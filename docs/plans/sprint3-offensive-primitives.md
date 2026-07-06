# Sprint 3 — Offensive primitives (network scanner + first Looter)

> **2026-07-06 correction (post-v0.3, retroactive).** §2.1's bullets treating `/api/blobs/<digest>` as a GET-able weight-download channel sit outside Ollama's documented HTTP API surface. Upstream defines only `HEAD` (existence check for the create-model flow) and `POST` (upload) on that path — raw weight blobs are reachable via filesystem access to `~/.ollama/models/blobs/` on the host, not over HTTP. The Ollama Looter's `--include-weights` / `--weights-dir` surface (planned in §5) was removed in a follow-up to align with the upstream API — see the CHANGELOG entry titled "Ollama Looter: align flag surface with upstream API". Read every subsequent Ollama-loot section in this plan with that correction in mind.
>
> **Status:** Draft for design review (refreshed 2026-05-16).
> **Authors:** AgentHound architect (research + plan).
> **Date:** 2026-04-23, refreshed 2026-05-16.
> **Audience:** Adithyan AK + future contributors.
> **Scope of this document:** research-grounded plan for AgentHound's "ship the offensive surface" milestone (v0.2). **This is a plan, not an implementation.** No code in this repo has changed in service of this plan since 2026-04-26.
>
> **2026-05-16 refresh + architect review.** Two passes landed on this date:
>
> 1. **CFP refresh.** §7 + §8 rewritten around **DEF CON 34 Red Team Village (CFP closes 2026-05-31)** as the new primary v0.2 target. The original Demo Labs / BSidesLV deadlines passed before any v0.2 implementation could ship. fwd:cloudsec EU 2026 (2026-06-12) + OWASP Global AppSec US 2026 SF (2026-06-29) are now secondary/tertiary.
>
> 2. **Architect review (corrections #39–#58).** Three parallel reviewers swept the plan for vision/cohesion gaps, code-grounded technical drift, and internal contradictions. Twenty-two true findings landed; ~25 were verified false positives and rejected. The most consequential changes: (a) added the **credential merge-key strategy** (`value_hash`) without which the central credential-chain demo cannot fire across collectors (§3.7 + §4.5); (b) added the missing `UmbrellaLabels` skip-list so the umbrella `:AIService` label doesn't trigger duplicate Neo4j uniqueness constraints (§3.5 + §6 + §11); (c) added the missing `model_test.go` count bumps for new node kinds (§6 + §11); (d) reconciled `cross_service_credential_chain.Dependencies()` to `["has_access_to", "can_reach"]` consistently (§6 + §11); (e) renamed the `--scan-output` / `--scan-concurrency` flags to remove documentation-vs-implementation drift; (f) removed all effort/timeline estimates — phases are now ordered-and-deliverable-defined, execution speed is left to the implementer.

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
3. **Nine new node kinds** (8 per-service + `AIService` umbrella per §3.5 Option B multi-label) and **two new edge kinds** (`EXPOSES`, `EXPOSES_CREDENTIAL`) wired through the ingest schema, the validator (including the SHIP-BLOCKER fix at `server/internal/ingest/validator.go:80` per §6), the writer, and the UI. The `AIModel` reservation originally proposed for v0.2 was deferred to v0.3 — see `docs/plans/v0.2-implementation.md` decision E for rationale (no v0.2 emitter, dead schema entry confuses readers, and adding it later is a five-line PR).
4. **Demo seed file** (`testdata/demo/scan_lab.json`) showing a credential chain that reaches a LiteLLM-extracted OpenAI key. Generated from a real run of the v0.2 demo lab (`docker/demo/docker-compose.yml`, 2 services per §9.8) plus an anonymization pass — NOT hand-fabricated. The §8.5 8-VM lab is the v0.3/v0.4 target.
5. **One submitted talk** to DEF CON 34 Red Team Village (CFP closes 2026-05-31). Secondary submissions: fwd:cloudsec EU 2026 (deadline 2026-06-12), OWASP Global AppSec US 2026 SF (deadline 2026-06-29). DEF CON main-stage is intentionally NOT a v0.2 target — see §7 and §8.2 for reasoning. Aim DEF CON 35 (2027) main-stage once Phase 3 + 5 results are real.

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

For each target host, probe each configured port with a TCP connect (no SYN scan — we are not raw-socket-privileged, and connect scans are sufficient for our threat model). Bounded concurrency via a semaphore — default 50 in-flight network probes, override `--network-scan-concurrency`. Connection timeout 3 seconds (the rule-of-thumb for "is this port open"). Failed connections are dropped silently.

The existing `--scan-concurrency` flag (default 5) governs MCP/A2A enumeration worker count and is kept as-is — these have different cost profiles (MCP/A2A do JSON-RPC handshakes; network probes do raw TCP connects), so a single knob would be the wrong abstraction.

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
- UI dispatches on Neo4j labels in `server/ui/src/lib/node-styles.ts:9-14` (color: `for (const kind of kinds)` — first match in order), `node-styles.ts:17` (size: `kinds[0]`), `server/ui/src/theme/tokens.ts:5-20`, and `server/ui/src/lib/explorer/hex-config.ts:37-150`. Per-kind label MUST be `kinds[0]` so size dispatch picks the right service; color lookup walks the array but gets the same answer because per-kind comes first. A property-based discriminator would force a runtime branch in UI code that today is a clean lookup.

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
    // AIModel deferred to v0.3 — no v0.2 emitter; see v0.2-implementation.md decision E.
}

var AllNodeLabels = []string{
    // ... existing 14 ...
    "OllamaInstance", "VLLMInstance", "QdrantInstance", "MLflowServer",
    "LiteLLMGateway", "JupyterServer", "LangServeApp", "OpenWebUIInstance",
    "AIService",
    // AIModel lands in v0.3 with the first model-artifact emitter.
}

// Labels for which `objectid` uniqueness constraints must NOT be created
// (the umbrella label is shared across multiple per-kind nodes; constraining
// it would create false collisions during MERGE).
var UmbrellaLabels = map[string]bool{
    "AIService": true,
}
```

Each emitted node carries `kinds: ["OllamaInstance", "AIService"]` (per-service first for primary dispatch, umbrella second). The writer `MERGE`s on the per-service label and applies both labels to the merged node. The Neo4j constraint-creation loop in `server/internal/graph/schema.go:37` iterates `AllNodeLabels` and skips any label in `UmbrellaLabels` so the umbrella gets indexes only, not constraints — see §6 for the schema delta.

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
| `EXPOSES` | `AIService` | `AIService` | An AI service exposes another AI service it has a backend dependency on — e.g., `OpenWebUI EXPOSES Ollama` (chat UI → inference backend). For v0.2 this edge is reserved (added to allow-lists) but not emitted by any v0.2 collector; Phase 3 (v0.3) populates it. |
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

#### Credential merge keys (load-bearing for the demo)

The Cypher above joins on `(c1:Credential)` being the same node from two different collectors:

- **Config Collector** emits `c1` with `objectid = ComputeNodeID("Credential", source, name)` where `source` is the config-file path and `name` is the env-var name (see `modules/config/collector.go:165`).
- **LiteLLM Looter** emits `c1` (the master key it received from the operator) and `c2` (the upstream provider keys it extracted via `/key/list` and `/model/info`). These have no relation to a config-file path — the Looter doesn't see one.

For the chain to fire, the Looter MUST emit the master-key `Credential` node with an `objectid` that matches whatever the Config Collector emitted for the same secret. The plan's merge strategy:

1. **`Credential` nodes carry a `value_hash` property** — SHA-256 of the credential's actual value (already produced by the Config Collector via `sdk/common/hasher.go`). This lets us merge across collectors without sharing `objectid` derivation.
2. **The cross-service-credential-chain processor joins on `value_hash`, not `objectid`**:
   ```cypher
   MATCH p = (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)
                 -[:HAS_ENV_VAR]->(c1:Credential)
   MATCH (svc:AIService)-[:EXPOSES_CREDENTIAL]->(c1master:Credential
                 {value_hash: c1.value_hash})
   MATCH (svc)-[:EXPOSES_CREDENTIAL]->(c2:Credential)
   WHERE c2.provider IN ["openai", "anthropic", "aws_bedrock"]
   RETURN p, svc, c2
   ```
3. **The Looter's `Credential` `objectid` derivation is independent** — `ComputeNodeID("Credential", "litellm", endpoint, name)` for v0.2 — but `value_hash` is what bridges to Config Collector emissions.
4. **When `--include-credential-values=false` (default)**, the Looter still computes `value_hash` over the master key; the value itself is not stored. The Config Collector already does the same. This makes the join secret-safe.

§4.5 (Looter output) commits to populating `value_hash` on every emitted `Credential` node. Without this property, the §3.7 chain cannot fire — a `Credential`-merge gap was the demo's biggest hidden ship-blocker before this subsection landed.

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
| `Credential` × N | `type=apiKey`, `name=upstream-<provider>`, `provider=openai\|anthropic\|aws_bedrock\|...`, `is_exposed=true`, `source=litellm`, `value_hash=<sha256>` (per §3.7 merge convention), `evidence_ref=model_info_response_<idx>` | One per upstream provider key found in `/model/info` |
| `Credential` × N | `type=virtual_key`, `name=<virtual_key_id>`, `is_exposed=true`, `source=litellm`, `value_hash=<sha256>`, `spend_usd=...`, `models=[...]` | One per entry in `/key/list` |
| `Credential` (master) | `type=master_key`, `name=litellm-master`, `is_exposed=true`, `source=litellm`, `value_hash=<sha256>` — used by §3.7's `cross_service_credential_chain` join | The master key the operator supplied at loot time; stored as hash, not value (unless `--include-credential-values`) |

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

For v0.2, the `--master-key` flag is registered directly on the `loot` cobra command (`collector/cli/loot.go`) — it's not module-discoverable yet. The generic mechanism is `--credential KEY=VALUE`, which the looter reads as `Credentials[KEY]` from `LootOptions`. So `--credential master_key=sk-...` works for any future Looter without per-module flag registration; `--master-key` is sugar for the LiteLLM-specific case.

The `Module.Flags()` / `FlagsModule` sidecar interface (see §5.4) is deferred until the second concrete Looter ships — it would let modules self-register their flags rather than the CLI hard-coding them. v0.2 hard-codes `--master-key` because the cost of the abstraction isn't paid back until there are 2+ Looters with module-specific flags.

Future convention (when `FlagsModule` lands): `--<credential-name>` flags are module-scoped — Ollama's looter would use `--auth-token`; Jupyter's would use `--token`; Open WebUI's would use `--admin-cookie`.

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

**Note (v0.2 deferral):** the `AIModel` kind originally listed in this table moved to v0.3. The v0.2 LiteLLM Looter does not emit model artifacts; the v0.3 Ollama Looter will be the first. Adding a kind later is a five-line PR (one entry in `AllowedNodeKinds`, one in `AllNodeLabels`, two test count bumps, one Neo4j constraint) — cheaper than carrying a dead schema entry that confuses onboarding for an entire release cycle. See `docs/plans/v0.2-implementation.md` decision E.

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
// AIModel deferred to v0.3 — see note above.

// AllNodeLabels — additions
"AIService",

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
- `sdk/ingest/model_test.go:100` — bump `if len(AllowedNodeKinds) != 12` to `21` (12 existing + 9 new: 8 per-service + `AIService`; `AIModel` deferred to v0.3).
- `sdk/ingest/model_test.go:106` — bump `if len(AllNodeLabels) != 14` to `23` (14 existing + 9 new).
- `sdk/ingest/model_test.go:112` — bump `if len(AllowedEdgeKinds) != 21` to `23` (21 existing + `EXPOSES` + `EXPOSES_CREDENTIAL`).
- `sdk/ingest/model_test.go:117` — `TestRawEdgeKindsSubsetOfAllowed` continues to pass automatically since we add to both maps.
- New test in `sdk/ingest/model_test.go` — assert `EXPOSES`, `EXPOSES_CREDENTIAL`, `AIService`, and the 8 per-service labels are present in their respective maps (regression guard against future drift). (`AIModel` lands with v0.3 — its corresponding assertion ships with the Ollama Looter PR.)

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
-- AIModel constraint deferred to v0.3 — no v0.2 emitter.

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
-- AIModel constraint deferred to v0.3.
CREATE INDEX FOR (n:AIService) ON (n.is_anonymous_loot);
CREATE INDEX FOR (n:AIService) ON (n.endpoint);
```

These statements live in `server/internal/graph/schema.go:13-77` (`indexDefs` slice + `InitSchema` + `constraintCypher` helper, where the 4.4-vs-5.x version fork actually lives). The version-detection path that decides between `ON...ASSERT` and `FOR...REQUIRE` already exists; we just add to the per-version Cypher block lists.

**Post-processor wiring (`server/internal/analysis/registry.go:5`)** — the new `cross_service_credential_chain` processor (described in §3.7) must be registered in the `allProcessors()` slice. Verified location: `server/internal/analysis/registry.go:5` (NOT `postprocessor.go` — `postprocessor.go` holds the runner; the slice lives in `registry.go`). Concrete edits:

- Create `server/internal/analysis/processors/cross_service_credential_chain.go` implementing `Name() string` (returns `"cross_service_credential_chain"`), `Dependencies() []string` (returns `[]string{"has_access_to", "can_reach"}` — the chain reads `EXPOSES_CREDENTIAL` edges plus the agent-to-resource state populated by `CanReach`; ordering is enforced by `validateDependencyOrder` in `postprocessor.go`), and `Process(ctx, db, scanID) (ProcessingStats, error)`.
- Edit `server/internal/analysis/registry.go:6-17` to append `&processors.CrossServiceCredentialChain{}` to the slice. Add it after `&processors.CanReach{}` (line 12) since the chain depends on `CanReach`-derived state and must run after it.
- Add a smoke test in `server/internal/analysis/processors/cross_service_credential_chain_test.go`: build a synthetic graph with `(:AgentInstance)-[:HAS_ENV_VAR]->(:Credential)<-[:EXPOSES_CREDENTIAL]-(:LiteLLMGateway:AIService)-[:EXPOSES_CREDENTIAL]->(:Credential {provider:"openai"})`, run the processor, assert it emits the expected `CAN_REACH`-style edge from the agent to the upstream credential.
- The dependency order check in `validateDependencyOrder` (`server/internal/analysis/registry.go` is exported by `postprocessor.go`) will fail-fast if dependencies are wrong.

**UI integration scope.** CLAUDE.md correctly documents the UI stack as React Flow + ELK (verified against `server/ui/package.json:26,29`). The actual UI files that change for this milestone are:

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

CLAUDE.md was already updated to reflect the actual React Flow + ELK frontend stack — no separate doc-fix follow-up is required for this sprint.

---

## 7. Phased roadmap

This section defines the phase ordering, deliverables, and acceptance criteria. Effort estimates and timelines are deliberately omitted — execution speed is a function of who's working on this and at what cadence. The dependency order is what matters: each phase produces artifacts that later phases consume, and skipping ahead breaks the chain.

The CFP deadlines in §8 are external, not a per-phase clock; they constrain *what must demonstrably exist by submission time*, not how phase-1 takes.

**Phase ordering at a glance:**

```
Phase 0 (design review)
   ↓
Phase 1 (scanner skeleton, no fingerprinting)
   ↓
Phase 2 (rules engine v2 + Ollama fingerprinter + AIService node kind)
   ↓
Phase 4 (LiteLLM fingerprinter + LiteLLM Looter + EXPOSES_CREDENTIAL edge)
   ↓
Phase 6 (demo data + docs + UI integration + credential-chain query)
   ↓
Phase 7 (CFP submission + talk prep + lab build)

Phase 3 (vLLM / Open WebUI / Jupyter fingerprinters)   ─── deferred to v0.3
Phase 5 (Qdrant / MLflow / LangServe fingerprinters)   ─── deferred to v0.4
```

Phases 3 and 5 are intentionally numbered out of execution order — they were originally planned in this sprint but moved to v0.3/v0.4 per §9.8 scope discipline. The numbering is preserved so the v0.3/v0.4 plans can reference "Phase 3 / Phase 5 of the original Sprint 3 plan" without renumbering everything.

### Phase 0 — Design review

- **Deliverable:** This document, reviewed and approved.
- **Acceptance:** Multi-label schema decision (§3.5 Option B) accepted, LiteLLM-first prioritization accepted, validator update (§6 ship-blocker) acknowledged, CFP target (§8) acknowledged.
- **Risk:** Schema decision (multi-label) gets reversed to single `AIService` kind; per-kind processor queries rewrite to property predicates, UI hex-config entries consolidate, Neo4j constraints consolidate. Mechanical cleanup — §3.5 presents both sides.

### Phase 1 — Scanner skeleton

- **Deliverables:**
  - `modules/networkscan/scanner.go` — CIDR/host expansion + bounded port sweep with a fixed-size worker pool (default 50 workers) consuming a buffered task channel. `O(workers)` goroutines regardless of target count.
  - `expandTargets` for IPv4 + IPv6, handles /N CIDRs, single hosts, file-of-hosts, DNS names.
  - CIDR cap enforcement (`--allow-large-cidr` flag).
  - Public-IP guard (`--allow-public-targets` flag) plus the §9.6 hardening: interactive "type AUTHORIZED" confirmation, `--authorization-file` alternative, scan-output watermark.
  - Returns `[]action.Target` with Meta populated. **No fingerprinting in this phase** — Meta carries `candidate_kinds` only.
  - Unit tests for expansion (CIDR sizes, IPv6, edge cases like /32, /31, /128).
  - Unit tests for public/private classification. `sdk/common/host.go` already exports `ClassifyHost(string) HostInfo` with `IsLocal`/`IsPrivate`/`IsPublic` fields covering IPv4 + RFC 1918. Phase 1 EXTENDS this file to handle: IPv6 ULA (`fc00::/7`), IPv6 link-local (`fe80::/10`), IPv6 multicast (`ff00::/8`), IPv4 link-local (`169.254.0.0/16`), and IPv4 multicast (`224.0.0.0/4`). The scanner refuses link-local and multicast outright (documented in `docs/scanner.md`).
  - `select` checking `ctx.Done()` BEFORE every `tasks <-` send so Ctrl-C does not spawn additional work.
  - `defer recover()` around each worker task body for panic isolation; logs and continues.
- **Acceptance criteria:**
  - `agenthound scan 10.0.0.0/30` returns 4 targets.
  - `agenthound scan 10.0.0.0/16 --allow-large-cidr=false` errors with the cap explanation.
  - `agenthound scan 1.1.1.1` errors without `--allow-public-targets`.
  - Race-detector-clean tests.
- **Risk:** IPv6 expansion edge cases (link-local, unique-local, multicast). Mitigation: refuse multicast and link-local entirely; document the policy.

### Phase 2 — Rules engine v2 + first Fingerprinter (Ollama)

- **Deliverables:**
  - `sdk/rules/MatcherSpec.Version: 2` extension landed (`http_status`, `http_header`, `json_path` matchers).
  - `rules/builtin/fingerprints/ollama.yaml` shipped.
  - `modules/ollamafp/fingerprinter.go` implementing `sdk/action.Fingerprinter`.
  - Integration test: a stub HTTP server emitting `{"version":"0.5.1"}` on `GET /api/version` is correctly fingerprinted.
  - CLI dispatcher: `agenthound scan 10.0.0.42` → port sweep → fingerprint dispatch → emit `AIService` node.
  - New `AIService` umbrella + `OllamaInstance` per-kind labels landed in `sdk/ingest/kinds.go` (BOTH `AllowedNodeKinds` AND `AllNodeLabels`) + Neo4j schema migration + UI rendering.
- **Acceptance criteria:**
  - `agenthound scan <stub-host>` produces ingest JSON containing one node with `kinds: ["OllamaInstance", "AIService"]`, `version=0.5.1`.
  - Server ingests the JSON with no validation errors.
  - UI displays the new node with the orange-red Ollama color.
- **Risk:** Rules-engine extension is the architecturally significant piece. Mitigation: land the `Version: 2` boundary as its own PR; fingerprint rule depends on it.

### Phase 3 — DEFERRED to v0.3

Originally planned: vLLM / Open WebUI / Jupyter fingerprinters + first emission of the `EXPOSES` edge (Open WebUI → Ollama is the canonical case). Deferred per §9.8 scope discipline.

**The `EXPOSES` edge KIND itself lands in v0.2** (added to `AllowedEdgeKinds` + `RawEdgeKinds` + `EdgeKindEndpoints` in Phase 4 alongside `EXPOSES_CREDENTIAL`) — this is a one-time schema migration we want to ship now so v0.3 doesn't need a second migration. v0.2 simply has zero collectors emitting `EXPOSES` until v0.3's fingerprinters arrive.

Numbered phases preserved so v0.3 can reference "Phase 3 of Sprint 3" cleanly.

### Phase 4 — First Looter (LiteLLM)

- **Deliverables:**
  - LiteLLM Fingerprinter (`rules/builtin/fingerprints/litellm.yaml` + `modules/litellmfp/`).
  - LiteLLM Looter (`modules/litellmloot/`).
  - `EXPOSES_CREDENTIAL` edge kind landed in BOTH `AllowedEdgeKinds` AND `RawEdgeKinds` (per the §6 SHIP-BLOCKER), plus `EdgeKindEndpoints`.
  - `agenthound loot <host> --type litellm --master-key sk-... [--include-credential-values]` CLI verb wired (replaces today's stub in `collector/cli/stubs.go`).
  - First concrete `LootResult` shape (per §4.4) — replaces the v0 `struct{}` stub in `sdk/action/looter.go`.
  - `cross_service_credential_chain` post-processor wired into `server/internal/analysis/registry.go` after `CanReach`.
  - Integration test: against a stub LiteLLM server (FastAPI with mocked `/model/info` + `/key/list`), looting produces the expected `Credential` nodes + `EXPOSES_CREDENTIAL` edges.
  - GET-only assertion in test suite (looter MUST NOT issue mutating HTTP methods).
  - Master-key redaction in slog output, with a unit test asserting the full master key never appears in logs.
- **Acceptance criteria:**
  - Stub-server loot session emits ≥3 `Credential` nodes (one per fake provider).
  - `EXPOSES_CREDENTIAL` edges connect the LiteLLM `AIService` node to each credential.
  - The credential-chain detector fires on the resulting graph.
  - Server ingests the JSON with no validation errors.
- **Risk:** LiteLLM's `/model/info` response shape differs across versions. Mitigation: parse leniently, log unknown shapes as warnings, do not fail-fast on schema drift; record partial results in `LootResult.PartialErrors`.

### Phase 5 — DEFERRED to v0.4

Originally planned: Qdrant / MLflow / LangServe fingerprinters + 8-service docker-compose lab. Deferred per §9.8 scope discipline.

### Phase 6 — Demo data + docs + UI integration

- **Deliverables:**
  - `docker/demo/docker-compose.yml` — minimal lab covering the two v0.2 service kinds (Ollama + LiteLLM). The full 8-service lab is the v0.3/v0.4 target.
  - `testdata/demo/scan_lab.json` — anonymized real-lab capture (per §10.5 recipe). NOT hand-fabricated.
  - `scripts/anonymize-scan.sh` — anonymization helper used by the demo capture pipeline.
  - `docs/scanner.md` — operator guide for the network scanner with the §9.1 legal warning at the top.
  - `docs/loot-litellm.md` — LiteLLM-specific loot guide with master-key safety notes + the §9.5 audit-trail residue caveat.
  - UI updates: 8 entries in `server/ui/src/theme/tokens.ts` (`NODE_KIND_COLORS`) and 8 entries in `server/ui/src/lib/explorer/hex-config.ts` (`HEX_CONFIG`) — 2 final (Ollama, LiteLLM), 6 stubbed for v0.3/v0.4 — so the schema is forward-compatible. Size dispatch in `server/ui/src/lib/node-styles.ts` for `:AIService`. Inspector per-kind property panels for the 2 v0.2 kinds; generic `:AIService` panel covers the others. New prebuilt query option in `server/ui/src/components/queries/` for `litellm-credential-leak`. TypeScript types in `server/ui/src/api/types.ts` for the new node shapes.
  - New pre-built query: `litellm-credential-leak` (LiteLLM `AIService` with `EXPOSES_CREDENTIAL` edges).
  - The existing 17 pre-built queries audited for breakage against the new schema.
- **Acceptance criteria:**
  - `make demo` produces a graph with the v0.2 service kinds (Ollama + LiteLLM) and ≥1 credential-chain finding.
  - Credential-chain detector fires on the demo data and surfaces in the Findings panel.
  - The new `litellm-credential-leak` query is wired and runnable from both CLI and UI.

### Phase 7 — CFP submission + talk prep + lab build

- **Deliverables:**
  - DEF CON 34 Red Team Village CFP submission. Hard deadline 2026-05-31. Primary v0.2 CFP target.
  - fwd:cloudsec EU 2026 submission (deadline 2026-06-12) — secondary, cloud-AI framing.
  - OWASP Global AppSec US 2026 SF submission (deadline 2026-06-29) — tertiary, OWASP Agentic Top 10 framing.
  - Slide deck draft.
  - Demo recording captured at 1080p, ≤8 minutes, in OBS, with the master key and any incidentally captured tokens redacted.
- **Acceptance criteria:**
  - DEF CON RTV CFP submitted by 2026-05-31.
  - fwd:cloudsec EU 2026 CFP submitted by 2026-06-12 (secondary).
  - OWASP Global AppSec US 2026 SF CFP submitted by 2026-06-29 (tertiary).
  - Demo recording captures end-to-end flow: `agenthound scan` → `agenthound loot litellm` → server graph → credential-chain finding.

### Critical scheduling tension — DEF CON Red Team Village is the new primary

The earlier May-1 / May-8 venues (DEF CON main, Demo Labs, Workshops, BSidesLV) all closed before any v0.2 implementation could ship. The new primary is **DEF CON 34 Red Team Village (RTV)**, CFP closing **2026-05-31**.

RTV is a stronger fit than the missed venues anyway: its audience is exactly AgentHound's audience — red teamers building and using offensive AI/ML tooling. The acceptance bar is "working tool walkthrough with a credible offensive use case," not "finished published research." That matches what v0.2 will plausibly look like at submission time: scanner skeleton landed, Ollama fingerprinter working, LiteLLM Looter prototype, demo lab capable of producing one credential-chain finding end-to-end.

Path forward:

1. **Submit DEF CON 34 Red Team Village by 2026-05-31.** Primary v0.2 target. Talk title proposal: "AgentHound: Mapping the Cross-Protocol Attack Surface of AI Agent Infrastructure."
2. **Submit fwd:cloudsec EU 2026 by 2026-06-12.** Secondary; cloud-AI framing. Different audience overlap.
3. **Submit OWASP Global AppSec US 2026 SF by 2026-06-29.** Tertiary; OWASP Agentic Top 10 framing on top of AgentHound's existing OWASP mapping.
4. **Track Hexacon 2026 (Oct 16–17, Paris) — CFP TBD.** Strong fit for offensive-research framing once Phase 5+6 results are in.
5. **Aim DEF CON 35 (2027) main-stage** — the real main-stage target. By then Phase 5+6+7 have shipped, the lab dataset is mature, and the talk has empirical findings to anchor on.

Closed venues for context: DEF CON 34 main-stage / Demo Labs / Workshops (closed 2026-05-01); BSidesLV 2026 breaking-ground (closed 2026-05-08); RSAC 2026 (closed 2025-08-18); Black Hat USA 2026 main briefings (closed 2026-03-20); Black Hat Arsenal (closed 2026-03-16); BSidesSF 2026 (already happened — flag for BSidesSF 2027); fwd:cloudsec NA 2026 (closed 2026-03-20); OWASP Global AppSec EU 2026 Vienna (closed 2026-02-03).

---

## 8. CFP / conference strategy

### 8.1 Target conferences (status as of 2026-05-16)

| Conference | Dates | CFP closes | Status | Track fit |
|---|---|---|---|---|
| **DEF CON 34 Red Team Village** | 2026-08-06 → 09 | **2026-05-31** | **OPEN — primary v0.2 target** | Audience match: red teamers building AI/ML offensive tooling. Acceptance bar = working-tool walkthrough with a credible offensive use case. |
| **fwd:cloudsec EU 2026** | TBD (June 2026) | **2026-06-12** | Open | Secondary. Cloud-AI angle for the European audience. |
| **OWASP Global AppSec US 2026 (SF)** | 2026-11-05 → 06 | **2026-06-29 23:59 PDT** | Open | Tertiary. AppSec audience increasingly AI-aware; AgentHound's existing OWASP MCP / Agentic Top-10 mapping is the framing. ([OWASP US 2026 CFP](https://sessionize.com/owasp-global-appsec-us-2026-cfp-SF/)) |
| **Hexacon 2026 (Paris)** | 2026-10-16 → 17 | CFP TBD as of audit time; **monitor** | Likely opens summer 2026 | Strong fit for offensive-research framing once Phase 5+6 results are in. Track and submit when open. |
| **SAINTCON 2026** | 2026-10-27 → 30 | Unverified | Unknown | Moderate fit. ([SAINTCON 2026](https://www.saintcon.org/)) |
| **DEF CON 35 (2027) main-stage** | 2027 dates TBD | TBD (typically opens Jan, closes May) | Future | The real main-stage target — by then Phase 5+6+7 have shipped and the lab dataset is mature. |
| **BSidesSF 2027** | TBD | TBD (typical CFP closes winter) | Future | Flag for the next cycle once v0.3+ ships. |
| **DEF CON 34 main stage / Demo Labs / Workshops** | 2026-08-06 → 09 | **CLOSED 2026-05-01** | Closed | N/A this cycle. |
| **BSidesLV 2026 (breaking-ground)** | 2026-08-03 → 05 | **CLOSED 2026-05-08** | Closed | N/A this cycle. |
| **Black Hat USA 2026 main briefings** | 2026-08-04 / 2026-10-07 → 08 | **CLOSED 2026-03-20** | Closed | N/A. |
| **Black Hat USA 2026 Arsenal** | 2026-08-04 | **CLOSED 2026-03-16** | Closed | N/A. |
| **OWASP Global AppSec EU 2026 (Vienna)** | 2026-06-25 → 26 | **CLOSED 2026-02-03** | Closed | N/A. |
| **fwd:cloudsec NA 2026** | passed | **CLOSED 2026-03-20** | Closed | N/A. |
| **BSidesSF 2026** | 2026-03-21 → 22 | passed | Past | N/A — see BSidesSF 2027 above. |
| **RSAC 2026** | 2026-03-23 → 26 | **CLOSED 2025-08-18** | Past | N/A. |

### 8.2 Recommended submission portfolio

Priority order:

1. **DEF CON 34 Red Team Village** — submit by **2026-05-31**. **This is the primary v0.2 target.** Talk title proposal: "AgentHound: Mapping the Cross-Protocol Attack Surface of AI Agent Infrastructure." RTV explicitly accepts working-tool walkthroughs from offensive practitioners; the demo (scanner → LiteLLM Looter → graph → credential chain) is exactly the format. The CFP submission must be honest about what's shipped vs. in flight at submission time — RTV reviewers value working code over aspirational pitches.
2. **fwd:cloudsec EU 2026** — submit by **2026-06-12**. Cloud-AI framing for a different audience. Lower acceptance volatility.
3. **OWASP Global AppSec US 2026 SF** — submit by **2026-06-29**. AppSec audience values the OWASP Agentic Top-10 mapping AgentHound already does. Framing: "OWASP Agentic Top 10 in practice — what we found scanning agent infrastructure."
4. **Hexacon 2026 (Paris)** — monitor CFP open and submit when available. Offensive-research framing once Phase 5+6 results are in.
5. **DEF CON 35 (2027) main stage** — the *real* main-stage target. By then Phase 5+6+7 have shipped, the lab dataset is mature, and the talk has empirical findings to anchor on. Plan the v0.3 milestone with this in mind.

### 8.3 Talk angle — "Mapping the Cross-Protocol Attack Surface of AI Agent Infrastructure"

**One-paragraph abstract draft:**

> Self-hosted AI infrastructure has eaten enterprise networks faster than security tooling has kept up. Ollama instances expose model weights to the internet (12,269 found in February 2026 alone). LiteLLM gateways aggregate provider API keys — OpenAI, Anthropic, Bedrock, Azure, Cohere — behind a single master credential. Once you compromise the master, the whole upstream provider stack is yours. We built AgentHound — a BloodHound-style attack-path mapper for AI agent infrastructure — and pointed it at consenting environments. This talk shows what we found: cross-protocol credential chains that span agent clients, MCP servers, A2A delegates, and exposed AI gateways, surfaced as graph paths a defender can read in seconds. We will demonstrate the live tool — `agenthound scan` to discover Ollama and LiteLLM on a lab CIDR, `agenthound loot litellm` to extract upstream provider keys, the graph showing the credential chain from agent to compromised provider — and release the v0.2 build at talk time. Vector stores, MLflow tracking servers, and notebook hosts are on the v0.3+ roadmap.

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

### 9.8 Scope creep — staged module rollout, not a big-bang sprint

**Issue.** 8 target services × 2 actions (Fingerprinter + Looter) = 16 modules. Treating all 16 as one milestone is the wrong unit of delivery — each new service kind requires a fingerprint rule, a Looter (where applicable), node-kind plumbing, UI hex-config, and demo data. Bundling 16 of those into v0.2 produces an undemoable mass; staging them produces a working tool early.

**Resolution — staged scope:**

- **v0.2:** scanner skeleton, **2** fingerprinters (Ollama + LiteLLM), **1** Looter (LiteLLM). This is the minimum that lets the credential-chain demo land end-to-end.
- **v0.3:** 3 more fingerprinters (vLLM, Open WebUI, Jupyter); 1 Looter (Ollama).
- **v0.4:** remaining 3 fingerprinters (Qdrant, MLflow, LangServe); 1 Looter (Jupyter or MLflow — chosen by which lab finding lands first).

The roadmap §7 reflects this — Phases 3 and 5 are explicitly deferred to v0.3 / v0.4.

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

- [ ] `sdk/ingest/kinds.go` contains `AIService` in `AllowedNodeKinds`. (`AIModel` deferred to v0.3 — no v0.2 emitter.)
- [ ] `sdk/ingest/kinds.go` contains `EXPOSES` and `EXPOSES_CREDENTIAL` in `AllowedEdgeKinds`.
- [ ] `EdgeKindEndpoints` covers both new edges.
- [ ] Neo4j schema migration runs cleanly on Neo4j 4.4 and 5.x (the existing version-detection path).
- [ ] The validator rejects malformed `AIService` nodes (e.g. missing `service_kind`).

### 10.3 UI acceptance

- [ ] The Graph Explorer renders the two v0.2 `AIService` node kinds (Ollama + LiteLLM) with distinct service-kind icons.
- [ ] The remaining 6 service kinds (vLLM, Qdrant, MLflow, Jupyter, LangServe, Open WebUI) have UI plumbing wired ahead of v0.3/v0.4 — entries present in `NODE_KIND_COLORS` (`tokens.ts`), `HEX_CONFIG` (`hex-config.ts`), and the legend — but no demo nodes of those kinds in the v0.2 graph.
- [ ] The Findings panel surfaces the new `litellm-credential-leak` finding.
- [ ] The Inspector shows `service_kind`, `endpoint`, `version`, `auth_method`, `is_anonymous_loot` for `AIService` nodes. Per-kind property panels for the 2 v0.2 kinds; generic `:AIService` panel for the remaining 6.
- [ ] The Legend lists all 8 service variants (the two v0.2 kinds active; the other 6 grayed-out / "v0.3+").

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
- [ ] `make demo` produces a graph with the two v0.2 service kinds (Ollama + LiteLLM, per §9.8) and ≥1 credential chain finding.
- [ ] A screen recording at 1080p, ≤8 minutes, captured in OBS (per §7 Phase 7 + §8.5), showing: scan → loot → graph → finding. The master key and any incidentally captured tokens are redacted.

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
| `sdk/ingest/kinds.go` | 1, 2, 4 | Edit | Add 8 per-kind labels + `AIService` umbrella to `AllowedNodeKinds` and `AllNodeLabels`. Add `EXPOSES`, `EXPOSES_CREDENTIAL` to BOTH `AllowedEdgeKinds` AND `RawEdgeKinds`. Add edge endpoints in `EdgeKindEndpoints`. (`AIModel` deferred to v0.3 — see Section 3.5 deferral note.) |
| `sdk/ingest/model_test.go:100,106,112,117` | 1 | Edit | Bump `TestAllowedNodeKindsComplete` 12 → 22, `TestAllNodeLabelsComplete` 14 → 24, `TestAllowedEdgeKindsComplete` 21 → 23. Add regression test asserting the new edges and per-service node labels are present in their respective maps. |
| `sdk/action/looter.go` | 4 | Edit | Replace v0 stub `LootOptions` and `LootResult` structs with concrete shapes per §4.4 (incl. `Credentials map[string]string`, `MaxItems int`, `Timeout time.Duration`, `IncludeCredentialValues bool`). Add the `LootSummary` type and the `(r *LootResult) ToIngest() *ingest.IngestData` method. Update the file-level doc comment to drop "added when the first Looter implementation lands." |
| `sdk/module/module.go` | 4 (sidecar) | Unchanged | Existing `Module` interface stays as-is (`Description`, `Version` preserved). |
| `sdk/module/flags.go` | 4 (sidecar) | NEW | Define `FlagsModule` sidecar interface (§5.4). Land only when 2nd Looter exists. |
| `sdk/module/state.go` | future | NEW | Define `StatefulModule` sidecar interface (§5.5). Defer to first Poisoner/Implanter. |
| `sdk/rules/matchers.go` | 2 | Edit | Extend `MatcherSpec` with `Version: 2` matchers (`http_status`, `http_header`, `json_path`). |
| `sdk/rules/engine.go` | 2 | Edit | Add probe orchestrator for HTTP fingerprinting (HTTP request → match against rule probes). |
| `sdk/rules/validate.go` | 2 | Edit | Validate the new matcher types under `Version: 2`. |
| `server/internal/ingest/validator.go:80` | 1 | Edit | Add new edges to RawEdgeKinds (already covered by sdk-side edit; this file's check at line 80 does not need its logic changed if RawEdgeKinds is extended). Confirm with a regression test. |
| `server/internal/graph/schema.go:13-24, 26-69, 71-77` | 1 | Edit | Three non-contiguous regions: (a) `indexDefs` slice at lines 13-24 — append per-kind indexes; (b) `InitSchema` constraint-creation loop at lines 26-69 — skip labels listed in `ingest.UmbrellaLabels` so `:AIService` does NOT get a uniqueness constraint (a duplicate constraint on a multi-labeled node would falsely collide); (c) `constraintCypher` at lines 71-77 — no syntax change, just relies on the loop's filter. Both 4.4 (`ON...ASSERT`) and 5.x (`FOR...REQUIRE`) branches inherit the filter automatically. |
| `server/internal/analysis/registry.go:5` | 4 | Edit | Append `&processors.CrossServiceCredentialChain{}` to `allProcessors()` slice (after `&processors.CanReach{}`). |
| `server/internal/analysis/processors/cross_service_credential_chain.go` | 4 | NEW | New processor: `Name() = "cross_service_credential_chain"`, `Dependencies() = []string{"has_access_to"}` plus `"can_reach"`, `Process()` runs the §3.7 Cypher path query. |
| `server/internal/analysis/processors/cross_service_credential_chain_test.go` | 4 | NEW | Smoke test on a synthetic graph. |
| `server/internal/analysis/prebuilt/litellm_credential_leak.go` | 6 | NEW | New prebuilt query: `litellm-credential-leak` (LiteLLM `:AIService` nodes with `EXPOSES_CREDENTIAL` edges). Severity: critical. OWASP: MCP03/ASI04 (credential exposure). Wires to `GET /api/v1/analysis/prebuilt/{id}` and `agenthound-server query --prebuilt litellm-credential-leak`. Brings the prebuilt count from 17 → 18. |
| `collector/cli/scan.go` | 1 | Edit | Add positional CIDR/host argument; dispatch to Scanner module when set; preserve existing flag-based mode for backwards compat. **Rename the local `--scan-output` flag (line 64) to `--output`** so the docs and the §3.8 CLI examples match what the binary actually accepts (today the persistent root `--output` is the documented form; the local `--scan-output` shadows it confusingly). Add `--allow-public-targets` + `--authorization-file` per §9.6, and the AUTHORIZED interactive prompt. Add `--network-scan-concurrency` (default 50) for the network-probe worker pool, distinct from the existing `--scan-concurrency` (default 5) which keeps governing MCP/A2A enumeration. |
| `collector/cli/loot.go` | 4 | NEW | Replace the `stubs.go` loot entry with a real `loot` cobra command. Flags: `--type litellm`, `--master-key`, `--credential KEY=VALUE`, `--include-credential-values`, `--engagement-id <ID>` (per §9.5; recorded in every log line for attribution). On first invocation, prompts for AUTHORIZED confirmation and writes `~/.agenthound/loot-acknowledged` sentinel (per §9.5). |
| `sdk/rules/bundle.go` | 4 | NEW | Versioned-rules-bundle loader (per §9.7). Reads `--rules-bundle <path>` (tar.gz or directory), overlays or replaces the embedded `sdk/rules/builtin/*.yaml` set at startup. Required before Phase 3 ships so the rules-update path doesn't depend on cutting binaries. |
| `collector/cli/scan.go` (extended) | 1 | Edit | (already enumerated above; for completeness it ALSO adds the `--allow-public-targets` AUTHORIZED prompt and `--authorization-file` per §9.6, plus scan-output watermark with `engagement_id` + authorization-file SHA-256.) |
| `collector/cli/stubs.go` | 4 | Edit | Remove `loot` from the not-implemented stub list (poison/implant/extract remain). |
| `collector/scanner/scanner.go` | 1 | Delete | Retire the `Stub` package; the real implementation lives at `modules/networkscan/` per §3.9. Any call site that references `scanner.Stub` switches to looking up the registered scanner module via `sdk/module`. |
| `modules/networkscan/` | 1 | NEW (dir) | Scanner module per §3.9 sketch (worker-pool, ctx-cancel guards, panic-recover). Includes `register.go` for self-registration. Conforms to `sdk/action.Scanner`. |
| `modules/ollamafp/` | 2 | NEW (dir) | Ollama Fingerprinter module + rule file `rules/builtin/fingerprints/ollama.yaml`. |
| `modules/litellmfp/` | 4 | NEW (dir) | LiteLLM Fingerprinter module + rule file `rules/builtin/fingerprints/litellm.yaml`. |
| `modules/litellmloot/` | 4 | NEW (dir) | LiteLLM Looter module per §4.8 sketch. Tests: GET-only assertion, master-key-redaction assertion. |
| `server/ui/src/theme/tokens.ts` | 6 | Edit | Add 8 entries to `NODE_KIND_COLORS` keyed by per-kind label. The 2 v0.2 service kinds (Ollama, LiteLLM) get final colors; the remaining 6 get placeholder colors so v0.3/v0.4 don't require theme-token edits — they only swap the placeholders for chosen colors. |
| `server/ui/src/lib/explorer/hex-config.ts:37-150` | 6 | Edit | Add 8 entries to `HEX_CONFIG`, keyed by per-kind label. Include `strokeColor`, `fillColor`, `icon`, `kindTag`, `column`, `groupLabel`. As with `tokens.ts`: 2 v0.2 entries final, 6 stubbed. |
| `server/ui/src/lib/explorer/layout.ts` | 6 | Edit | Update partition-column logic if columns shift; likely a no-op. |
| `server/ui/src/lib/node-styles.ts` | 6 | Edit | Update size switch — `:AIService` size scales with `EXPOSES_CREDENTIAL` out-degree. |
| `server/ui/src/api/scans.ts` | 6 | Possibly edit | Possible additions for new scan-type filter. Verify when wiring. |
| `docs/loot-litellm.md` | 6 | NEW | LiteLLM-specific loot guide with master-key safety notes + audit-trail residue caveat (§9.5). |
| `docs/scanner.md` | 6 | NEW | Operator guide + legal warning. |
| `testdata/demo/scan_lab.json` | 6 | NEW | Real lab capture, anonymized. NOT hand-fabricated. |
| `scripts/anonymize-scan.sh` | 6 | NEW | Anonymization helper for the lab capture. |
| `docker/demo/docker-compose.yml` | 6 | NEW | The §8.5 docker-compose lab definition. |
| `CLAUDE.md` | 6 | Edit | Add new node kinds + edge kinds to "Graph Data Model" section. (The earlier-drafted Sigma+graphology stale-doc fix is already done — no separate follow-up needed.) |

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
| 8 | §8.1 CFP table | (Historical: BSidesLV 2026-05-08 deadline now passed; superseded by the 2026-05-16 RTV refresh below.) | verifier #1 |
| 9 | §8.1 CFP table | (Historical: DEF CON 34 Demo Labs / Workshops / main-stage 2026-05-01 deadlines all passed; superseded by the RTV refresh below.) | verifier #1 |
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
| 23 | §3.5 Schema decision | Reversed the single-`AIService` recommendation. Rewrote to recommend Option B: per-service kinds (`OllamaInstance`, `VLLMInstance`, etc.) WITH multi-label `:AIService` umbrella for unified queries. Cited evidence: `sdk/ingest/kinds.go:4-17` (12 distinct labels), `server/internal/analysis/processors/has_access_to.go:20` (every processor matches by label), UI dispatches on `kinds[0]` in `server/ui/src/lib/node-styles.ts:9-14`, `theme/tokens.ts:5-20`, `lib/explorer/hex-config.ts:37-150`. | verifier #1 + verifier #2 |
| 24 | §6 Schema additions | Added explicit instruction to wire `cross_service_credential_chain` processor into `allProcessors()` at `server/internal/analysis/registry.go:5` (verified path; the user's correction said `postprocessor.go:15` but the actual location is `registry.go:5`). Declared dependencies, smoke test path. | verifier #1 |
| 25 | §6 UI integration | Replaced misleading reference to CLAUDE.md "Node Visual Encoding" with the actual UI files that change: `server/ui/src/theme/tokens.ts`, `lib/explorer/hex-config.ts`, `lib/explorer/layout.ts`, `lib/node-styles.ts`. (The earlier CLAUDE.md Sigma+graphology drift was fixed before this sprint started.) | verifier #1 + verifier #2 |
| 26 | (multiple) `docs/future-modules.md` | Verified the file exists at `/Users/akoffsec/dev/agenthound/docs/future-modules.md`. References preserved as-is — no action required. | verifier #1 |
| 27 | §9.5 Reverter contract | Rewrote from "Reverter is N/A — looting is read-only" to acknowledge audit-trail residue (LiteLLM Postgres, cloud HTTP logs, LangFuse, defender SIEMs). Added one-time interactive confirmation, `--engagement-id` flag, and `docs/loot-litellm.md` documentation as mitigations. | verifier #1 + verifier #2 |
| 28 | §9.6 (new) | Added CFAA-exposure risk: `--allow-public-targets` is one flag away. Stronger gates: interactive "type AUTHORIZED" confirmation, `--authorization-file` alternative, scan-output watermark. | verifier #1 |
| 29 | §9.7 (new) | Added maintenance-burden risk. Committed to versioned-rules-bundle path BEFORE Phase 3 ships, not as a future-template aspiration. Concrete mechanism: `--rules-bundle <path>` + signed monthly tarball releases. | verifier #1 + verifier #2 |
| 30 | §9.8 | Added scope-creep risk. v0.2 commits to scanner + 2 fingerprinters + 1 Looter; remaining services staged into v0.3 / v0.4. Phases 3 and 5 explicitly deferred. | verifier #1 + verifier #2 |
| 31 | §7 Phased roadmap | Removed effort/timeline estimates. Phases now defined by deliverables, dependency order, and acceptance criteria only — execution speed is left to the implementer. | doc-sweep audit |
| 32 | §7 Critical scheduling tension + §8.2 portfolio | (Historical: original recommendation was Demo Labs + BSidesLV; both deadlines passed before implementation could ship. Superseded by the 2026-05-16 RTV refresh below.) | verifier #1 + verifier #2 |
| 36 | §7 + §8 (2026-05-16 refresh) | Replaced the now-passed Demo Labs / BSidesLV / DEF CON main-stage targets with **DEF CON 34 Red Team Village (CFP closes 2026-05-31)** as the primary v0.2 target. fwd:cloudsec EU 2026 (2026-06-12) and OWASP Global AppSec US 2026 SF (2026-06-29) are secondary/tertiary. CFP table reorganized to show open vs. closed clearly. | doc-sweep audit |
| 37 | §3.5 + §11 line-range fixes (2026-05-16 refresh) | Corrected `tokens.ts:5-21` → `5-20` (map closes at line 20). Widened `schema.go:13-24` → `13-77` to include the constraint creation loop and the 4.4-vs-5.x version fork in `constraintCypher()` where the actual edits land. | doc-sweep audit |
| 38 | §6 + §11 stale-doc note (2026-05-16 refresh) | Removed the "CLAUDE.md still says Sigma+graphology, fix in a follow-up PR" notes. CLAUDE.md was already updated to React Flow + ELK before this sprint started; the follow-up is moot. | doc-sweep audit |
| 39 | §1 v0.2 deliverables (2026-05-16 architect review) | Replaced the now-passed Demo Labs / BSidesLV CFP citation with DEF CON RTV (closes 2026-05-31) + secondary fwd:cloudsec EU + OWASP US targets. Demo seed source updated from §8.5 8-VM lab to v0.2 2-service `docker/demo/docker-compose.yml`. | architect review |
| 40 | §6 model_test.go count bumps (architect review) | Original §6 only specified the edge-count bump (21 → 23). Added the missing node-count bumps: `TestAllowedNodeKindsComplete` 12 → 22 and `TestAllNodeLabelsComplete` 14 → 24. Without these, the build breaks the moment new labels land. | architect review |
| 41 | §3.7 + §4.5 credential merge keys (architect review) | The cross-service-credential-chain Cypher joins `(c1:Credential)` from the Config Collector to `(c1:Credential)` from the LiteLLM Looter. Without a shared merge predicate, these are two distinct nodes and the chain returns zero rows. Added `value_hash` (SHA-256 of credential value) as the cross-collector merge key; both emitters MUST populate it. | architect review |
| 42 | §11 looter.go scope (architect review) | Original §11 row only said "replace stubs"; expanded to enumerate the `LootSummary` type and the `(r *LootResult) ToIngest()` method that the file's doc comment promises. | architect review |
| 43 | §11 scanner module home (architect review) | Original §11 had two conflicting rows: edit `collector/scanner/scanner.go` AND create `modules/networkscan/`. Resolved: the `Stub` package is retired; real implementation lives at `modules/networkscan/` per §3.9. | architect review |
| 44 | §3.5 + §3.8 + §11 `--scan-output` rename (architect review) | `collector/cli/scan.go:64` registers `--scan-output` while every doc example uses `--output`. Renamed in the implementation to match documentation. | architect review |
| 45 | §3.3 + §11 scanner concurrency (architect review) | The existing `--scan-concurrency` flag (default 5) governs MCP/A2A enumeration. The plan also wanted a 50-default network-probe concurrency on the same flag, which is two contradictory semantics. Renamed the new flag to `--network-scan-concurrency` (default 50). | architect review |
| 46 | §6 + §11 `Dependencies()` (architect review) | §6 said `["has_access_to"]`, §11 said `["has_access_to", "can_reach"]`. Standardized on the latter, which matches "after CanReach" ordering in `registry.go`. | architect review |
| 47 | §3.5 + §6 + §11 umbrella label schema (architect review) | Putting `:AIService` in `AllNodeLabels` would make the constraint-creation loop in `schema.go` create a uniqueness constraint on the umbrella label — but every per-kind node also carries `:AIService`, so two nodes with different per-kind `objectid`s would falsely collide. Added `UmbrellaLabels` set in `sdk/ingest`; `schema.go` skips constraint creation for entries in that set. | architect review |
| 48 | §10.3 + §7 Phase 6 + §11 UI scope (architect review) | §10.3 said "renders eight distinct service-kind icons" while §9.8 caps v0.2 at 2 service kinds. Reworded: 2 v0.2 kinds rendered live, remaining 6 stubbed in the UI plumbing for forward-compat with v0.3/v0.4. | architect review |
| 49 | §8.3 talk abstract (architect review) | Removed the vector-database sentence (Qdrant ships in v0.4). Reframed the abstract around what v0.2 actually demos: Ollama discovery + LiteLLM Looter + cross-protocol credential chain. | architect review |
| 50 | §10.5 demo recording length (architect review) | §10.5 said "5-minute"; §7 Phase 7 + §8.5 said "≤8 minutes". Standardized on ≤8 minutes. | architect review |
| 51 | §4.6 master-key flag binding (architect review) | §4.6 said `--master-key` binds via `Module.Flags()` extension; §5.4 + §9.9 say `FlagsModule` is deferred. Reworded: `--master-key` is hard-coded on the `loot` cobra command for v0.2; the generic mechanism is `--credential KEY=VALUE`; `FlagsModule` lands when the second Looter does. | architect review |
| 52 | §3.6 + §6 EXPOSES target (architect review) | §3.6 said "EXPOSES → AIService (or other resource)"; §6 declared `TargetKinds: ["AIService"]`. Closed the door — EXPOSES is `:AIService → :AIService` only. | architect review |
| 53 | §7 Phase 3 EXPOSES ownership (architect review) | Phase 3 (deferred) was described as introducing EXPOSES, but §6/§11 land it in v0.2. Clarified: the edge KIND is reserved in v0.2 to avoid a future schema migration, but no v0.2 collector emits it; Phase 3 (v0.3) populates it. | architect review |
| 54 | §11 missing rows (architect review) | Added rows for: new `litellm-credential-leak` prebuilt query, new `sdk/rules/bundle.go` rules-bundle loader, expansion of `collector/cli/loot.go` to include `--engagement-id` + AUTHORIZED prompt + sentinel file, expansion of `collector/cli/scan.go` to include `--authorization-file` + scan-output watermark per §9.6. | architect review |
| 55 | §7 Phase 7 acceptance (architect review) | Phase 7 listed three CFP submissions but only RTV had an acceptance criterion. Added explicit acceptance bullets for fwd:cloudsec EU 2026 and OWASP Global AppSec US 2026 SF deadlines. | architect review |
| 56 | §3.5 UI dispatch precision (architect review) | "UI dispatches on `kinds[0]`" was imprecise; `node-styles.ts` uses `kinds[0]` for size but iterates `kinds` for color (first match wins). Documented the actual contract: per-kind label MUST be `kinds[0]` so size dispatch picks the right service. | architect review |
| 57 | §7 Phase 1 host.go scope (architect review) | "Reuses `sdk/common/host.go`" understated the work. The existing file covers IPv4 + RFC 1918 only. Phase 1 EXTENDS it for IPv6 ULA/link-local/multicast and IPv4 link-local/multicast, which the scanner refuses outright. | architect review |
| 58 | §7 effort/timeline removal (architect review) | All week-number / effort-estimate language removed from §7. Phases now defined by deliverables, dependency order, and acceptance criteria only — execution speed is left to the implementer. The dependency graph is what matters; the calendar isn't a contract. | architect review |
| 59 | §3.5 + §6 + §11 + §10 — `AIModel` deferred to v0.3 | The original v0.2 design reserved `AIModel` in `AllowedNodeKinds` "because adding it later requires a schema migration." During implementation the user accepted decision E in `docs/plans/v0.2-implementation.md`: defer to v0.3 with the Ollama Looter that produces the first model artifact. Adding the kind later is a five-line PR; carrying a dead schema entry confuses onboarding for an entire release cycle. v0.2 ships **9 new node kinds** (8 per-service + `AIService`), counts bumped 12→21 / 14→23 (not 22 / 24). | implementation review |
| 33 | §10.6 Documentation acceptance | Removed "Blog post or CFP submission references this milestone" from acceptance criteria — marketing fluff. Moved to Phase 7 deliverable. | verifier #1 |
| 34 | §10.5 Demo acceptance | Tightened: demo data is GENERATED via the §8.5 docker-compose lab + real scan capture + anonymization, NOT hand-fabricated. Concrete recipe added. Filename changed to `testdata/demo/scan_lab.json`. | verifier #2 |
| 35 | §11 (new) | Added "Critical files to modify" table enumerating every file that changes per phase, verified against current repo. Original §11 ("What this plan is NOT") renumbered to §12. | verifier #1 + verifier #2 |
