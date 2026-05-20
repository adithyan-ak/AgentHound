# `agenthound loot --type litellm` — LiteLLM Looter operator guide

> **Authorized engagements only.** Looting a LiteLLM gateway with the master key extracts upstream provider credentials (OpenAI, Anthropic, AWS Bedrock, Azure, Cohere keys behind the master) AND leaves a clear audit trail in the gateway's Postgres backend, LangFuse instrumentation (if present), and any defender SIEM watching the proxy. Coordinate with the target's IR/security team out-of-band BEFORE running this against production. The first `agenthound loot` invocation on a machine triggers an interactive `AUTHORIZED` prompt and writes a sentinel file (`~/.agenthound/loot-acknowledged`) to record the acknowledgement.

The LiteLLM Looter is the v0.2 marquee action — the first concrete `Looter` against a high-leverage target. A single LiteLLM master key compromise yields aggregated provider credentials for every upstream the gateway proxies. This is what lights up the credential-chain finding in the AgentHound graph.

---

## What the looter does

Three GET-only HTTP probes against a fingerprinted LiteLLM gateway:

1. **`GET /model/info`** (master-key authenticated) — lists every upstream provider model the gateway proxies, including `litellm_params.api_base` and (when LiteLLM exposes it) `litellm_params.api_key`. Emits one `:Credential` node per provider with `type=apiKey`, `provider=openai|anthropic|aws_bedrock|...`, `value_hash` populated.

2. **`GET /key/list`** (master-key authenticated) — enumerates virtual keys with their spend and model allowlist. Emits one `:Credential` node per virtual key with `type=virtual_key`. Failure here (common — many production deployments restrict `/key/list`) does not abort the loot; it lands in `LootResult.PartialErrors` and the looter continues.

3. **The master-key Credential itself** — emitted unconditionally as the FIRST node, with `value_hash = HashCredentialValue(master_key)`. This is the cross-collector merge primitive: if the same secret appears as `LITELLM_MASTER_KEY` in an MCP config, the Config Collector emits a `:Credential` with the same `value_hash`, and the `cross_service_credential_chain` post-processor joins the two sides into a credential-chain finding.

All emissions land in a single `EXPOSES_CREDENTIAL` star: the `:LiteLLMGateway:AIService` node points at every emitted `:Credential` with edge evidence `{endpoint, source, engagement_id}`.

The looter is read-only by contract. A regression test (`modules/litellmloot/get_only_test.go`) asserts only `GET` and `HEAD` requests are issued. Any future probe that mutates state on the target — POST, PUT, DELETE — must be a Poisoner module, not an addition to this Looter.

---

## Quick start

```bash
# First invocation triggers AUTHORIZED prompt + writes ~/.agenthound/loot-acknowledged.
agenthound loot 10.0.0.10:4000 --type litellm \
    --master-key sk-ENGAGEMENT-MASTER-KEY \
    --engagement-id RTV-DEMO-2026-001 \
    --output -

# Subsequent invocations skip the prompt (sentinel exists).
agenthound loot 10.0.0.10:4000 --type litellm \
    --master-key sk-... --engagement-id ENG-002 --output ./loot.json

# Stream straight into the analysis server.
agenthound loot 10.0.0.10:4000 --type litellm \
    --master-key sk-... --engagement-id ENG-003 --output - | \
    agenthound-server ingest -

# Generic --credential form (works for any future Looter without per-module flags).
agenthound loot 10.0.0.10:4000 --type litellm \
    --credential master_key=sk-... --engagement-id ENG-004
```

---

## Flags

| Flag | Required | Default | Notes |
|------|----------|---------|-------|
| `--type litellm` | Yes | — | Module dispatcher key. Resolves via `module.GetByTarget("litellm", action.Loot)`. |
| `--master-key sk-...` | One of | — | Sugar for `--credential master_key=...`. |
| `--credential KEY=VALUE` | One of | — | Generic per-module credential form, repeatable. The LiteLLM Looter reads `master_key`. |
| `--engagement-id <id>` | Recommended | empty | Recorded in every emitted edge's evidence map and on every slog line. Coordinate with target IR for attribution. |
| `--include-credential-values` | No | `false` | When `false` (default), Credential nodes carry `value_hash` only — the raw value is omitted. When `true`, the raw `value` property is also populated. The hash is always populated. |
| `--max-items <n>` | No | 1000 | Caps emitted Credential nodes per category. |
| `--output <path>` | No | `./loot-<scan_id>.json` | Use `-` for stdout. |
| `--timeout <duration>` | No | 30s | Total probe timeout. |

---

## Audit-trail residue caveat

Looting LiteLLM is not invisible. Every probe shows up in:

- **LiteLLM's Postgres backend** — every authenticated request is logged with the master key prefix, the requesting IP, the response status, and the response body length.
- **Cloud HTTP access logs** — if the gateway sits behind a load balancer (ALB, Cloud Run, Cloudflare), every probe is in the access log.
- **LangFuse instrumentation** — if the gateway emits LangFuse events for `/model/info` or `/key/list`, those events show up in the LangFuse trace store with the master key's session ID.
- **Defender SIEMs** — if the operator's SOC ships LiteLLM logs to a SIEM, the loot session appears as a single-source burst of admin-API calls. Splunk/Datadog rules that alert on master-key-from-new-IP will fire.

The `--engagement-id` flag is the load-bearing operational mitigation. Communicate it to the target's IR team out-of-band BEFORE running. Then when the SOC sees the burst and pages someone, the engagement-id in the slog output (and on every emitted edge's evidence) is the correlation key that lets IR confirm "yes, this is the authorized assessment, not an incident." Without an engagement-id you have a non-zero chance of triggering a real incident response.

The looter does NOT scrub master keys from slog output — it redacts to an 8-character prefix (`sk-ENGAG...`). The full master key never appears in stdout, stderr, or the emitted JSON unless `--include-credential-values` is set. A regression test (`modules/litellmloot/redaction_test.go`) asserts the full master key never appears in slog across any code path.

---

## What the cross-collector chain does with this output

The graph after a successful `agenthound loot --type litellm` run contains:

```
(:LiteLLMGateway:AIService) -[EXPOSES_CREDENTIAL]-> (:Credential type=master_key, value_hash=H1)
(:LiteLLMGateway:AIService) -[EXPOSES_CREDENTIAL]-> (:Credential type=apiKey, provider=openai, value_hash=H2)
(:LiteLLMGateway:AIService) -[EXPOSES_CREDENTIAL]-> (:Credential type=apiKey, provider=anthropic, value_hash=H3)
(:LiteLLMGateway:AIService) -[EXPOSES_CREDENTIAL]-> (:Credential type=virtual_key, value_hash=H4)
```

If you previously ran the Config Collector against an MCP client config that referenced the master key by env var (e.g. `LITELLM_MASTER_KEY` in `claude_desktop_config.json`), the Config Collector emitted:

```
(:MCPServer) -[HAS_ENV_VAR]-> (:Credential value_hash=H1)  // SAME hash as master Credential above
```

The `cross_service_credential_chain` post-processor joins on `value_hash`, walks `(:AgentInstance)-[:TRUSTS_SERVER]->(:MCPServer)-[:HAS_ENV_VAR]->(c1)` and matches `c1.value_hash` to a master `:Credential` exposed by a `:LiteLLMGateway`, then emits `(:AgentInstance)-[:CAN_REACH]->(c2)` for every upstream provider Credential `c2` the gateway exposes.

The pre-built `litellm-credential-leak` query surfaces this finding in the UI:

```bash
curl -s localhost:8080/api/v1/analysis/findings | \
    jq '.[] | select(.processor=="cross_service_credential_chain")'
```

The result is a one-line agent → MCPServer → env-var-cred → LiteLLM master → upstream OpenAI/Anthropic/Bedrock provider key path that is otherwise invisible to single-collector tools.

---

## Operational notes

**`/key/list` 401 is normal.** Many production LiteLLM deployments scope down master-key permissions or disable the endpoint entirely. The looter records the 401 in `PartialErrors` and continues with the `/model/info` results.

**`/model/info` shape varies across LiteLLM versions.** The looter parses leniently — unknown fields are ignored, missing `litellm_params.api_key` falls back to a synthesized `value_hash` over `(provider, model_name)` so the upstream Credential node is still deterministic across re-runs. Schema drift produces no Credential nodes; partial drift produces fewer.

**Synthetic value_hash for unknown upstream values.** When LiteLLM's `/model/info` does NOT expose the actual upstream key (the common case — most production deployments mask it), the looter still emits a `:Credential` node with `value_hash = HashCredentialValue(provider + ":" + model_name)`. This means the upstream Credential node is identifiable across re-runs but the cross-collector chain join only fires for the master key (which the operator supplied) — not for the masked upstream keys themselves. Reasoning: a synthetic hash for upstreams keeps the graph node-stable; a real cross-collector merge for upstreams would require the operator to supply each upstream value, which they don't have (that's the point of master-key compromise).

**`--include-credential-values=true` audit-mode.** The default loot is hash-only. With this flag, raw values land in the `value` property on every `:Credential` node. Use this for engagements where the deliverable explicitly includes the credentials themselves (e.g. internal red-team handoff to remediation). The cross-collector chain works the same way either way — `value_hash` is always populated.

**Engagement-id is recorded everywhere.** Every edge's evidence map carries it; every slog line carries it; the top-level `meta.extra.engagement_id` carries it. After-the-fact attribution works regardless of which surface the SOC inspects first.

---

## See also

- [`docs/scanner.md`](scanner.md) — the network scanner that discovers the LiteLLM gateway in the first place.
- `modules/litellmloot/looter.go` — implementation reference.
- `server/internal/analysis/processors/cross_service_credential_chain.go` — the post-processor that consumes this output.
- [`docs/plans/sprint3-offensive-primitives.md`](plans/sprint3-offensive-primitives.md) Sections 4 and 9.5 — design rationale and audit-trail residue analysis.
