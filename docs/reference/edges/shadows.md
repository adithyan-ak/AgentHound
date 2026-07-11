# SHADOWS

**Type:** Composite (post-processor generated)  
**Direction:** `MCPTool → MCPTool`  
**Depends on:** Raw edges only  
**Severity:** High  
**OWASP:** MCP02 (Tool Description Manipulation), ASI06 (Tool Shadowing)

## What it means

One MCP tool's description references another tool by name or describes overlapping functionality — potentially tricking an agent into calling the shadowing tool instead of the legitimate one. This is the "tool shadowing" attack: a malicious server registers a tool with a description that mimics a trusted tool, causing the agent's planner to route requests to the attacker's implementation.

## How it's computed

The `shadows` post-processor emits a target-specific edge from `t1` to `t2` when `t1`'s description literally names `t2`, across two different servers:

1. Enumerate every `(t1, t2)` where `t1` and `t2` belong to different `MCPServer`s (same-server tools can't shadow each other — the agent already trusts both).
2. Require `t2.name` to be non-null and `t1.description` to be non-null.
3. Emit a `SHADOWS` edge iff `toLower(t1.description) CONTAINS toLower(t2.name)`.

The match is a plain lowercased substring test — no TF-IDF, no cosine similarity, no `tool_name:` / endpoint parsing. The target-specificity (t1 has to name t2) is load-bearing: an earlier version of the processor OR-ed in `t1.has_cross_references`, but that flag is target-blind — a single tool that referenced any sibling made it shadow every tool on every other server, a cartesian false-positive blow-up. `has_cross_references` still feeds tool-level risk scoring (`server/internal/analysis/riskscore/tool.go`); it just no longer manufactures `SHADOWS` edges.

## Cypher example

```cypher
MATCH (shadow:MCPTool)-[:SHADOWS]->(legit:MCPTool)
MATCH (shadow)<-[:PROVIDES_TOOL]-(evil:MCPServer)
MATCH (legit)<-[:PROVIDES_TOOL]-(good:MCPServer)
RETURN shadow.name AS shadowing_tool, evil.name AS malicious_server,
       legit.name AS legitimate_tool, good.name AS trusted_server
```

## What an operator does with it

Tool shadowing is a supply-chain attack on agent behavior:
1. Identify which agent trusts the shadowing server (via TRUSTS_SERVER)
2. Check if the shadowing server was added recently (supply-chain compromise)
3. Compare the two tool descriptions side-by-side — is the shadow an exact copy or a subtle modification?
4. Remediate: remove the malicious server from the agent's config, or pin the trusted tool by server+name

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `confidence` | float | `0.9` when the shadowing tool also has `has_injection_patterns=true`, else `0.6`. |
| `risk_weight` | float | Fixed `0.4`. |
| `is_composite` | bool | `true`. |
| `source_collector` | string | `mcp`. |
| `scan_id`, `last_seen` | string | Standard edge provenance. |

## Second pass: `POISONS_CONTEXT`

The same processor runs a second Cypher pass that emits `POISONS_CONTEXT` edges. This is the deliberate widening of the narrow `SHADOWS` guard above: an injection-bearing tool can poison the shared agent context that drives a high-capability sibling tool even without naming it. It is documented here because both edges are produced by the `shadows` processor in one invocation.

**Rule.** For every `AgentInstance a` that trusts both a source tool `src` (with `has_injection_patterns = true`) and a sink tool `snk` (with a capability in `{shell_access, code_execution, credential_access, email_send}`), and `src <> snk`, emit `(src)-[:POISONS_CONTEXT]->(snk)`. Both `src` and `snk` are reached via `a-[:TRUSTS_SERVER]->MCPServer-[:PROVIDES_TOOL]->MCPTool` — scoping to a single agent is what stops the two MATCH clauses from forming a cross-tenant global cross-product.

**Fan-out cap.** Per `(agent, source)` pair, at most 20 sinks are materialized. When more than 20 eligible sinks co-reside, the first 20 by `snk.objectid` (stable across runs) are kept — the cap truncates, it does not suppress the whole group, so an attacker cannot silence the finding by registering a 21st sink. Grouping by `(a, src)` (not `src` alone) is load-bearing: keying on `src` alone would union sink sets across agents and re-globalize the cap. The `poisons_context_perf_integration_test.go` regression guards the per-source cap; `scripts/perf-check.sh` enforces the downstream ≤200 pairs-per-agent operator heuristic (10 sources × 20).

**Properties on `POISONS_CONTEXT`.** `confidence = 0.6`, `risk_weight = 0.4`, `is_composite = true`, `source_collector = 'mcp'`, plus standard `scan_id` / `last_seen`.
