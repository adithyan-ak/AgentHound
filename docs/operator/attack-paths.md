# Attack paths

After ingest, AgentHound combines collector observations with server-side analysis to show how trust, credentials, tools, resources, and protocols connect. Raw graph evidence remains distinguishable from inferred paths and same-scan proof.

## Evidence states

| State | Interpretation |
|---|---|
| `observed_signal` | A collector directly observed the fact represented by the finding. |
| `inferred` | Current graph evidence supports a deterministic analysis path. |
| `verified` | The scan proved exact credential access to the target MCP resource. The dashboard labels this **Verified During Scan**. |
| `hypothesis` | The relationship is a bounded correlation that requires operator validation. |
| `reference_only` | The graph contains a masked, hashed, or otherwise non-executable reference. |
| `unknown` | Available evidence cannot support a stronger classification. |

Verification applies to the exact credential-to-resource read. It does not claim that every upstream agent invocation or downstream impact occurred.

## Main path families

| Family | Primary edges | Question answered |
|---|---|---|
| Reachability | `HAS_ACCESS_TO`, `CAN_REACH` | Which resources or credentials can an agent reach through current trust and capability evidence? |
| Credential chains | `CAN_REACH` with credential-path properties | Where does observed credential reuse connect services? |
| Execution | `CAN_EXECUTE` | Which tools expose shell or code execution on a host? |
| Exfiltration | `CAN_EXFILTRATE_VIA` | Where can sensitive access combine with an outbound channel? |
| Tool and instruction integrity | `SHADOWS`, `POISONED_DESCRIPTION`, `POISONED_INSTRUCTIONS`, `POISONS_CONTEXT` | Which descriptions or instruction sources can steer privileged behavior? |
| Untrusted data flow | `TAINTS`, `IFC_VIOLATION` | Can attacker-controlled input reach a compatible or high-impact tool? |
| A2A trust | `CAN_IMPERSONATE`, `CONFUSED_DEPUTY`, cross-protocol `CAN_REACH` | Where can delegation, similarity, weak authentication, or host correlation cross boundaries? |

The [Graph Model](../reference/graph-model.md) lists every node and edge. [Server Analysis](../architecture/server-analysis.md) explains when composite edges are rebuilt.

## Reachability

A typical MCP resource path is:

```text
AgentInstance -TRUSTS_SERVER-> MCPServer
              -PROVIDES_TOOL-> MCPTool
              -HAS_ACCESS_TO-> MCPResource
```

The server materializes this as an `AgentInstance -CAN_REACH-> MCPResource` edge with the supporting node IDs, hop count, confidence, and evidence state.

Credential paths join only concrete material with the same `Credential.value_hash`. Masks, provider references, unresolved values, and identity-only records remain context rather than executable secrets. `Credential.blast_radius` reports how many distinct agents correlate with the observed material.

Useful queries:

```bash
agenthound-server query --prebuilt credential-chain
agenthound-server query --prebuilt shortest-to-database
agenthound-server query --prebuilt agents-shell-access
agenthound-server query --prebuilt litellm-credential-leak
```

## Same-scan access proof

For an eligible MCP resource, the collector performs an anonymous control read first. A successful exact read records public access without presenting a credential. Otherwise, the collector follows with an authenticated read; a denied control plus an allowed authenticated read emits:

```text
Credential -CREDENTIAL_ACCESS_OBSERVED-> MCPResource
```

During analysis, AgentHound requires the exact Credential and MCPResource to occur in an existing `CAN_REACH` evidence path. The matching edge is upgraded to confidence `1.0` and evidence state `verified`. The proof strengthens that finding in place and does not add a second risk item.

## Cross-protocol correlations

An A2A delegation path and an MCP service recorded on the same host can produce a cross-protocol `CAN_REACH` hypothesis. This relationship carries 0.5 confidence because host co-location does not prove that the A2A actor can invoke the MCP service.

```bash
agenthound-server query --prebuilt cross-protocol-paths
```

Validate process isolation, identities, authorization, and an authorized end-to-end call before treating the correlation as exploitable.

## Findings and traversal

List findings from the published projection:

```bash
agenthound-server query --findings
agenthound-server query --findings --severity high --format json
agenthound-server query --findings --fail-on high
```

Find a directed security path:

```bash
agenthound-server query --shortest-path \
  --from AgentInstance:operator-agent \
  --to MCPResource:customer-records
```

Use `--path-mode topology` only when investigating undirected graph connectivity. Security mode follows directed policy relationships and is the correct default for attack-path reasoning.

The REST equivalents are documented in the [API reference](../reference/api.md). Finding detail includes the persisted evidence subgraph used at publication time, so later graph changes do not silently rewrite the explanation of an existing finding.
