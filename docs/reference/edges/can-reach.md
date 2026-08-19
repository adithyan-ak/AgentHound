# CAN_REACH edge

`CAN_REACH` is a server-computed composite path from an AgentHound graph. It begins as inferred evidence. A same-scan differential MCP read can upgrade exactly one matching path to verified evidence.

## Variants

| Variant | Endpoints | Meaning |
|---|---|---|
| Direct MCP | `AgentInstance -> MCPResource` | Trust/server/tool/resource path. |
| MCP credential chain | `AgentInstance -> MCPResource` | Path through concrete exposed credential material used by another server. |
| Cross-protocol | `A2AAgent -> MCPResource` | Shared-host correlation hypothesis. |
| Cross-service credential | `AgentInstance -> Credential` | Reachability to a provider or virtual-key record correlated through a gateway. |

All variants carry exact evidence node and relationship IDs. Those references are the path's local identity and are persisted into the finding snapshot.

## Same-scan access proof

The collector's `credential_reach` action reads one exact MCP resource twice:

1. an unauthenticated control request must be denied;
2. an authenticated request with the selected concrete bearer must address and read that same resource.

When the differential succeeds, the artifact contains:

```text
(Credential)-[:CREDENTIAL_ACCESS_OBSERVED]->(MCPResource)
```

The raw edge includes `action_id`, `verified_at`, `proof_type=differential_resource_read`, the control and credential stages/statuses, resource-addressed booleans, and `cleanup_status=not_applicable`.

During post-processing, AgentHound upgrades a `CAN_REACH` relationship only when:

- the proof and path name the same MCPResource;
- the exact Credential ID appears in the path's `evidence_node_ids`;
- both differential stages have the required denied/allowed shape.

The upgrade sets `reach_evidence_state=verified` and confidence `1.0`, copies only generic proof properties, and updates the existing finding. It never creates a duplicate finding.

Every base `CAN_REACH` rebuild first resets evidence to inferred and removes proof and legacy campaign properties. Removing a proof therefore cannot leave stale verified state.

`PUBLIC_ACCESS_OBSERVED` remains a separate raw fact for an anonymous read. It is stripped of campaign, witness, and engagement properties.

## Interpretation

Verified means AgentHound proved that the concrete credential could read the exact resource during the scan. It does not claim that an agent autonomously invoked the resource or that every other path with the same target is valid.

Cross-protocol shared-host paths remain hypotheses unless their exact credential/resource path receives proof.

## Finding presentation

Finding detail exposes generic proof under `evidence.proof` and labels it **Verified During Scan**. It contains no scenario, campaign, engagement, witness, oracle, or publication-revision fields.
