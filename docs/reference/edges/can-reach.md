# CAN_REACH Edge

The `CAN_REACH` composite edge is AgentHound's primary reachability finding. It
records an inferred path or correlation from an agent to a resource or
credential reference. It is not, by itself, proof of a successful end-to-end
invocation. An exact credential-reach campaign can upgrade one matching
agent-to-resource edge to verified evidence.

---

## Semantics

Current processors emit these endpoint shapes:

| Variant | Endpoints | Meaning |
|---------|-----------|---------|
| Direct MCP | `AgentInstance -> MCPResource` | Inferred trust/server/tool/resource path |
| MCP credential chain | `AgentInstance -> MCPResource` | Inferred path through an observed exposed credential used by another server |
| Cross-protocol host correlation | `A2AAgent -> MCPResource` | 50%-confidence shared-host hypothesis; not an invocation bridge |
| Cross-service credential chain | `AgentInstance -> Credential` | Reachability to a provider or virtual-key credential record after a master-key correlation; finding evidence determines whether the target is observed material or reference-only |

---

## Computation

The `can_reach` post-processor runs after `auth_strength` and `has_access_to`
and produces two variants:

### Direct Path (3 hops)

```cypher
MATCH (a:AgentInstance)-[ts:TRUSTS_SERVER]->(s:MCPServer)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
MERGE (a)-[e:CAN_REACH]->(r)
SET e.hops = 3,
    e.via_server = s.name,
    e.via_tool = t.name,
    e.confidence = CASE WHEN ts.effective_risk_weight <= 0.1 THEN 1.0
                        WHEN ts.effective_risk_weight <= 0.3 THEN 0.8
                        ELSE 0.5 END
```

Confidence decreases as the trust edge auth strengthens — a server behind mTLS is harder to abuse than one with no auth.

### Credential Chain (6 hops)

```cypher
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s1:MCPServer)-[:PROVIDES_TOOL]->(t1:MCPTool)
WHERE ANY(cap IN t1.capability_surface WHERE cap IN ['file_read', 'credential_access'])
MATCH (s2:MCPServer)-[:AUTHENTICATES_WITH]->(i:Identity)-[:USES_CREDENTIAL]->(c:Credential)
MATCH (s2)-[:PROVIDES_TOOL]->(t2:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE s1 <> s2
  AND (
    (s1.effective_auth_assurance = 'unauthenticated'
      AND s1.effective_auth_source = 'observed')
    OR s1.effective_auth_assurance = 'weak'
  )
  AND c.value_hash IS NOT NULL AND c.value_hash <> ''
  AND c.merge_key = 'value_hash'
  AND c.identity_basis = 'value_hash'
  AND c.material_status = 'observed'
  AND c.exposure_status = 'exposed'
```

This variant models: "agent has a tool that can read credentials, and observed,
exposed credential material authenticates to a second server with access to
additional resources." The canonical identity topology applies to every config
location; `HAS_ENV_VAR` is only optional location evidence and is not required.
An unauthenticated first server is eligible only when its effective auth source
is an accepted runtime observation. Configured weak authentication remains
eligible, while a configured no-auth claim without runtime proof does not.
Fixed confidence: 0.6.

---

## Cross-Protocol Variant

The `cross_protocol` post-processor emits a separate `CAN_REACH` edge with `cross_protocol = true`:

```cypher
MATCH (ext:A2AAgent)-[:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[:RUNS_ON]->(h:Host)<-[:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE ext.effective_auth_assurance = 'unauthenticated'
  AND ext.effective_auth_source = 'observed'
  AND ext.effective_auth_evidence = 'anonymous_probe_succeeded'
```

This models a runtime-confirmed anonymous A2A agent delegating through a chain
that lands on the same host as an MCP server — host correlation bridges the
protocol boundary. A missing auth tuple or configured no-auth claim alone does
not satisfy the correlation. Host co-location remains a hypothesis, not proof
that the A2A caller invoked the MCP resource.

---

## Cross-Service Credential Variant

The `cross_service_credential_chain` processor correlates an observed Config
Collector credential with the operator-supplied LiteLLM master key using the
same canonical `value_hash`. It then emits:

```text
(AgentInstance)-[:CAN_REACH]->(Credential)
```

The target is a provider or virtual-key credential record exposed by the same
gateway. Provider rows are masked identity references and virtual-key rows are
hashed references, so this edge normally represents reference reachability, not
possession of usable plaintext. The findings layer upgrades severity and wording
only when the target independently carries observed, usable material.

---

## Edge Properties by Variant

All variants carry `scan_id`, `last_seen`, `is_composite=true`,
`source_collector`, `confidence`, `risk_weight`, and exact-witness references
(`evidence_version`, `evidence_node_ids`, and `evidence_relationship_ids`).
Variant-specific properties are:

| Variant | Confidence | Properties |
|---------|------------|------------|
| Direct MCP | `0.5`, `0.8`, or `1.0` from effective trust weight | `hops=3`, `via_server`, `via_tool` |
| MCP credential chain | `0.6` | `hops=6`, `via_credential` |
| Cross-protocol | `0.5` | `cross_protocol=true`, `via_mcp_server`, `via_mcp_tool`, `via_host` |
| Cross-service credential | `0.95` | `hops=6`, `via_server`, `via_credential`, `via_gateway`, `merge_value_hash`, `upstream_provider`, `evidence_synthetic_edge` |

The findings layer, not the relationship itself, derives presentation fields
such as `variant` and `evidence.state`. An exact `cred-reach` campaign can set
`reach_evidence_state=verified`, attach bounded verification metadata, and raise
one matching resource edge's confidence to `1.0`.

---

## Operator Guidance

1. Sort CAN_REACH findings by target resource sensitivity (critical > high > medium).
2. Prioritize paths where the agent's trust edge has
   `effective_risk_weight <= 0.1` (runtime-confirmed no auth).
3. Treat cross-protocol paths (`cross_protocol = true`) as host-correlation hypotheses until validated.
4. Distinguish observed credential material from masked/hashed references before assigning exposure impact.

---

## OWASP Mapping

| ID | Name |
|----|------|
| MCP04 | Tool Poisoning / Privilege Escalation |
| MCP09 | Improper Access Control |
| ASI02 | Excessive Agency |
| ASI05 | Improper Access Control |
