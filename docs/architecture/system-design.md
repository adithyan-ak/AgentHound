# Architecture overview

AgentHound ships two intentionally separate binaries.

```text
compromised host                         analysis host

agenthound scan [scope]                 agenthound-server ingest scan.json
  local collection                         validate and publish
  contact policy                           Neo4j post-processing
  discovery/fingerprinting                 PostgreSQL history/findings
  service collection                       API + embedded dashboard
  local planner
  immediate cleanup
  atomic scan.json
```

The collector contains no database client, UI, server callback, or remote-ingest client. The server never participates in foothold-time planning. Operators move the plain ingest V1 artifact through their existing channel and ingest it manually.

## Collector

The public surface is `scan`, `revert`, and `version`. One scan owns the complete flow:

1. build the immutable contact policy;
2. initialize and checkpoint the artifact;
3. collect local configs, instructions, and raw credentials;
4. admit configured, local, and positional targets;
5. enumerate MCP/A2A and discover/fingerprint network services;
6. run deep service collectors;
7. rebuild lightweight planner indexes and execute deterministic candidates;
8. restore every temporary mutation immediately;
9. finalize the artifact.

The planner uses standard-library maps over graph nodes, edges, credentials, targets, and completed candidate keys. It adds no Neo4j, PostgreSQL, LLM, DAG, workflow language, or policy engine to the binary.

## Connection boundary

The scan context carries one `sdk/contact.Policy`. Target admission filters exact excluded hostnames, IPs, and CIDRs. Guarded HTTP transports and TCP dials resolve hostnames, filter concrete addresses, disable proxy bypass, and recheck redirects and derived URLs. Modules cannot opt out of the final-dial boundary.

## Artifact and recovery

The artifact remains `{meta, graph}` ingest V1. Complete action and recovery state lives under `meta.extra.scan_execution`. The same file is strictly encoded and atomically replaced after each meaningful transition. There are no engagement directories, witness files, campaign artifacts, encrypted outputs, or receipt sidecars.

`scan_execution.exclusions` records the immutable network boundary for standalone recovery. Recovery rebuilds its guarded clients from that field instead of creating an unrestricted policy.

A reversible ContextForge candidate uses an exclusive mutation lease. Recovery state is checkpointed before the write, applied state immediately after it, and restored state only after independent confirmation. Cleanup gets a detached 90-second context. Unresolved cleanup stops forward planning.

Collector coverage declarations and outcomes are validated before each checkpoint. Partial graphs remain useful evidence, but partial structured failures never become successful action outcomes. Protocol discovery persists its positive MCP/A2A observations and keeps protocol identity in target deduplication.

## Graph proof

The collector emits `CREDENTIAL_ACCESS_OBSERVED` for a successful unauthenticated-denied/authenticated-allowed read of the exact MCPResource. Server post-processing correlates the exact Credential and resource against a current `CAN_REACH` path, upgrades that relationship in place, and exposes generic proof as `evidence.proof`.

## Server and dashboard

The server retains ingest validation, normalization, graph writes, reconciliation, post-processors, risk scores, findings, scan history, triage, rules, queries, and file import. Complete execution data is stored in `metadata.artifact_extra.scan_execution`; a bounded summary is promoted to `metadata.scan_execution` for scan history.

The dashboard changes only where the collector contract changes: same-scan proof wording, execution summary, the new proof edge, and masking/reveal/copy for exact Credential `value`. Navigation and analysis workflows remain intact.
