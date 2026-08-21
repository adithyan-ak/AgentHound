# Server analysis

`agenthound-server ingest` turns a complete collector artifact into a published graph revision and a stable set of findings.

## Ingest lifecycle

1. Strictly decode and validate the ingest V1 envelope.
2. Normalize identities, property semantics, coverage declarations, and observation domains.
3. Create a PostgreSQL scan record and mark the projection as updating.
4. Scope and merge raw nodes and edges into Neo4j.
5. Reconcile complete collection domains while retaining partial evidence honestly.
6. Retire the current composite epoch and run the registered processors in dependency order.
7. Compute node risk bounds and materialize findings.
8. Persist the exact evidence subgraph for every finding.
9. Publish the Neo4j projection and PostgreSQL finding set as one revision.

A failed or incomplete analysis does not replace the last coherent published projection. Scan history records collection, graph, analysis, snapshot, projection, and publication state separately.

## Processor order

The registry runs:

```text
auth_strength
HAS_ACCESS_TO
CAN_EXECUTE
SHADOWS and POISONS_CONTEXT
POISONED_DESCRIPTION
instruction integrity (`INSTRUCTION_SIGNAL` and `POISONED_INSTRUCTIONS`)
TAINTS
CAN_REACH
cross_service_credential_chain
IFC_VIOLATION
CAN_EXFILTRATE_VIA
CAN_IMPERSONATE
CONFUSED_DEPUTY
cross-protocol CAN_REACH
risk scoring
```

Processors consume current raw evidence and write composite edges for the new epoch. Complete authoritative collection can retire absent children; targeted, partial, failed, or truncated collection cannot claim absence.

## Proof upgrade

`CREDENTIAL_ACCESS_OBSERVED` records an anonymous-denied/authenticated-allowed read of one MCP resource. The `CAN_REACH` processor upgrades a path only when that exact resource and Credential ID occur in its evidence node set. The result carries confidence `1.0`, evidence state `verified`, and the bounded fields exposed as `evidence.proof`.

Every base rebuild starts from inferred evidence, so a later current projection without the proof cannot retain a stale verified state.

## Instruction projection

The instruction processor reads only validated structured evidence. A signal in any scope, or a poisoning verdict from recursive deep collection, becomes medium `INSTRUCTION_SIGNAL`. A poisoning verdict in an exact project or user instruction scope becomes high `POISONED_INSTRUCTIONS`. The projections are mutually exclusive and include the InstructionFile as exact evidence.

Finding construction parses the evidence again from the immutable snapshot and exposes it only on finding detail. Instruction projections do not create `LOADS_INSTRUCTIONS`; agent exposure and risk require that observed raw relationship independently.

## Findings and publication

Findings are deterministic projections of composite edges. Their fingerprint remains stable across scans so triage can follow the same issue. Each published finding stores:

- severity, category, title, and affected endpoints;
- confidence, variant, evidence state, and optional proof;
- OWASP and MITRE ATLAS mappings;
- the exact node and edge evidence selected during analysis;
- any triage state keyed by fingerprint.

Normal graph, finding, posture, scan-history, rule, and prebuilt-query reads use the published projection. This keeps a dashboard session internally consistent while a later ingest is still processing.
