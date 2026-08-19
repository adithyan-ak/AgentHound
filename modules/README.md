# AgentHound modules

Modules supply scanners, fingerprinters, protocol/config collectors, service collectors, and the internal ContextForge reversible adapter used by the autonomous planner.

The operator does not select modules. `agenthound scan` fingerprints targets, dispatches applicable collection, reuses compatible credentials, and executes eligible proof actions using fixed normal/deep presets.

Public extension interfaces live under `sdk/action`; registration metadata lives under `sdk/module`. The collector's lightweight `PlannerAction` composes those capabilities without a workflow engine or database.

Requirements:

- use the shared contact policy for every connection;
- keep collection bounded and deterministic;
- return ingest V1 graph facts with observation domains;
- store concrete credential material in `Credential.properties.value`;
- never add module-specific CLI flags;
- use the scan artifact journal before any mutation and clean up immediately.

See [Writing modules](../docs/contributing/modules.md).
