# AgentHound modules

Modules provide target scanning, fingerprinting, protocol and configuration collection, service collection, and action adapters for the autonomous planner.

`agenthound scan` selects modules from the current targets, credentials, service kinds, mode, and completed candidate keys. Normal and deep presets keep operator behavior consistent across modules.

Every module must:

- use the shared contact policy for AgentHound-owned connections;
- keep collection bounded and deterministic;
- return ingest V1 graph facts with observation domains and honest outcomes;
- store concrete credential material in `Credential.properties.value`;
- preserve parsed authentication schemes for planner compatibility;
- checkpoint recovery state before mutation and restore immediately;
- keep the collector dependency and size boundaries intact.

Public action interfaces live in `sdk/action`; registration lives in `sdk/module`. Planner composition lives in the collector orchestration layer.

See [Writing modules](../docs/contributing/modules.md).
