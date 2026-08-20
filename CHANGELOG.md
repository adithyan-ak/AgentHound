# Changelog

## Unreleased

## 1.1.0 — Autonomous Collector

AgentHound 1.1 provides one autonomous scan workflow for foothold-time collection and verification.

- `agenthound scan [host|CIDR|@targets-file]` always performs local collection and can add explicit network scope.
- Active mode captures concrete credentials, reuses compatible material, proves exact MCP resource access, and runs eligible reversible ContextForge round trips.
- `--stealth` keeps network work read-only; `--deep` adds recursive instruction collection, Qdrant payload sampling, expensive probes, and bounded Ollama embedding verification.
- One contact policy enforces hostname, IP, CIDR, DNS, redirect, derived-URL, cleanup, and final-dial exclusions.
- Invalid positional targets fail before configured enumeration; fully excluded scopes produce not-applicable outcomes and partial CIDRs scan their admitted remainder.
- The lightweight local planner re-evaluates deterministic candidates as new targets and credentials appear.
- Concrete secrets are stored in `Credential.properties.value`, deduplicated by `value_hash`, and printed once unless quiet mode is enabled.
- One ingest V1 JSON artifact carries graph evidence, execution state, action outcomes, exclusions, and recovery records.
- Reversible mutations checkpoint original state, restore immediately, and support `agenthound revert <scan.json>` for unresolved recovery.
- Service collection covers LiteLLM, Open WebUI, Jupyter, Qdrant, MLflow, Ollama, MCP, and A2A with normal and deep presets.
- `agenthound-server ingest` publishes the artifact into Neo4j and PostgreSQL for graph paths, findings, risk, scan history, triage, rules, queries, and dashboard inspection.
- Differential credential proof emits `CREDENTIAL_ACCESS_OBSERVED` and upgrades only the exact matching `CAN_REACH` path to **Verified During Scan**.
- The dashboard masks Credential `value` properties by default and provides Reveal and Copy controls.
