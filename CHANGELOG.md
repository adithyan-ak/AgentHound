# 🐕 AgentHound Changelog

## Unreleased

## v1.0.1 — 🚀 First Supported Public Release (2026-07-22)

AgentHound v1.0.1 is the first supported public release of an offensive
security framework built specifically for AI agent infrastructure. It brings
the relationship-driven analysis of an attack graph to MCP, A2A, agent
configuration, model infrastructure, credentials, tools, resources, and
instruction supply chains—then lets operators validate predicted paths against
real systems with evidence-backed, reversible workflows.

> **From observation to proof.** Discover the agentic estate, reveal the paths
> that matter, and validate them against real infrastructure.

| 🗺️ Discover | 🧠 Correlate | 🎯 Validate | 🔎 Investigate | 📦 Ship |
|---|---|---|---|---|
| MCP, A2A, configs, AI services | Temporal attack graph | Reversible campaigns | Evidence-backed UI | Signed multi-platform artifacts |

### 🗺️ Map the agentic attack surface

- **One graph across the agentic stack.** Model agents, MCP servers, tools,
  prompts, resources, A2A agents, AI services, credentials, instruction files,
  hosts, models, and their trust relationships in one temporal attack graph.
- **Broad local configuration coverage.** Discover MCP and agent configuration
  across Claude Desktop, Claude Code, VS Code, Windsurf, Continue, Zed, Cline,
  JetBrains, Kiro, Amazon Q, and Augment, including nested project rules and
  instruction files.
- **Protocol-aware MCP and A2A collection.** Enumerate live MCP capabilities
  through the official SDK and ingest A2A v0.3 and v1.0.1 Agent Cards with
  schema-aware parsing, interface preservation, authentication requirements,
  and bounded JWS verification.
- **Port-neutral AI service discovery.** Fingerprint Ollama, Open WebUI,
  LiteLLM, vLLM, LangServe, MLflow, Qdrant, and Jupyter from observed protocol
  behavior rather than assuming a service from its port number.
- **Evidence-backed inventory.** Read-only looters cover LiteLLM, Ollama,
  Open WebUI, MLflow, Qdrant, and Jupyter while distinguishing verified
  anonymous access, authenticated access, partial inventory, and unknown state.

### 🧠 Turn observations into defensible attack paths

- **Deterministic cross-collector identity.** Content-addressed node IDs merge
  the same infrastructure across collectors, while stable credential hashes
  correlate a secret observed in configuration with the service that accepts
  or exposes it—without persisting the raw value by default.
- **Vantage-aware temporal ingestion.** Ingest v4 derives collection-point and
  network-context provenance automatically. Ambiguous identities, lifecycle
  ownership, and cross-observation processing remain scoped per vantage, while
  weak identity stays analyzable under artifact-local additive-only scope.
- **Coverage-aware temporal ingestion.** Collection domains declare what they
  observed completely, partially, or not at all. Complete epochs retire stale
  truth and rebuild derived relationships; incomplete scans cannot silently
  present an authoritative clean posture.
- **Ordered graph reasoning.** Post-processors derive access, execution,
  shadowing, poisoned content, reachability, credential chains, exfiltration,
  impersonation, cross-protocol paths, and risk scores from the retained raw
  evidence.
- **Canonical risk semantics.** The legacy `EdgeRiskWeight` helper and the v1
  risk table now agree for Basic, OIDC, and unknown or custom authentication.
- **Evidence-first findings.** Prebuilt attack paths, finding detail,
  remediation guidance, graph evidence, and stable witness export keep each
  security conclusion tied to the nodes, edges, provenance, and publication
  revision that produced it.
- **Rules with provenance.** Built-in detection and fingerprint rules cover
  agent capabilities, credentials, prompt and instruction injection, exposed
  services, and supply-chain risk. Each collection records the effective rule
  manifest so reviewers can identify the semantics behind an observation.

### 🎯 Validate the graph against real infrastructure

- **Predicted-to-verified campaigns.** `agenthound campaign` converts a graph
  hypothesis into observed evidence. Credential-reach campaigns compare an
  anonymous control with a hash-matched authenticated probe and upgrade the
  existing predicted finding when gated access is proven.
- **ContextForge MCP round trips.** Provider-aware MCP tool-description
  campaigns bind a live MCP tool to its exact ContextForge row, apply a benign
  run-specific marker, verify it through management and MCP surfaces, restore
  the original value, and independently report mutation and cleanup outcomes.
- **Reversible offensive primitives.** Authorized extraction, poisoning,
  implantation, campaign, and recovery workflows are dry-run-first. Mutating
  operations persist typed recovery receipts before the write, use bounded
  verification, and retain the receipt whenever cleanup is incomplete.
- **Truthful runtime evidence.** A2A authentication probes, MCP observations,
  Jupyter access checks, looter authentication results, and campaign outcomes
  record only states proven by protocol-correct responses; ambiguity remains
  visible instead of being promoted into a security claim.

### 🛡️ Built for trustworthy field use

- **Lean collector boundary.** `agenthound` is a static field binary with no
  Neo4j, PostgreSQL, web-server, or `server/internal` dependency. Dependency
  and stripped-size gates enforce that boundary on every release.
- **Local-first analysis.** `agenthound-server` combines PostgreSQL, Neo4j,
  post-processing, the REST API, and an embedded React UI while binding to
  `127.0.0.1:8080` by default.
- **Automatic storage pairing.** The server generates and validates the
  PostgreSQL/Neo4j storage pairing internally, accepts artifacts from multiple
  recognized vantages, and reports identity recognition in ingest results.
- **Clean ingest-v4 boundary.** Version 4 artifacts require a fresh database,
  avoiding unsafe per-point purge while the retained projection moves from the
  former single-realm model to automatic vantage-aware ownership.
- **Strict transport defaults.** MCP and A2A TLS verification is on by default;
  insecure transport requires an explicit operator choice. Active operations
  require an `AUTHORIZED` acknowledgement and record engagement provenance.
- **Dependency remediation.** `golang.org/x/text` 0.39.0 closes the reachable
  `GO-2026-5970` invalid-input infinite loop reported by `govulncheck`.

### 🔎 Investigation-ready frontend

- **Dashboard and triage.** Review exposure, risk distribution, credential
  posture, chokepoints, cross-protocol reach, high-risk entities, and current
  findings from the same published graph revision.
- **Interactive graph explorer.** Navigate the React Flow + ELK graph through
  security lenses, search, evidence drawers, relationship semantics, attack
  paths, and exportable investigation context.
- **Reviewer-friendly findings.** Finding pages expose the supporting path,
  verification status, remediation, property evidence, and copy-ready reports
  without flattening predicted and observed claims into the same state.
- **Operator-guided collection.** Scan Manager generates origin-correct,
  copyable commands for configuration, MCP, A2A, discovery, and service
  collection workflows.

### 📦 Verifiable multi-platform release

- ✅ Collector and server archives for macOS, Linux, and Windows on amd64 and
  arm64.
- ✅ Multi-architecture `agenthound` and `agenthound-server` images on GHCR.
- ✅ SHA-256 checksums, keyless Sigstore verification bundles, and per-archive
  software bills of materials.
- ✅ Homebrew formulas for the collector and analysis server.
- ✅ Public Docker Compose deployment with health-checked PostgreSQL, Neo4j, and
  the loopback-bound AgentHound server.
- ✅ Tagged archives and containers carry the GoReleaser-injected source commit;
  `go install ...@latest` derives its module version from Go build metadata and
  truthfully reports `commit: none` when no linker commit was injected.
- ✅ Release gates reject drift across every installer pin and require an empty
  Unreleased section on tag builds. Publication verification covers the latest
  GitHub release, GHCR tag digests, Homebrew URLs and checksums, the default
  installer, Go module retractions, and fresh source installs.

### ✅ Release confidence

This release was validated end to end against the project’s real disposable
infrastructure: collection, ingest lifecycle, database binding, derived graph,
API responses, browser representation, recovery paths, upgrades, release
gates, and distribution configuration. Documentation and source comments were
also reconciled against the shipped v1 implementation and release process.

## v1.0.0 — 🚀 First Supported Public Release (2026-07-20)

> **Retracted historical publication.** This section preserves the original
> v1.0.0 notes. That publication is unsupported because GitHub and the Go
> module proxy resolved it to different source commits. v1.0.1 is the first
> supported public release.

AgentHound v1.0.0 is the first supported public release of an offensive
security framework built specifically for AI agent infrastructure. It brings
the relationship-driven analysis of an attack graph to MCP, A2A, agent
configuration, model infrastructure, credentials, tools, resources, and
instruction supply chains—then lets operators validate predicted paths against
real systems with evidence-backed, reversible workflows.

> **From observation to proof.** Discover the agentic estate, reveal the paths
> that matter, and validate them against real infrastructure.

| 🗺️ Discover | 🧠 Correlate | 🎯 Validate | 🔎 Investigate | 📦 Ship |
|---|---|---|---|---|
| MCP, A2A, configs, AI services | Temporal attack graph | Reversible campaigns | Evidence-backed UI | Signed multi-platform artifacts |

### 🗺️ Map the agentic attack surface

- **One graph across the agentic stack.** Model agents, MCP servers, tools,
  prompts, resources, A2A agents, AI services, credentials, instruction files,
  hosts, models, and their trust relationships in one temporal attack graph.
- **Broad local configuration coverage.** Discover MCP and agent configuration
  across Claude Desktop, Claude Code, VS Code, Windsurf, Continue, Zed, Cline,
  JetBrains, Kiro, Amazon Q, and Augment, including nested project rules and
  instruction files.
- **Protocol-aware MCP and A2A collection.** Enumerate live MCP capabilities
  through the official SDK and ingest A2A v0.3 and v1.0.1 Agent Cards with
  schema-aware parsing, interface preservation, authentication requirements,
  and bounded JWS verification.
- **Port-neutral AI service discovery.** Fingerprint Ollama, Open WebUI,
  LiteLLM, vLLM, LangServe, MLflow, Qdrant, and Jupyter from observed protocol
  behavior rather than assuming a service from its port number.
- **Evidence-backed inventory.** Read-only looters cover LiteLLM, Ollama,
  Open WebUI, MLflow, Qdrant, and Jupyter while distinguishing verified
  anonymous access, authenticated access, partial inventory, and unknown state.

### 🧠 Turn observations into defensible attack paths

- **Deterministic cross-collector identity.** Content-addressed node IDs merge
  the same infrastructure across collectors, while stable credential hashes
  correlate a secret observed in configuration with the service that accepts
  or exposes it—without persisting the raw value by default.
- **Coverage-aware temporal ingestion.** Collection domains declare what they
  observed completely, partially, or not at all. Complete epochs retire stale
  truth and rebuild derived relationships; incomplete scans cannot silently
  present an authoritative clean posture.
- **Ordered graph reasoning.** Post-processors derive access, execution,
  shadowing, poisoned content, reachability, credential chains, exfiltration,
  impersonation, cross-protocol paths, and risk scores from the retained raw
  evidence.
- **Evidence-first findings.** Prebuilt attack paths, finding detail,
  remediation guidance, graph evidence, and stable witness export keep each
  security conclusion tied to the nodes, edges, provenance, and publication
  revision that produced it.
- **Rules with provenance.** Built-in detection and fingerprint rules cover
  agent capabilities, credentials, prompt and instruction injection, exposed
  services, and supply-chain risk. Each collection records the effective rule
  manifest so reviewers can identify the semantics behind an observation.

### 🎯 Validate the graph against real infrastructure

- **Predicted-to-verified campaigns.** `agenthound campaign` converts a graph
  hypothesis into observed evidence. Credential-reach campaigns compare an
  anonymous control with a hash-matched authenticated probe and upgrade the
  existing predicted finding when gated access is proven.
- **ContextForge MCP round trips.** Provider-aware MCP tool-description
  campaigns bind a live MCP tool to its exact ContextForge row, apply a benign
  run-specific marker, verify it through management and MCP surfaces, restore
  the original value, and independently report mutation and cleanup outcomes.
- **Reversible offensive primitives.** Authorized extraction, poisoning,
  implantation, campaign, and recovery workflows are dry-run-first. Mutating
  operations persist typed recovery receipts before the write, use bounded
  verification, and retain the receipt whenever cleanup is incomplete.
- **Truthful runtime evidence.** A2A authentication probes, MCP observations,
  Jupyter access checks, looter authentication results, and campaign outcomes
  record only states proven by protocol-correct responses; ambiguity remains
  visible instead of being promoted into a security claim.

### 🛡️ Built for trustworthy field use

- **Lean collector boundary.** `agenthound` is a static field binary with no
  Neo4j, PostgreSQL, web-server, or `server/internal` dependency. Dependency
  and stripped-size gates enforce that boundary on every release.
- **Local-first analysis.** `agenthound-server` combines PostgreSQL, Neo4j,
  post-processing, the REST API, and an embedded React UI while binding to
  `127.0.0.1:8080` by default.
- **Realm-safe graph ownership.** The v1.0.0 wire contract used a canonical
  host/private-network realm and admitted one collection realm per database.
- **Fail-closed storage pairing.** The v1.0.0 server required a configured
  versioned storage-pair binding in both databases and rechecked it before
  ingest mutation.
- **Strict transport defaults.** MCP and A2A TLS verification is on by default;
  insecure transport requires an explicit operator choice. Active operations
  require an `AUTHORIZED` acknowledgement and record engagement provenance.

### 🔎 Investigation-ready frontend

- **Dashboard and triage.** Review exposure, risk distribution, credential
  posture, chokepoints, cross-protocol reach, high-risk entities, and current
  findings from the same published graph revision.
- **Interactive graph explorer.** Navigate the React Flow + ELK graph through
  security lenses, search, evidence drawers, relationship semantics, attack
  paths, and exportable investigation context.
- **Reviewer-friendly findings.** Finding pages expose the supporting path,
  verification status, remediation, property evidence, and copy-ready reports
  without flattening predicted and observed claims into the same state.
- **Operator-guided collection.** Scan Manager generates origin-correct,
  copyable commands for configuration, MCP, A2A, discovery, and service
  collection workflows.

### 📦 Verifiable multi-platform release

- ✅ Collector and server archives for macOS, Linux, and Windows on amd64 and
  arm64.
- ✅ Multi-architecture `agenthound` and `agenthound-server` images on GHCR.
- ✅ SHA-256 checksums, keyless Sigstore verification bundles, and per-archive
  software bills of materials.
- ✅ Homebrew formulas for the collector and analysis server.
- ✅ Public Docker Compose deployment with health-checked PostgreSQL, Neo4j, and
  the loopback-bound AgentHound server.

### ✅ Release confidence

This release was validated end to end against the project’s real disposable
infrastructure: collection, ingest lifecycle, database binding, derived graph,
API responses, browser representation, recovery paths, upgrades, release
gates, and distribution configuration.
