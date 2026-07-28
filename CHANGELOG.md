# 🐕 AgentHound Changelog

## Unreleased

## 1.0.0 — 🚀 First Supported Release (2026-07-27)

AgentHound 1.0.0 is the first supported release of the offensive security
framework built for AI agent infrastructure. It maps MCP, A2A, agent
configuration, model infrastructure, credentials, tools, resources, notebooks,
vector stores, and instruction supply chains into one attack graph—then helps
operators validate the paths that matter against real systems.

> **From observation to proof.** Discover the agentic estate, reveal the paths
> that matter, and validate them against real infrastructure.

| 🗺️ Discover | 🧠 Correlate | 🎯 Validate | 🔎 Investigate | 📦 Ship |
|---|---|---|---|---|
| MCP, A2A, configs, AI services | Temporal attack graph | Reversible campaigns | Evidence-backed UI | Signed multi-platform artifacts |

### 🗺️ Map the agentic attack surface

- **One graph across the agentic stack.** Model agents, MCP servers, tools,
  prompts, resources, A2A agents, AI services, credentials, instruction files,
  hosts, and models share one relationship-driven view.
- **Broad agent configuration coverage.** Discover MCP and agent configuration
  across Claude Desktop, Claude Code, VS Code, Windsurf, Continue, Zed, Cline,
  JetBrains, Kiro, Amazon Q, Augment, Cursor, and GitHub Copilot.
- **Bounded instruction discovery.** Normal scans inspect registered
  instruction sources at canonical user and project roots. Deep scans add
  bounded nested-project discovery while excluding dependency, cache, trash,
  and symlinked descendant trees.
- **Protocol-aware MCP and A2A collection.** Enumerate live MCP capabilities
  through the official SDK and ingest A2A v0.3 and v1.0.1 Agent Cards with
  schema-aware parsing, preserved interfaces, authentication requirements, and
  bounded JWS verification.
- **Port-neutral service discovery.** Fingerprint Ollama, Open WebUI, LiteLLM,
  vLLM, LangServe, MLflow, Qdrant, and Jupyter from observed protocol behavior
  instead of assuming a service from its port number.
- **Evidence-backed inventory.** Read-only looters cover LiteLLM, Ollama,
  Open WebUI, MLflow, Qdrant, and Jupyter while distinguishing verified
  anonymous access, authenticated access, partial inventory, and unknown state.
- **First-class scan upload.** `agenthound scan --ingest <server-url>` saves the
  local artifact before uploading those exact bytes and returns a correlated
  ingest receipt with finding counts.

### 🧠 Turn observations into defensible attack paths

- **Deterministic cross-collector identity.** Content-addressed node IDs merge
  the same infrastructure across collectors, while stable credential hashes
  correlate a secret observed in configuration with the service that accepts
  or exposes it—without persisting the raw value by default.
- **Vantage-aware temporal ingestion.** Collection-point and network-context
  provenance keep identity, lifecycle, and cross-observation analysis scoped to
  what a scanner could actually observe.
- **Coverage-aware truth.** Collection domains declare what they observed
  completely, partially, or not at all. Complete epochs retire stale facts;
  incomplete scans cannot silently present an authoritative clean posture.
- **Resilient publication lifecycle.** Interrupted ingests preserve the last
  trustworthy publication, expose incomplete coverage, and recover cleanly
  when a later authoritative scan arrives.
- **Ordered graph reasoning.** Post-processors derive access, execution,
  shadowing, poisoned content, reachability, credential chains, exfiltration,
  impersonation, cross-protocol paths, and risk scores from retained evidence.
- **Evidence-first findings.** Prebuilt attack paths, finding detail,
  remediation guidance, graph evidence, and stable witness export keep each
  security conclusion tied to the nodes, edges, provenance, and publication
  revision that produced it.
- **Rules with provenance.** Built-in detection and fingerprint rules cover
  agent capabilities, credentials, prompt and instruction injection, exposed
  services, and supply-chain risk, with the effective rule set recorded for
  each collection.

### 🎯 Validate the graph against real infrastructure

- **Predicted-to-verified campaigns.** `agenthound campaign` turns a graph
  hypothesis into observed evidence. Credential-reach campaigns compare an
  anonymous control with a hash-matched authenticated probe and upgrade the
  predicted finding only when gated access is proven.
- **ContextForge MCP round trips.** Provider-aware campaigns bind a live MCP
  tool to its exact ContextForge row, apply a benign run-specific marker,
  verify it through management and MCP surfaces, and restore the original
  value.
- **Reversible offensive primitives.** Authorized extraction, poisoning,
  implantation, campaign, and recovery workflows are dry-run-first. Mutating
  operations persist recovery receipts before the write and retain them when
  cleanup is incomplete.
- **Truthful runtime evidence.** A2A authentication probes, MCP observations,
  Jupyter access checks, looter results, and campaign outcomes record only
  states proven by protocol-correct responses.

### 🛡️ Built for trustworthy field use

- **Lean collector boundary.** `agenthound` is a static field binary with no
  Neo4j, PostgreSQL, web-server, or server implementation dependency.
  Dependency and stripped-size gates protect that boundary on every release.
- **Local-first analysis.** `agenthound-server` combines PostgreSQL, Neo4j,
  post-processing, the REST API, and an embedded React UI while binding to
  `127.0.0.1:8080` by default.
- **Automatic storage pairing.** The server generates and validates its
  PostgreSQL/Neo4j pairing, accepts artifacts from recognized vantages, and
  reports identity recognition in ingest results.
- **Strict transport defaults.** MCP and A2A TLS verification is on by default;
  insecure transport requires an explicit operator choice. Authenticated A2A
  redirects cannot cross origin or downgrade from HTTPS to HTTP.
- **Fail-closed inputs.** Invalid custom detection rules, oversized fingerprint
  bundles, incompatible wire contracts, and unsupported persisted export
  schemas are rejected instead of being partially trusted.
- **Explicit authorization.** Active operations require an `AUTHORIZED`
  acknowledgement and record engagement provenance.

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

- Collector and server archives for macOS, Linux, and Windows on amd64 and
  arm64.
- Multi-architecture `agenthound` and `agenthound-server` images on GHCR.
- SHA-256 checksums, a keyless Sigstore verification bundle, and per-archive
  software bills of materials.
- Homebrew formulas for the collector and analysis server.
- Public Docker Compose deployment with health-checked PostgreSQL, Neo4j, and
  the loopback-bound AgentHound server.
- Release archives and containers identify the exact source commit.
- Release gates protect installer pins, release notes, dependency boundaries,
  binary size, tests, documentation, cross-compilation, and distribution
  metadata before publication.
