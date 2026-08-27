# 🐕 AgentHound Changelog

## Unreleased

### Changed

- Public Compose deployments now pin the coordinated AgentHound server release, and release publication verifies the signed production image before making the GitHub release public.
- Server ingestion now reports collector, artifact-contract, and server versions while retaining backward compatibility with supported historical V1 artifacts.

## 1.1.1 — Evidence Precision and Reliability

### Added

- Instruction findings now preserve bounded matched excerpts, source positions, scope, and file metadata from the scan artifact through the dashboard and copied report.
- A medium-severity `INSTRUCTION_SIGNAL` finding separates reviewable standalone or deep-scope signals from high-confidence poisoning in active instruction scope.

### Fixed

- Instruction-file classification now requires deterministic override, identity, hidden-content, decoded-payload, or sensitive-outbound semantics instead of promoting ordinary instruction language and documentation examples.
- Concrete credentials discovered in multiple agent configurations now share one `value_hash`-based identity with deterministic provenance and authentication hints.
- Positional scan targets now reject malformed hostname syntax before any resolver or network work begins.
- The installer now validates before promotion and atomically restores the previous binary when installed-path startup validation fails.
- Legitimate documentation URLs no longer look like Base64 prompt-injection payloads or, by themselves, outbound-network capabilities.
- Active planning avoids redundant credential presentation when the exact MCP resource or A2A card/probe surface has already succeeded anonymously.
- Repeated service collection now keeps protected Open WebUI posture stable across credential attempts and gives each distinct LiteLLM master key a contextual `value_hash` identity.

## 1.1.0 — ⚡ Autonomous Offensive Collection

AgentHound 1.1 is an offensive security framework built for the moment a red-team operator lands on a compromised host. One static collector maps the foothold, captures usable secrets, discovers the reachable agentic estate, expands access with compatible credentials, proves concrete attack paths, and preserves the operation in one JSON artifact.

> **One foothold. One scan. Secrets, services, and proof before access disappears.**

| 🔎 Discover | 🔑 Collect | 🎯 Prove | 💾 Recover | 🕸️ Analyze |
|---|---|---|---|---|
| Local and network attack surface | Credentials and service data | Exact access and compute | Continuous checkpoints | Full attack graph and findings |

### ⚡ Drop once, scan once

- **One autonomous workflow.** `agenthound scan` collects the local host, discovers reachable infrastructure, fingerprints services, inventories useful data, reuses compatible credentials, and executes eligible verification actions without making the operator drive individual modules.
- **Foothold-first targeting.** A targetless scan starts from local agent configuration, instruction files, loopback, active interfaces, configured endpoints, and standard AI-service ports. A hostname, IP, CIDR, or targets file adds network scope without disabling local collection.
- **Active by default.** The first run can perform credential validation, bounded compute verification, and reversible action proof while access is still available.
- **Read-only OPSEC when needed.** `--stealth` keeps the same collection workflow read-only, while `--deep` adds recursive instruction discovery, vector payload samples, expensive probes, and bounded model-compute verification.
- **No database on the foothold.** The collector plans locally with deterministic indexes and standard-library data structures. Neo4j, PostgreSQL, Node.js, and the analysis server stay off the compromised host.

### 🔑 Turn exposed secrets into usable access

- **Concrete credential capture.** Bearer tokens, API keys, master keys, Jupyter tokens, and other resolved material are stored directly in the artifact and deduplicated by `value_hash` while preserving every observed source.
- **Same-scan credential expansion.** Newly discovered credentials immediately unlock compatible MCP, A2A, LiteLLM, Open WebUI, and Jupyter collection candidates.
- **Protocol-aware reuse.** Credentials are presented only through adapters that understand their concrete type and destination protocol. Masks, hashes, unresolved references, and arbitrary strings remain evidence rather than guesses.
- **Useful content, not just banners.** AgentHound collects MCP resources and capabilities, agent cards and skills, gateway posture, model metadata, notebooks, vector collections, MLOps experiments, registry data, service configuration, and returned content.

### 🎯 Prove the path while the foothold is live

- **Differential MCP access proof.** AgentHound compares an anonymous control read with an authenticated read of the exact same resource. A denied control and successful credentialed read becomes `CREDENTIAL_ACCESS_OBSERVED` evidence bound to the credential and resource.
- **Verified During Scan findings.** Manual ingestion upgrades only the matching credential-to-resource `CAN_REACH` path to verified confidence. Inferred paths remain honestly inferred.
- **Reversible ContextForge validation.** Eligible tools receive a scan-specific description marker, are observed through MCP, restored immediately, and independently checked before planning resumes.
- **Bounded model-compute proof.** Deep active mode can invoke an Ollama embedding request to confirm usable inference access.
- **Deterministic autonomy.** New targets and credentials generate new candidates; completed and failed candidate keys prevent loops; independent failures do not block unrelated collection.

### 🌐 Map the full agentic attack surface

- **Agent clients and instructions.** Discover Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline, Continue, Zed, JetBrains, Kiro, Amazon Q, Augment, and their instruction surfaces.
- **Agent protocols.** Enumerate configured and discovered MCP servers, tools, resources, prompts, server instructions, A2A Agent Cards, skills, authentication schemes, interfaces, signatures, and JWKS evidence.
- **AI and data services.** Fingerprint LiteLLM, Open WebUI, Ollama, vLLM, Qdrant, MLflow, Jupyter, and LangServe from observed protocol behavior, then run the applicable deep service collectors.
- **One connected evidence model.** Hosts, agent instances, credentials, services, tools, resources, models, configs, and instruction files share deterministic identities and observation provenance.

### 🕸️ Turn one artifact into an attack graph

- **Manual, operator-controlled ingestion.** Move the completed artifact to the analysis system and ingest it with `agenthound-server ingest` when operational timing allows.
- **Graph-native offensive analysis.** Derive reachability, execution, exfiltration, impersonation, credential-chain, shadowing, poisoning, tainted-flow, and cross-protocol paths from the same evidence.
- **Evidence-backed findings.** Findings preserve the supporting nodes, edges, confidence, proof, remediation, publication revision, and triage state.
- **Investigation-ready dashboard.** Inspect risk, attack paths, credentials, findings, queries, scan history, and triage. Raw credential values are masked by default and remain one click away through Reveal and Copy.
- **Coverage-aware truth.** Complete observations retire stale facts, partial scans remain useful without claiming a clean posture, and publication always points to the last trustworthy graph state.

### 💾 Built for loss of access

- **Continuously valid evidence.** AgentHound creates an ingest-valid artifact before collection and checkpoints after every meaningful collector result, action transition, and recovery transition.
- **Immediate mutation cleanup.** Original state is durably recorded before a mutation. Cleanup runs under a separate bounded context even after interruption, and no new work starts until restoration is confirmed.
- **Recover from the same artifact.** `agenthound revert <scan.json>` retries unresolved records newest-first, observes current state before writing, and refuses to overwrite third-party changes.
- **Hard contact exclusions.** One policy enforces exact hostname, IP, CIDR, DNS-result, redirect, derived-URL, JWKS, action, cleanup, and final-dial exclusions.
- **Operationally honest output.** Raw credentials, collected content, proof, and recovery material remain available in plain JSON. Operators can restrict file permissions without a separate vault or key workflow.

### 📦 Verifiable release delivery

- Collector and server archives for macOS, Linux, and Windows on amd64 and arm64.
- Multi-architecture collector and server images on GHCR.
- Homebrew formulas for `agenthound` and `agenthound-server`.
- SHA-256 checksums, keyless Sigstore verification, release attestations, and per-archive software bills of materials.
- Version metadata tied to the exact release commit across archives, containers, and Homebrew installs.
- Release gates for code quality, race tests, vulnerabilities, licenses, Neo4j 4 and 5 integrations, native Windows behavior, real collector-to-server proof, documentation, size, dependencies, containers, and public distribution surfaces.

### 🚀 Start the operation

```bash
# Install the collector
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.0/install.sh \
  | AGENTHOUND_VERSION=1.1.0 sh

# Collect, expand, and prove in one active scan
agenthound scan --deep --output scan.json

# On the analysis system
agenthound-server ingest scan.json
agenthound-server serve
```

Active mode performs offensive verification when prerequisites are present. Use AgentHound only on systems you own or are authorized to assess.
