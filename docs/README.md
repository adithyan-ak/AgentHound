# AgentHound Documentation

Attack-path discovery for AI agent infrastructure. [BloodHound](https://github.com/BloodHoundAD/BloodHound) for MCP, A2A, and AI services.

---

## Get Started

- **[Install](getting-started/install.md)** — Homebrew, Docker, or build from source
- **[Quickstart](getting-started/quickstart.md)** — First scan to first finding in 10 minutes
- **[Demo Lab](getting-started/demo-lab.md)** — Full offensive arc with Docker (scan → discover → loot → poison → revert)

## Operator Guides

- **[Network Scanning](operator/scanner.md)** — Sweep CIDRs for AI/ML services + fingerprint
- **[Protocol Discovery](operator/discover.md)** — Find MCP servers and A2A agents by protocol shape
- **[Looting](operator/loot/)** — Extract credentials and model artifacts from discovered services
  - [LiteLLM](operator/loot/litellm.md) — Master key → upstream provider keys
  - [Ollama](operator/loot/ollama.md) — Model inventory, modelfiles, weight extraction
- **[Offensive Actions](operator/offensive-actions.md)** — Poison tool descriptions, implant configs, revert
- **[Attack Paths](operator/attack-paths.md)** — Credential chains, cross-protocol pivots, exfiltration routes
- **[Deployment](operator/deployment.md)** — Production setup, reverse proxy, backups
- **[Security and OPSEC](operator/security.md)** — Threat model, audit trail, operator posture

## Reference

- **[CLI Reference](reference/cli.md)** — Every command, flag, and env var
- **[API Reference](reference/api.md)** — REST endpoints, auth, request/response schemas
- **[Graph Model](reference/graph-model.md)** — 25 node types, 25 edge types, ID strategy, merge semantics
  - [CAN_REACH](reference/edges/can-reach.md) — The marquee composite edge (transitive agent→resource access)
  - [CAN_EXFILTRATE_VIA](reference/edges/can-exfiltrate-via.md) — Sensitive data + outbound channel
  - [SHADOWS](reference/edges/shadows.md) — Cross-server tool shadowing
- **[Detection Rules](reference/detection-rules.md)** — 18 pre-built queries + OWASP mapping
- **[Rule Syntax](reference/rule-syntax.md)** — YAML schema for detection + fingerprint rules
- **[Configuration](reference/configuration.md)** — Env vars, state directories, defaults
- **[Risk Scoring](reference/risk-scoring.md)** — Edge weights, node scores, sensitivity classification

## Architecture

- **[System Design](architecture/system-design.md)** — Two-binary split, data flow, tech stack
- **[Ingest Pipeline](architecture/ingest-pipeline.md)** — Validate → normalize → deduplicate → write → post-process
- **[Post-Processors](architecture/post-processors.md)** — 11 composite-edge processors with dependency ordering

## Contributing

- **[Development Setup](contributing/dev-setup.md)** — Clone to green CI in 5 minutes
- **[Writing Modules](contributing/modules.md)** — Add a fingerprinter, looter, or poisoner
- **[Authoring Rules](contributing/authoring-rules.md)** — Write + test YAML detection rules

## Decisions

- **[ADR-0001: Two-Binary Split](adr/0001-two-binary-split.md)** — Why collector and server are separate binaries

---

## Where does my new doc go?

| Question | Folder |
|----------|--------|
| How to USE the tool operationally? | `operator/` |
| A lookup table, schema, or flag reference? | `reference/` |
| How the code works internally? | `architecture/` |
| How to add something to the codebase? | `contributing/` |
| A first-time setup walkthrough? | `getting-started/` |
| An architecture decision? | `adr/` |

One concept per file. Split before 500 lines. kebab-case filenames.
