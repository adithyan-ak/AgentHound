# Detection rules

AgentHound combines compiled collector rules, server post-processors, and prebuilt queries. The matching collector and server release therefore share one reproducible detection set.

## Detection layers

| Layer | Runs | Produces |
|---|---|---|
| Compiled YAML rules | During collection | Capability, sensitivity, source-trust, credential, injection, and service-fingerprint properties. |
| Post-processors | During ingest | Composite graph edges, evidence states, and risk factors. |
| Prebuilt queries | On the published projection | Operator-focused views of common attack paths and exposures. |

The repository currently compiles 42 YAML rule definitions and registers 19 prebuilt queries. Inspect the effective rules through `GET /api/v1/rules` or the dashboard Rules page.

## Coverage

| Area | Representative evidence and analysis |
|---|---|
| Authentication exposure | Observed anonymous MCP/A2A protocol access, configured auth posture, effective auth strength. |
| Credential exposure | Concrete high-entropy secrets, LiteLLM master-key exposure, cross-service `value_hash` chains. |
| Tool capability | Shell, code execution, database, credential, file, network, and email surfaces. |
| Resource sensitivity | Production databases, object storage, credentials, keys, system files, logs, and general remote resources. |
| Description integrity | Injection patterns, tool shadowing, context poisoning, and cross-tool taint. |
| Instruction integrity | Override language, exfiltration commands, hidden Unicode, and encoded payload indicators. |
| Supply chain | Unpinned packages and current hash drift in descriptions, schemas, or instructions. |
| A2A trust | Unsigned cards, delegation hypotheses, impersonation, confused deputy, and cross-protocol host correlation. |
| Impact paths | Shell access, sensitive-resource reachability, outbound channels, and chokepoints. |

## Evidence boundaries

AgentHound fails closed when the required evidence is missing:

- A declared or configured no-auth posture is not treated as observed anonymous access.
- Masked, hashed, or unresolved credential references do not become usable secrets.
- Host co-location is a hypothesis rather than proof of a protocol bridge.
- Capability classification identifies a candidate surface rather than confirmed command execution.
- Exfiltration analysis identifies compatible access and output channels rather than an observed transfer.
- An unmatched resource URI remains unknown rather than being classified as low sensitivity.
- Ordinary instruction language, documentation URLs, inert security examples, undecodable encoded strings, and supporting-only markup or zero-width characters do not become instruction findings.

Same-scan `CREDENTIAL_ACCESS_OBSERVED` proof can upgrade the exact matching `CAN_REACH` finding to **Verified During Scan**. It strengthens existing analysis and does not create a separate detection or add risk twice.

### Instruction classification

Instruction-file rules feed a bounded classifier rather than promoting every regex match. Standalone override semantics and U+202E bidirectional overrides produce a medium `INSTRUCTION_SIGNAL`. Strong combinations and validated sensitive disclosure, transfer, or decoded payloads produce a poisoning verdict. Evidence combines only within the same or an adjacent structural block, within 256 bytes, and never across headings, fenced-region boundaries, or explicitly inert-region boundaries. That verdict becomes high `POISONED_INSTRUCTIONS` only in an exact project or user scope; recursive deep matches remain medium review signals.

Sensitive-action evidence requires a disclosure or transmission verb near a concrete subject such as credentials, tokens, keys, environment values, system prompts, or instruction context. Transfer verbs require a destination; ambiguous output verbs also require material language such as `raw`, `contents`, or `verbatim`. Protective language and representation-only uses such as schemas, names, hashes, counts, mocks, or redacted examples remain clean.

Base64 candidates use strict RFC 4648 decoding. Hex and percent candidates require nearby language that explicitly directs decoding and execution. All decoders accept 16–2,048 predominantly printable UTF-8 bytes, run once, and do not recursively decode nested content.

Every promoted instruction finding carries bounded, inspectable excerpts. Confidence represents direct observation of the matched content, not certainty about malicious intent or execution.

## Common prebuilt queries

```bash
agenthound-server query --prebuilt no-auth-servers
agenthound-server query --prebuilt no-auth-a2a
agenthound-server query --prebuilt poisoned-tools
agenthound-server query --prebuilt instruction-poisoning
agenthound-server query --prebuilt unpinned-packages
agenthound-server query --prebuilt credential-chain
agenthound-server query --prebuilt exfiltration-routes
agenthound-server query --prebuilt cross-protocol-paths
```

List every registered query through `GET /api/v1/analysis/prebuilt` or the dashboard Queries page.

Contributors can change compiled rules by following [Authoring rules](../contributing/authoring-rules.md). Processor-backed detections are documented in [Server Analysis](../architecture/server-analysis.md).
