# Security and operational behavior

AgentHound is designed for an authorized compromised-host workflow. Its priority is completing useful collection and proof during one access window, not building a credential-management product.

## Plain credentials

Concrete secret material is stored directly in `Credential.properties.value` inside the scan JSON. `value_hash` remains for identity and planner deduplication. Values are not encrypted, wrapped, moved to a second vault, or omitted from the CLI artifact.

The CLI prints each newly discovered value once unless `--quiet`. The dashboard masks only the exact `value` property on Credential nodes and offers Reveal and Copy. Query results and JSON exports remain literal.

Masked provider references, hashes, and unresolved environment or vault references remain represented as such and are never mislabeled as concrete secrets.

## Active versus stealth

Active mode is the default. It may present compatible credentials to other supported endpoints, perform differential authenticated reads, invoke a bounded Ollama embedding probe in deep mode, and run a reversible ContextForge description marker round trip.

`--stealth` disables cross-target reuse and actions. It still permits anonymous collection, exact configured authentication, GETs, and protocol-required read-only POSTs. `--stealth --deep` adds deep read-only collection only.

## Network exclusion boundary

One immutable contact policy is built before any network-capable phase. It checks configured targets before enumeration, every discovered or planner-derived target before insertion, and concrete DNS results immediately before dialing. HTTP requests and redirects, service clients, MCP/A2A, cleanup, and JWKS retrieval all use guarded transports.

The normalized exclusions are persisted in `meta.extra.scan_execution.exclusions`. Standalone recovery reconstructs the same policy; it does not silently broaden the original scan boundary.

The guarantee is limited to AgentHound-owned network connections. AgentHound does not claim to network-sandbox an external stdio MCP process.

## Recovery

Recovery records live in `meta.extra.scan_execution.recovery` in the same artifact. There are no engagement directories or receipt sidecars.

A mutator must checkpoint `prepared` before writing. It marks and checkpoints `applied` immediately after the write, then restores and confirms the original before returning. Forward cancellation cannot cancel cleanup; cleanup receives its own 90-second context.

If recovery is uncertain, AgentHound stops forward planning. `agenthound revert <scan.json>` observes current state and restores only when the recorded original can be applied without overwriting a third-party change.

Restoration is complete only after the independent confirmation succeeds. A partially verified restore remains `indeterminate` and eligible for retry.

## Data handling

The artifact contains secrets and collected service content. Handle or delete it according to the assessment's existing data rules. AgentHound itself deliberately adds no output encryption, public-key workflow, secret service, permission layer, or reveal endpoint.
