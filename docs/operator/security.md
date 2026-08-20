# Security and OPSEC

AgentHound is designed for authorized work from a compromised host. Active collection favors completing useful verification during the available access window.

## Plaintext artifacts

Concrete secrets are stored directly in `Credential.properties.value` and printed once unless `--quiet` is set. The JSON artifact also contains collected service content, topology, action results, and recovery data.

Store, transport, and delete the artifact under the assessment's existing evidence-handling rules. The dashboard masks Credential `value` in the normal property view and provides Reveal and Copy; explicit query output and JSON export remain literal.

## Active and stealth modes

Active mode can reuse compatible credentials, perform differential MCP reads, invoke the deep Ollama embedding probe, and run an eligible reversible ContextForge marker round trip.

`--stealth` keeps collection read-only. It permits anonymous requests, exact configured authentication, and protocol-required read-only POSTs. Cross-target credential presentation, model and tool invocation, and mutation are disabled.

## Exclusions

The contact policy checks exact hostnames, IPs, CIDRs, DNS results, redirects, derived URLs, cleanup requests, and final dials. The same normalized policy is recorded for standalone recovery.

The boundary covers AgentHound-owned network connections. A local stdio MCP process is an external child process and is not network-sandboxed by the collector.

## Reversible actions

Recovery state is checkpointed before mutation. The action restores immediately under a separate 90-second cleanup context and confirms the original before the planner continues. Unresolved cleanup stops forward work.

Use the same artifact for a later recovery attempt:

```bash
agenthound revert scan-<scan_id>.json
```

The command observes live state first and refuses to overwrite a third-party change.

## Analysis server

`agenthound-server` has no application login and binds to `127.0.0.1:8080` by default. Use an SSH tunnel, private mesh, or authenticated reverse proxy for remote access. Keep PostgreSQL and Neo4j private and back them up as one pair.
