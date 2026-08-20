# Scanner guide

`agenthound scan` collects the local host and any added network scope in one operation. Active verification is the default.

## Targets

```bash
agenthound scan
agenthound scan ai-gateway.internal
agenthound scan 10.20.0.0/24
agenthound scan @targets.txt
```

A positional target adds to local collection. Without one, AgentHound seeds loopback, active local unicast interfaces, endpoints from supported MCP configuration, and standard ports for supported AI services.

A targets file accepts one hostname, IP, or CIDR per line. Blank lines and lines beginning with `#` are ignored. Target expansion is capped at 1,048,576 hosts, including the aggregate contents of a targets file. Multicast and link-local scope are rejected.

An invalid positional target fails before configured network enumeration begins. Explicit public targets are accepted.

## Modes

| Mode | Collection and actions |
|---|---|
| Active | Uses configured authentication, reuses compatible credentials, verifies MCP resource access, and runs eligible reversible ContextForge probes. |
| Active with `--deep` | Adds recursive instruction collection, Qdrant payload samples, expensive probes, and bounded Ollama embedding verification. |
| `--stealth` | Performs anonymous read-only collection and exact configured authentication. Credential reuse, compute, tool invocation, and mutation are disabled. |
| `--stealth --deep` | Adds deep filesystem and payload reads while retaining stealth restrictions. |

Read-only protocol operations may use POST when the protocol requires it. `--insecure` changes TLS certificate verification only; it does not change target exclusions or action mode.

## Exclusions

`--exclude` accepts an exact hostname, IP, or CIDR and can be repeated:

```bash
agenthound scan 10.20.0.0/16 \
  --exclude admin.internal \
  --exclude 10.20.4.12 \
  --exclude 10.20.8.0/24
```

The contact policy applies before target admission and at the final socket dial. Hostnames are compared case-insensitively without a trailing DNS dot. Resolved addresses, redirects, derived management and cleanup URLs, and remote JWKS locations pass through the same policy. Mixed DNS results use only admitted addresses; a fully excluded scope produces a skipped outcome and no connection.

Configuration referring to an excluded endpoint remains useful graph evidence, but AgentHound does not enumerate that endpoint. A stdio MCP child process runs as a local process and is outside network-level enforcement.

Normalized exclusions are stored in the artifact and reused by `agenthound revert`.

## Credentials and service collection

AgentHound stores concrete credentials as `Credential.properties.value` and uses `value_hash` for identity and deduplication. Each newly discovered raw value is printed once unless `--quiet` is set.

The planner can execute LiteLLM master, bearer, and API keys; Open WebUI bearer and API keys; Jupyter tokens; A2A bearer credentials; and MCP bearer credentials tied to an exact resource. Masks, hashes, unresolved environment references, unresolved secret-provider references, custom strings, and basic-auth guesses are preserved as evidence but are not presented to services.

Anonymous collection covers applicable LiteLLM, Open WebUI, Jupyter, Qdrant, MLflow, and Ollama endpoints. New targets and credentials are indexed as they appear, allowing useful authenticated work during the same scan.

## Verification actions

The active planner performs three bounded actions when their prerequisites are present:

- MCP credential access compares an anonymous control read with an authenticated read of the same resource and saves returned content.
- The ContextForge description round trip writes a scan-specific marker, observes it through MCP, restores the original immediately, and confirms restoration.
- Deep Ollama verification invokes a bounded embedding request to prove compute access.

The ContextForge action runs exclusively. Collection and other actions are drained before mutation, and nothing else runs until restoration is confirmed. Cleanup uses a separate 90-second context even when the main scan is interrupted.

## Artifact and interruption behavior

AgentHound writes an ingest-valid artifact before collection and checkpoints after every meaningful result or action transition. Independent target and collector errors are recorded while unrelated work continues.

A checkpoint failure or unresolved cleanup stops forward planning. A deadline or signal finalizes the scan as interrupted. If recovery remains unresolved, retry it from the same artifact:

```bash
agenthound revert scan-<scan_id>.json
```

`revert` observes current state first, processes unresolved records newest-first, refuses to overwrite third-party changes, and checkpoints every attempt.

See the [CLI reference](../reference/cli.md) for all flags and exit behavior.
