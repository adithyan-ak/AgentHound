# CLI reference

The collector exposes one normal workflow and one recovery command.

```text
agenthound scan [host|CIDR|@targets-file]
agenthound revert <scan.json>
agenthound version
```

Bare `agenthound` shows help.

## `agenthound scan`

Local configuration, instruction, and credential collection always runs. A positional host, CIDR, or `@targets-file` adds network targets; it never changes the scan into a network-only mode.

With no positional target, AgentHound seeds loopback, active local unicast interfaces, configured endpoints, and standard AI-service ports.

### Flags

| Flag | Default | Meaning |
|---|---:|---|
| `--deep` | `false` | Add bounded recursive instruction collection, Qdrant payload samples, expensive probes, and active Ollama embedding verification. |
| `--stealth` | `false` | Disable cross-target credential reuse, compute invocation, tool invocation, mutation, and every other active planner action. |
| `--timeout <duration>` | `15m` | Overall scan deadline. |
| `--exclude <value>` | none | Repeatable exact hostname, IP, or CIDR that AgentHound must not contact. Globs and URLs are rejected. |
| `--insecure` | `false` | Skip TLS certificate verification. It does not bypass exclusions. |
| `--output <path>` | `scan-<scan_id>.json` | Artifact file. Directories and `-` are rejected. |
| `--quiet` | `false` | Suppress progress, summary, ingest hint, and discovered-secret output. Errors remain visible. |

`AGENTHOUND_QUIET=1` has the same effect as `--quiet`. Existing client configuration may still set log level and the default output path; it does not restore removed commands or flags.

### Modes

`scan` is active by default. It collects anonymous data, uses configured authentication on exact configured endpoints, reuses compatible concrete credentials, performs differential MCP resource-access proof, and runs eligible reversible ContextForge description round trips.

`scan --deep` additionally enables expensive read collection and the bounded Ollama embedding invocation.

`scan --stealth` keeps network operations read-only. Protocol-required read-only POSTs remain allowed. Configured credentials may enumerate only their exact configured endpoint. Cross-target credential presentation, model and tool invocation, and mutation are disabled.

`scan --stealth --deep` adds only deep read-only collection.

### Targets files

A targets file is selected by prefixing its path with `@`:

```text
# comments and blank lines are ignored
10.20.0.10
10.20.1.0/24
ai-gateway.internal
```

The expanded scan is capped at one million hosts. Multicast targets are rejected.

### Exit and artifact behavior

AgentHound writes an ingest-valid `running` artifact before local collection. It atomically replaces that same file after each phase, collector result, action transition, and cleanup transition.

Independent target and collector failures are recorded and do not stop unrelated work. A checkpoint failure, unresolved mutation cleanup, deadline, or signal stops forward planning. Deadline and signal termination finalize the execution as `interrupted`; other fatal errors use `failed`.

At successful completion the CLI prints:

```text
Next: agenthound-server ingest <scan.json>
```

There is no collector-side remote ingest and no JSON-to-stdout artifact mode.

## `agenthound revert <scan.json>`

Strictly decodes a unified scan artifact and retries unresolved recovery records newest-first. It resolves credential values from Credential nodes in the artifact, uses the recorded endpoint and TLS settings, and checkpoints after every attempt.

The command reconstructs the immutable contact policy from the scan's recorded `exclusions`; recovery cannot contact a destination the original scan was forbidden to contact.

`prepared` is treated as possibly applied, so live state is observed before any restore. A third-party change produces `conflict` and is never overwritten. Restored records are skipped. The command exits nonzero while any recovery remains unresolved.

## `agenthound version`

Prints collector version and build commit.

## Removed workflows

The collector does not expose `discover`, `loot`, `extract`, `poison`, `implant`, `campaign`, `rules`, `--commit`, engagement IDs, witness files, authorization prompts, watermarks, or remote-ingest flags. Discovery, service collection, and eligible proof actions are internal scan phases. Runtime rule bundles and specialized GGUF extraction were removed.
