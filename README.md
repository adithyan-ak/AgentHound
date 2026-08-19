<div align="center">

<img src="docs/readme-assets/agenthound-banner.png" alt="AgentHound" width="100%">

### Autonomous offensive collection for AI agent infrastructure

**MCP · A2A · model gateways · inference servers · vector stores · MLOps · notebooks**

[Quickstart](#quickstart) · [Scan modes](#scan-modes) · [Documentation](https://docs.agenthound.io)

[![CI](https://github.com/adithyan-ak/agenthound/actions/workflows/ci.yml/badge.svg)](https://github.com/adithyan-ak/agenthound/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

</div>

> Use AgentHound only on systems you own or are authorized to assess.

AgentHound is a single-binary collector built for the short window after a host is compromised. One `scan` collects local evidence, discovers and fingerprints reachable AI services, saves raw credentials, performs compatible same-run credential reuse, verifies concrete access, and cleans up reversible probes immediately. It continuously replaces one plain JSON artifact, so partial work survives loss of access.

The collector is the operational product. The server and dashboard are optional, secondary analysis surfaces for the artifact after the operation.

## Quickstart

Install the static collector:

```bash
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
```

Run a targetless active scan. It always collects local configuration and instructions, then seeds network work from loopback, active local interfaces, configured endpoints, and standard AI-service ports:

```bash
agenthound scan
```

Add a host, CIDR, or targets file without disabling local collection:

```bash
agenthound scan 10.20.0.0/24
agenthound scan @targets.txt --deep --exclude 10.20.0.15
```

The default artifact is `scan-<scan_id>.json`. To analyze it later:

```bash
agenthound-server ingest scan-<scan_id>.json
```

Start the optional server/UI stack with Docker Compose, then open `http://127.0.0.1:8080`:

```bash
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/docker/docker-compose.public.yml \
  | docker compose -f - -p agenthound up -d --wait
```

## CLI

```text
agenthound scan [host|CIDR|@targets-file]
    --deep
    --stealth
    --timeout <duration>
    --exclude <host|IP|CIDR>
    --insecure
    --output <path>
    --quiet

agenthound revert <scan.json>
agenthound version
```

Bare `agenthound` shows help. There are no separate discovery, loot, campaign, or mutation workflows and no collector-side upload.

## Scan modes

| Mode | Collection | Credential behavior | Active verification |
|---|---|---|---|
| `scan` | Local, network, protocol, and service collection | Save raw values; use configured credentials; reuse compatible credentials | MCP credential access and eligible ContextForge round trips |
| `scan --deep` | Adds recursive instructions, Qdrant payloads, and expensive probes | Same as active | Also invokes a bounded Ollama embedding probe |
| `scan --stealth` | Anonymous/read-only collection | Save raw values; configured auth may enumerate only its exact endpoint | None |
| `scan --stealth --deep` | Adds deep filesystem and read-only payload collection | No cross-target reuse | No compute invocation or mutation |

Active mode is the default. A ContextForge mutation is never left around for later planner work: AgentHound records recovery state, applies a scan-specific marker, observes it, restores the original immediately using a separate cleanup timeout, and confirms restoration before continuing.

## What one scan does

1. Creates an ingest-valid artifact and checkpoints it.
2. Parses supported local MCP client configuration and registered instruction sources without contacting endpoints.
3. Saves every concrete raw credential as `Credential.properties.value` and retains `value_hash` for identity and deduplication.
4. Builds and filters the target set.
5. Enumerates configured MCP endpoints with their configured authentication and discovered A2A endpoints through their protocol surface.
6. Discovers protocols, scans ports, and fingerprints admitted endpoints.
7. Runs anonymous service collection for LiteLLM, Open WebUI, Jupyter, Qdrant, MLflow, and Ollama where applicable.
8. Replans as new targets and credentials appear, using deterministic in-memory indexes.
9. Runs compatible authenticated collection, differential MCP resource-access proofs, eligible reversible ContextForge round trips, and deep Ollama compute verification.
10. Retries only unresolved cleanup records and finalizes the same artifact.

The local planner uses standard Go maps. It embeds no database, LLM, workflow engine, or numeric risk model.

## Exclusions

`--exclude` is repeatable and accepts exact hostnames, IP addresses, and CIDRs. No AgentHound-owned network connection is made to an excluded destination. The same immutable policy guards configured enumeration, discovery, redirects, derived management and cleanup URLs, JWKS retrieval, and final socket dials. A launched stdio MCP child is not a network sandbox.

## Credentials and artifacts

The JSON artifact is intentionally plain. Concrete secrets are neither encrypted nor redacted in collector output. The CLI prints each newly discovered raw value once unless `--quiet`; the dashboard masks only the exact `value` property on Credential nodes and provides Reveal and Copy controls.

Execution state lives under `meta.extra.scan_execution`; there is no vault file, receipt directory, engagement, campaign, or witness artifact. If a reversible action cannot confirm cleanup, forward work stops. Retry it with:

```bash
agenthound revert scan-<scan_id>.json
```

`revert` walks unresolved recovery records newest-first, reconstructs the scan's recorded exclusions, observes live state before changing anything, refuses to overwrite third-party changes, and checkpoints every attempt.

## Optional server and dashboard

Manual ingest retains the complete execution journal and runs the full Neo4j-backed analysis pipeline: attack paths, risk scoring, findings, history, triage, rules, and queries. Same-scan MCP credential proof is represented as `CREDENTIAL_ACCESS_OBSERVED`; matching `CAN_REACH` paths are shown as **Verified During Scan**.

The UI remains an inspection surface. It is not required for the collector to discover services, reuse eligible credentials, or execute its bounded same-run proofs.

## Development

```bash
go test ./... -race
go vet ./...
make deps-check
make size-check
cd server/ui && npm test && npm run build
```

The collector remains a static binary with no server, Neo4j, or PostgreSQL dependency. See the [module guide](docs/contributing/modules.md) for adding service collectors and planner actions.

<!-- Release automation updates this compatibility pin:
https://raw.githubusercontent.com/adithyan-ak/agenthound/1.0.0/install.sh
-->
