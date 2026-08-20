<div align="center">

<img src="docs/readme-assets/agenthound-banner.png" alt="AgentHound" width="100%">

### Autonomous offensive collection for AI agent infrastructure

**MCP · A2A · model gateways · inference servers · vector stores · MLOps · notebooks**

[Quickstart](#quickstart) · [Scan modes](#scan-modes) · [Documentation](https://docs.agenthound.io)

[![CI](https://github.com/adithyan-ak/agenthound/actions/workflows/ci.yml/badge.svg)](https://github.com/adithyan-ak/agenthound/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

</div>

> Use AgentHound only on systems you own or are authorized to assess.

AgentHound is built for the short operational window after a host is compromised. One `scan` collects local evidence, discovers reachable AI services, captures concrete credentials, reuses compatible credentials, verifies access, and restores reversible probes immediately. Progress is checkpointed to one plain JSON artifact so useful evidence survives an interrupted session.

The `agenthound` collector performs the foothold-time work. The optional `agenthound-server` ingests the finished artifact for graph analysis, findings, queries, triage, and dashboard inspection.

## Quickstart

Install AgentHound 1.1.0:

```bash
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.0/install.sh \
  | AGENTHOUND_VERSION=1.1.0 sh
export PATH="$HOME/.local/bin:$PATH"
```

Run an active scan of the local host and locally reachable AI services:

```bash
agenthound scan
```

Add a host, CIDR, or targets file without disabling local collection:

```bash
agenthound scan 10.20.0.0/24
agenthound scan @targets.txt --deep --exclude 10.20.0.15
```

The result is `scan-<scan_id>.json` unless `--output` selects another file. Move it to the analysis system for optional ingestion when convenient.

See the [Quickstart](docs/getting-started/quickstart.md) for the complete first-run workflow.

## Scan modes

| Command | Behavior |
|---|---|
| `agenthound scan` | Collects broadly, uses compatible credentials, verifies MCP access, and runs eligible reversible ContextForge probes. |
| `agenthound scan --deep` | Adds recursive instruction collection, Qdrant payload sampling, expensive probes, and bounded Ollama embedding verification. |
| `agenthound scan --stealth` | Performs anonymous read-only collection and exact configured authentication without credential reuse, compute, tool invocation, or mutation. |
| `agenthound scan --stealth --deep` | Adds deep read-only collection while retaining stealth restrictions. |

Concrete credential values are stored in the artifact and printed once unless `--quiet` is set. Treat the artifact as sensitive. The dashboard masks Credential `value` properties by default and provides Reveal and Copy controls.

If a reversible probe cannot confirm restoration, the collector stops forward work and preserves recovery data in the artifact:

```bash
agenthound revert scan-<scan_id>.json
```

## Optional analysis server

Start the server, Neo4j, PostgreSQL, and dashboard with Docker Compose:

```bash
curl -sSfL \
  https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.0/docker/docker-compose.public.yml \
  -o agenthound-compose.yml
docker compose -f agenthound-compose.yml -p agenthound up -d --wait
docker compose -f agenthound-compose.yml -p agenthound exec -T agenthound \
  agenthound-server ingest - < scan-6c6306d5.json
```

The dashboard is available at `http://127.0.0.1:8080`. It presents full-graph attack paths, risk scores, findings, queries, history, and triage. Same-scan MCP credential proofs appear as **Verified During Scan**.

## Documentation

- [Install](docs/getting-started/install.md)
- [Scanner guide](docs/operator/scanner.md)
- [CLI reference](docs/reference/cli.md)
- [Attack paths](docs/operator/attack-paths.md)
- [Deployment](docs/operator/deployment.md)
- [Development setup](docs/contributing/dev-setup.md)

## Development

```bash
go test ./... -race
go vet ./...
make deps-check
make size-check
cd server/ui && npm test && npm run build
```

The collector remains a static binary with no Neo4j, PostgreSQL, or server dependency. See [Writing modules](docs/contributing/modules.md) to extend service collection or planner actions.
