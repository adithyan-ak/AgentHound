# AgentHound isolated demo lab

This lab demonstrates the unified collector against synthetic MCP services. AgentHound runs only inside the isolated workstation container; the host supplies Docker and a browser.

## Start

```bash
export AGENTHOUND_DEMO_UID="$(id -u)"
export AGENTHOUND_DEMO_GID="$(id -g)"

docker compose -f demo/defcon/compose.yml down --volumes --remove-orphans
docker compose -f demo/defcon/compose.yml up -d --wait --build
curl -fsS http://127.0.0.1:18080/api/v1/health
```

## Run one scan

The workstation contains an unauthenticated devtools MCP configuration and an authenticated CRM MCP configuration. The latter's concrete bearer is deliberately present in the fixture config, so the same scan can collect it and perform differential resource-access proof.

```bash
docker compose -f demo/defcon/compose.yml exec workstation \
  agenthound scan --timeout 5m --output /demo/artifacts/scan.json
```

Expected behavior:

- local configs and raw Credential values are captured;
- both configured MCP servers are enumerated;
- the local planner attempts compatible collection and exact MCP access proof;
- `meta.extra.scan_execution` contains every action and recovery transition;
- the single artifact is ready for manual ingest.

## Ingest and inspect

```bash
docker compose -f demo/defcon/compose.yml exec agenthound-server \
  agenthound-server ingest /demo/artifacts/scan.json
```

Open <http://127.0.0.1:18080>. Inspect the `augment -> customers-database` path and its same-scan proof. A successful differential read is labeled **Verified During Scan** at confidence 100%. The credential value is masked in normal properties and available through Reveal or Copy.

There is no witness export, campaign, second collector run, engagement ID, or separate recovery file.

## Stop or reset

```bash
docker compose -f demo/defcon/compose.yml down
docker compose -f demo/defcon/compose.yml down --volumes --remove-orphans
```

All target data and credentials are synthetic.
