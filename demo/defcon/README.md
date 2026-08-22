# AgentHound isolated demo

This lab runs AgentHound against synthetic MCP services on a disposable Docker network. The workstation fixture contains the collector and sample client configuration; the host provides Docker and a browser.

## Start

```bash
export AGENTHOUND_DEMO_UID="$(id -u)"
export AGENTHOUND_DEMO_GID="$(id -g)"

docker compose -f demo/defcon/compose.yml down --volumes --remove-orphans
docker compose -f demo/defcon/compose.yml up -d --wait --build
curl -fsS http://127.0.0.1:18080/api/v1/health
```

## Scan

The workstation has an anonymous devtools MCP endpoint and an authenticated CRM endpoint. Its synthetic bearer credential lets the same scan perform a differential resource-access proof.

```bash
docker compose -f demo/defcon/compose.yml exec workstation \
  agenthound scan --timeout 5m --output /demo/artifacts/scan.json
```

The artifact contains local configuration, raw Credential material, MCP enumeration, planner action results, and the collected graph.

## Ingest and inspect

```bash
docker compose -f demo/defcon/compose.yml exec agenthound-server \
  agenthound-server ingest /demo/artifacts/scan.json
```

Open <http://127.0.0.1:18080>. Inspect the `augment` path to the customer resource. A successful differential read appears as **Verified During Scan** at confidence 100%. Credential values are masked in normal properties and available through Reveal or Copy.

## Stop

```bash
docker compose -f demo/defcon/compose.yml down
```

Delete all lab data and volumes:

```bash
docker compose -f demo/defcon/compose.yml down --volumes --remove-orphans
```

All target data and credentials in this lab are synthetic.
