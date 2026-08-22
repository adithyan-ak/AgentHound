# Quickstart

## 1. Run a scan

An active targetless scan is the fastest useful starting point:

```bash
agenthound scan
```

It collects local MCP configuration, instruction sources, and credentials; seeds loopback, active local interfaces, and configured endpoints; discovers supported AI services; and runs eligible same-scan access proofs.

Add network scope when needed:

```bash
agenthound scan 10.20.0.0/24
agenthound scan @targets.txt --deep --exclude 10.20.0.15
```

Use stealth mode when the operation must remain read-only:

```bash
agenthound scan --stealth
```

## 2. Preserve the result

The collector continuously updates `scan-<scan_id>.json`. The artifact contains the collected graph, raw credential values, action outcomes, and any recovery records.

The final summary reports nodes, edges, actions, and unresolved cleanup. If cleanup needs another attempt, keep the artifact and run:

```bash
agenthound revert scan-<scan_id>.json
```

## 3. Ingest for full analysis

Start the optional analysis stack:

```bash
curl -sSfL \
  https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.1/docker/docker-compose.public.yml \
  -o agenthound-compose.yml
docker compose -f agenthound-compose.yml -p agenthound up -d --wait
```

Move the artifact to that system and ingest it:

```bash
docker compose -f agenthound-compose.yml -p agenthound exec -T agenthound \
  agenthound-server ingest - < scan-6c6306d5.json
```

If `agenthound-server` is installed directly on the analysis host, use `agenthound-server ingest scan-6c6306d5.json` instead.

Open `http://127.0.0.1:8080` to inspect attack paths, findings, risk, queries, history, and triage. Credential values are masked in the normal property view and remain available through Reveal and Copy.

Next, read the [Scanner guide](../operator/scanner.md) for targeting and mode details or [Attack paths](../operator/attack-paths.md) for analysis.
