# Quickstart

## 1. Run a scan

An active targetless scan is the fastest useful starting point:

```bash
agenthound scan --output scan.json
```

It collects local MCP configuration, instruction sources, and credentials; seeds loopback, active local interfaces, and configured endpoints; discovers supported AI services; and runs eligible same-scan access proofs.

Add network scope when needed:

```bash
agenthound scan 10.20.0.0/24 --output scan.json
agenthound scan @targets.txt --deep --exclude 10.20.0.15 --output scan.json
```

Use stealth mode when the operation must remain read-only:

```bash
agenthound scan --stealth --output scan.json
```

## 2. Preserve the result

Choose one of the commands above. Each continuously updates `scan.json`.
Without `--output`, the collector writes `scan-<scan_id>.json`. An explicit
output path replaces an existing file, so use a new name for each scan. The
artifact contains the collected graph, raw credential values, action outcomes,
and any recovery records.

The final summary reports nodes, edges, actions, and unresolved cleanup. If cleanup needs another attempt, keep the artifact and run:

```bash
agenthound revert scan.json
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
  agenthound-server ingest - < scan.json
```

If `agenthound-server` is installed directly on the analysis host, use `agenthound-server ingest scan.json` instead.

The ingest result reports the collector version, artifact contract, and server
version. An unsupported-contract error reports the same compatibility details
before database initialization. Upgrade the server instead of editing the
artifact.

Open `http://127.0.0.1:8080` to inspect attack paths, findings, risk, queries, history, and triage. Credential values are masked in the normal property view and remain available through Reveal and Copy.

Next, read the [Scanner guide](../operator/scanner.md) for targeting and mode details or [Attack paths](../operator/attack-paths.md) for analysis.
