# Quickstart

## 1. Install the collector

```bash
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
agenthound version
```

## 2. Run one scan

The default is active and needs no server:

```bash
agenthound scan
```

This collects local configuration and instruction sources, saves concrete raw credentials, seeds local and configured targets, discovers reachable services, and executes eligible same-run proofs. It continuously updates `scan-<scan_id>.json`.

To add network scope:

```bash
agenthound scan 10.20.0.0/24
```

For read-only collection:

```bash
agenthound scan --stealth
```

For recursive and expensive collection:

```bash
agenthound scan 10.20.0.0/24 --deep --exclude 10.20.0.15
```

## 3. Inspect the operational result

The CLI prints newly discovered raw credential values unless `--quiet`, followed by node, edge, action, and unresolved-cleanup counts. The plain JSON artifact contains the graph and `meta.extra.scan_execution` action/recovery journal.

If cleanup remains unresolved, retain the artifact and retry:

```bash
agenthound revert scan-<scan_id>.json
```

## 4. Optionally ingest later

Start the server/UI:

```bash
curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/docker/docker-compose.public.yml \
  | docker compose -f - -p agenthound up -d --wait
```

Ingest manually:

```bash
agenthound-server ingest scan-<scan_id>.json
```

Open `http://127.0.0.1:8080`. The dashboard adds full-graph paths, findings, risk, queries, history, and triage. Credential values are masked in normal node properties but are one click from Reveal or Copy.

The server is not involved in the foothold-time planner and does not need to be reachable during collection.
