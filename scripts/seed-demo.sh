#!/usr/bin/env bash
# AgentHound demo seed.
#
# Brings up the analysis stack plus demo lab, runs all collector actions from
# a Docker-network-local runner, ingests envelopes through the HTTP API, and
# validates the flagship LiteLLM credential-chain finding.
#
# After this completes, the Findings panel surfaces:
#   - cross_service_credential_chain (v0.2 carry-over)
#   - the :EXPOSES edge from Open WebUI to its Ollama backend
#   - one :AIModel per Ollama tag with PROVIDES_MODEL edges
#   - one :MCPServer node discovered via protoscan
#
# Prerequisites:
#   - Docker Compose installed
#   - curl + python3 on the host (checked by preflight)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_COMPOSE="$REPO_ROOT/docker/docker-compose.yml"
SERVER_DEMO_COMPOSE="$REPO_ROOT/docker/demo/docker-compose.server-demo.yml"
LAB_COMPOSE="$REPO_ROOT/docker/demo/docker-compose.yml"
# Demo lab hosts (static IPs from docker/demo/docker-compose.yml). We scan an
# explicit host list rather than the whole 172.30.0.0/24 so the demo reports
# the real services instead of 254 Docker-bridge phantoms — every address on a
# bridge network accepts TCP connects, so a /24 sweep "finds" 256 identical
# hosts (see docs/operator/scanner.md).
LAB_HOSTS=(172.30.0.10 172.30.0.20 172.30.0.30 172.30.0.40 172.30.0.50 172.30.0.60 172.30.0.70 172.30.0.80)
LITELLM_HOST="172.30.0.20:4000"
OLLAMA_HOST="172.30.0.10:11434"
MASTER_KEY="sk-DEMO-CHAIN-KEY-NOT-REAL"
ENGAGEMENT_ID="DEMO-LOCAL"
OUT_DIR="$REPO_ROOT/docker/demo/out"
RUNNER=(docker compose -f "$LAB_COMPOSE" --profile tools run --rm -T collector-runner)
SERVER_COMPOSE_CMD=(docker compose -f "$SERVER_COMPOSE" -f "$SERVER_DEMO_COMPOSE")

KEEP=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
    esac
done

if [[ "$KEEP" -ne 1 ]]; then
    echo "[seed-demo] tearing down prior lab and analysis volumes"
    docker compose -f "$LAB_COMPOSE" down --volumes --remove-orphans 2>/dev/null || true
    "${SERVER_COMPOSE_CMD[@]}" down --volumes --remove-orphans 2>/dev/null || true
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/home"

port_available() {
    python3 - "$1" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        raise SystemExit(1)
PY
}

choose_server_endpoint() {
    if [[ -n "${AGENTHOUND_DEMO_BIND:-}" ]]; then
        export AGENTHOUND_DEMO_BIND
        SERVER_URL="${AGENTHOUND_DEMO_SERVER_URL:-http://127.0.0.1:${AGENTHOUND_DEMO_BIND##*:}}"
        return
    fi

    local port
    for port in 8080 18080 18081 18082 18083 18084 18085 18086 18087 18088 18089; do
        if port_available "$port"; then
            export AGENTHOUND_DEMO_BIND="127.0.0.1:$port"
            SERVER_URL="${AGENTHOUND_DEMO_SERVER_URL:-http://127.0.0.1:$port}"
            return
        fi
    done

    echo "[seed-demo] error: no free host port found for AgentHound UI/API" >&2
    echo "[seed-demo]        set AGENTHOUND_DEMO_BIND=127.0.0.1:<port> to choose one" >&2
    exit 1
}

wait_for_server() {
    local attempts=60
    local body="$OUT_DIR/health.json"
    echo "[seed-demo] waiting for AgentHound server health"
    for _ in $(seq 1 "$attempts"); do
        if curl -fsS --max-time 2 "$SERVER_URL/api/v1/health" -o "$body" 2>/dev/null &&
            python3 - "$body" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
if data.get("status") != "ok":
    raise SystemExit(1)
PY
        then
            return 0
        fi
        sleep 2
    done
    echo "[seed-demo] error: server did not become healthy at $SERVER_URL" >&2
    return 1
}

ingest() {
    local name="$1"
    local path="$OUT_DIR/$name.json"
    echo "[seed-demo] ingesting $name"
    curl -fsS \
        -H "Content-Type: application/json" \
        --data-binary "@$path" \
        "$SERVER_URL/api/v1/ingest" >/dev/null
}

validate_demo() {
    local finding_json="$OUT_DIR/litellm-credential-leak.json"
    local stats_json="$OUT_DIR/graph-stats.json"

    echo "[seed-demo] validating LiteLLM credential-chain finding"
    curl -fsS "$SERVER_URL/api/v1/analysis/prebuilt/litellm-credential-leak" -o "$finding_json"
    python3 - "$finding_json" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
rows = data.get("rows") or []
if not rows:
    print("litellm-credential-leak returned zero rows", file=sys.stderr)
    raise SystemExit(1)
print(f"[seed-demo] litellm-credential-leak rows={len(rows)}")
PY

    echo "[seed-demo] validating graph facts"
    curl -fsS "$SERVER_URL/api/v1/graph/stats" -o "$stats_json"
    python3 - "$stats_json" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    stats = json.load(fh)
nodes = stats.get("node_counts") or {}
edges = stats.get("edge_counts") or {}
required_nodes = ["LiteLLMGateway", "OllamaInstance", "MCPServer", "A2AAgent", "AIModel"]
missing = [kind for kind in required_nodes if nodes.get(kind, 0) < 1]
if edges.get("EXPOSES_CREDENTIAL", 0) < 1:
    missing.append("EXPOSES_CREDENTIAL edge")
if missing:
    print("missing expected graph facts: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(1)
print("[seed-demo] graph facts validated")
PY
}

choose_server_endpoint
echo "[seed-demo] using AgentHound server at $SERVER_URL ($AGENTHOUND_DEMO_BIND)"

echo "[seed-demo] starting analysis stack"
"${SERVER_COMPOSE_CMD[@]}" up -d --build --wait
wait_for_server

echo "[seed-demo] starting lab"
docker compose -f "$LAB_COMPOSE" up -d --build --wait

# Materialize the explicit host list as an @targets file for scan/discover.
LAB_TARGETS="$OUT_DIR/lab-hosts.txt"
printf '%s\n' "${LAB_HOSTS[@]}" > "$LAB_TARGETS"

echo "[seed-demo] running agenthound scan --config for demo operator config"
"${RUNNER[@]}" scan --config \
    --path /demo/operator-config/claude_desktop_config.json \
    --output /out/config.json

echo "[seed-demo] running agenthound scan against ${#LAB_HOSTS[@]} lab hosts"
"${RUNNER[@]}" scan @/out/lab-hosts.txt --output /out/scan.json

echo "[seed-demo] running agenthound discover against ${#LAB_HOSTS[@]} lab hosts"
"${RUNNER[@]}" discover @/out/lab-hosts.txt --output /out/discover.json

echo "[seed-demo] running agenthound loot --type litellm"
echo "AUTHORIZED" | "${RUNNER[@]}" loot "$LITELLM_HOST" \
    --type litellm \
    --master-key "$MASTER_KEY" \
    --engagement-id "$ENGAGEMENT_ID" \
    --output /out/loot-litellm.json

echo "[seed-demo] running agenthound loot --type ollama"
echo "AUTHORIZED" | "${RUNNER[@]}" loot "$OLLAMA_HOST" \
    --type ollama \
    --engagement-id "$ENGAGEMENT_ID" \
    --output /out/loot-ollama.json

echo "[seed-demo] ingesting envelopes"
for f in config scan discover loot-litellm loot-ollama; do
    ingest "$f"
done

validate_demo

echo "[seed-demo] complete."
echo "[seed-demo] outputs kept in $OUT_DIR"
echo "[seed-demo] open $SERVER_URL to explore the graph."
