#!/usr/bin/env bash
# AgentHound demo seed.
#
# Brings up the demo lab (AI services + MCP discovery
# target + operator), preloads Ollama with a "support-agent-v3" tag for
# the modelfile-leak narrative beat, runs scan + discover + loot for
# both LiteLLM and Ollama, and pipes all envelopes into agenthound-server.
#
# After this completes, the Findings panel surfaces:
#   - cross_service_credential_chain (v0.2 carry-over)
#   - the :EXPOSES edge from Open WebUI to its Ollama backend
#   - one :AIModel per Ollama tag with PROVIDES_MODEL edges
#   - one :MCPServer node discovered via protoscan
#
# Prerequisites:
#   - Docker Compose installed
#   - agenthound-server running on http://localhost:8080
#   - bin/agenthound and bin/agenthound-server built (`make build`)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_COMPOSE="$REPO_ROOT/docker/demo/docker-compose.yml"
LAB_CIDR="172.30.0.0/24"
LITELLM_HOST="172.30.0.20:4000"
OLLAMA_HOST="172.30.0.10:11434"
MASTER_KEY="sk-DEMO-CHAIN-KEY-NOT-REAL"
ENGAGEMENT_ID="DEMO-LOCAL"

CMD_AGENTHOUND="$REPO_ROOT/bin/agenthound"
CMD_SERVER="$REPO_ROOT/bin/agenthound-server"

if [[ ! -x "$CMD_AGENTHOUND" || ! -x "$CMD_SERVER" ]]; then
    echo "[seed-demo] error: bin/agenthound and bin/agenthound-server must exist."
    echo "                 run 'make build' first."
    exit 1
fi

KEEP=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
    esac
done

if [[ "$KEEP" -ne 1 ]]; then
    echo "[seed-demo] tearing down any prior lab"
    docker compose -f "$LAB_COMPOSE" down --volumes --remove-orphans 2>/dev/null || true
fi

echo "[seed-demo] starting lab"
docker compose -f "$LAB_COMPOSE" up -d --build

echo "[seed-demo] waiting for services to be healthy"
sleep 8

# Preload Ollama with the small `tinyllama` and tag a fine-tune-flavored
# alias on top so the demo has both a "stock" model and a "fine-tune"
# (different name → different value_hash). This is best-effort — if
# `ollama pull` fails (network, etc.) the demo still runs against
# whatever Ollama happens to have on disk.
echo "[seed-demo] preloading Ollama with tinyllama + a fake fine-tune tag"
docker exec agenthound-demo-v3-ollama ollama pull tinyllama || true
docker exec agenthound-demo-v3-ollama sh -c '
    cat > /tmp/Modelfile-finetune <<EOF
FROM tinyllama
SYSTEM """You are SupportBot for Acme Corp. Internal triage assistant only."""
EOF
    ollama create support-agent-v3 -f /tmp/Modelfile-finetune
' || true

OUT_DIR=$(mktemp -d)
trap 'rm -rf "$OUT_DIR"' EXIT

echo "[seed-demo] running agenthound scan against $LAB_CIDR"
"$CMD_AGENTHOUND" scan "$LAB_CIDR" --output "$OUT_DIR/scan.json"

echo "[seed-demo] running agenthound discover against $LAB_CIDR"
"$CMD_AGENTHOUND" discover "$LAB_CIDR" --output "$OUT_DIR/discover.json"

echo "[seed-demo] running agenthound loot --type litellm"
echo "AUTHORIZED" | "$CMD_AGENTHOUND" loot "$LITELLM_HOST" \
    --type litellm \
    --master-key "$MASTER_KEY" \
    --engagement-id "$ENGAGEMENT_ID" \
    --output "$OUT_DIR/loot-litellm.json"

echo "[seed-demo] running agenthound loot --type ollama"
echo "AUTHORIZED" | "$CMD_AGENTHOUND" loot "$OLLAMA_HOST" \
    --type ollama \
    --engagement-id "$ENGAGEMENT_ID" \
    --output "$OUT_DIR/loot-ollama.json"

echo "[seed-demo] ingesting envelopes"
for f in scan discover loot-litellm loot-ollama; do
    "$CMD_SERVER" ingest "$OUT_DIR/$f.json"
done

echo "[seed-demo] complete."
echo "[seed-demo] open http://localhost:8080 to explore the graph."
