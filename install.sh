#!/bin/sh
set -e

REPO="ghcr.io/adithyan-ak/agenthound"
TAG="allinone"
NAME="agenthound"
PORT="${AGENTHOUND_PORT:-8080}"

echo ""
echo "  AgentHound Installer"
echo "  ===================="
echo ""

# ── Detect container runtime ──
if command -v docker >/dev/null 2>&1; then
  RUNTIME="docker"
elif command -v podman >/dev/null 2>&1; then
  RUNTIME="podman"
else
  echo "Error: Docker or Podman is required."
  echo ""
  echo "Install Docker: https://docs.docker.com/get-docker/"
  exit 1
fi

$RUNTIME info >/dev/null 2>&1 || {
  echo "Error: $RUNTIME daemon is not running."
  echo "Start it and try again."
  exit 1
}

# ── Check port availability ──
if command -v lsof >/dev/null 2>&1 && lsof -i ":$PORT" >/dev/null 2>&1; then
  echo "Error: Port $PORT is already in use."
  echo ""
  echo "Use a different port:"
  echo "  AGENTHOUND_PORT=9090 sh -c \"\$(curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/main/install.sh)\""
  exit 1
fi

# ── Stop existing container if running ──
if $RUNTIME ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${NAME}$"; then
  echo "Stopping existing AgentHound container..."
  $RUNTIME stop "$NAME" 2>/dev/null || true
  $RUNTIME rm "$NAME" 2>/dev/null || true
fi

# ── Pull and run ──
echo "Pulling AgentHound image..."
$RUNTIME pull "$REPO:$TAG"

echo "Starting AgentHound on port $PORT..."
$RUNTIME run -d \
  --name "$NAME" \
  -p "${PORT}:8080" \
  -v agenthound-data:/data \
  --restart unless-stopped \
  "$REPO:$TAG"

# ── Wait for healthy ──
echo ""
echo "Waiting for services to start (this takes ~30s)..."
ATTEMPTS=0
while [ $ATTEMPTS -lt 45 ]; do
  if curl -sf "http://localhost:${PORT}/api/v1/health" >/dev/null 2>&1; then
    echo ""
    echo "  AgentHound is running!"
    echo ""
    echo "  URL:     http://localhost:${PORT}"
    echo "  Login:   admin / agenthound"
    echo ""
    echo "  Commands:"
    echo "    Stop:    $RUNTIME stop $NAME"
    echo "    Start:   $RUNTIME start $NAME"
    echo "    Logs:    $RUNTIME logs -f $NAME"
    echo "    Remove:  $RUNTIME rm -f $NAME && $RUNTIME volume rm agenthound-data"
    echo ""
    echo "  Data persisted in Docker volume: agenthound-data"
    echo "  Minimum requirements: 2 CPU, 2GB RAM"
    echo ""
    exit 0
  fi
  ATTEMPTS=$((ATTEMPTS + 1))
  sleep 2
  printf "."
done

echo ""
echo ""
echo "Warning: Health check timed out after 90s."
echo "Check logs: $RUNTIME logs $NAME"
exit 1
