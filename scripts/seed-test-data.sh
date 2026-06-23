#!/usr/bin/env bash
set -euo pipefail

# Ingests every testdata/valid_*.json into a running agenthound-server.
# Curl sends no Origin header, so OriginGuard admits the request as a
# non-browser caller — no token, no env vars, no auth setup.
BASE_URL="${AGENTHOUND_URL:-http://localhost:8080}"

for file in testdata/valid_*.json; do
    echo "Ingesting $file..."
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d @"$file" \
        "${BASE_URL}/api/v1/ingest")

    http_code=$(printf '%s\n' "$response" | tail -n 1)
    # `head -n -1` is GNU-only (not BSD/macOS). Use sed to drop the
    # last line portably.
    body=$(printf '%s\n' "$response" | sed '$d')

    if [ "$http_code" = "200" ]; then
        echo "  OK: $body"
    else
        echo "  FAILED ($http_code): $body"
        exit 1
    fi
done

echo ""
echo "Seed complete. Checking stats..."
curl -s "${BASE_URL}/api/v1/graph/stats" | python3 -m json.tool 2>/dev/null || \
    curl -s "${BASE_URL}/api/v1/graph/stats"
