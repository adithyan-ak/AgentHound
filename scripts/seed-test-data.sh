#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AGENTHOUND_URL:-http://localhost:8080}"

for file in testdata/valid_*.json; do
    echo "Ingesting $file..."
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d @"$file" \
        "${BASE_URL}/api/v1/ingest")

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | head -n -1)

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
