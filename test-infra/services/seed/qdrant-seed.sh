#!/bin/sh
set -eu

QDRANT_URL="${QDRANT_URL:-http://qdrant:6333}"

attempt=0
until curl --connect-timeout 2 --max-time 5 --fail --silent --show-error \
	"${QDRANT_URL}/readyz" >/dev/null 2>&1; do
	attempt=$((attempt + 1))
	if [ "${attempt}" -ge 60 ]; then
		echo "Qdrant did not become ready at ${QDRANT_URL}" >&2
		exit 1
	fi
	sleep 2
done

for collection in docs chat-history; do
	curl --silent --show-error --request DELETE \
		"${QDRANT_URL}/collections/${collection}" >/dev/null
done

curl --fail --silent --show-error --request PUT \
	--header 'Content-Type: application/json' \
	--data '{"vectors":{"size":4,"distance":"Cosine"}}' \
	"${QDRANT_URL}/collections/docs" >/dev/null

curl --fail --silent --show-error --request PUT \
	--header 'Content-Type: application/json' \
	--data-binary @- \
	"${QDRANT_URL}/collections/docs/points?wait=true" >/dev/null <<'JSON'
{
  "points": [
    {
      "id": 1,
      "vector": [0.1, 0.2, 0.3, 0.4],
      "payload": {
        "title": "Agent security runbook",
        "content": "Use sk-placeholder-qdrant-key-not-real for local QA only."
      }
    },
    {
      "id": 2,
      "vector": [0.4, 0.3, 0.2, 0.1],
      "payload": {
        "title": "Collector notes",
        "content": "Deterministic Qdrant fixture point."
      }
    }
  ]
}
JSON

curl --fail --silent --show-error --request PUT \
	--header 'Content-Type: application/json' \
	--data '{"vectors":{"size":4,"distance":"Dot"}}' \
	"${QDRANT_URL}/collections/chat-history" >/dev/null

curl --fail --silent --show-error --request PUT \
	--header 'Content-Type: application/json' \
	--data-binary @- \
	"${QDRANT_URL}/collections/chat-history/points?wait=true" >/dev/null <<'JSON'
{
  "points": [
    {
      "id": 101,
      "vector": [1.0, 0.0, 0.0, 0.0],
      "payload": {
        "role": "user",
        "content": "Summarize the local QA environment."
      }
    },
    {
      "id": 102,
      "vector": [0.0, 1.0, 0.0, 0.0],
      "payload": {
        "role": "assistant",
        "content": "The environment contains only non-production fixture data."
      }
    }
  ]
}
JSON

for collection in docs chat-history; do
	curl --fail --silent --show-error \
		"${QDRANT_URL}/collections/${collection}" |
		grep --extended-regexp '"points_count"[[:space:]]*:[[:space:]]*2' >/dev/null
done

echo "Seeded Qdrant collections docs and chat-history"
