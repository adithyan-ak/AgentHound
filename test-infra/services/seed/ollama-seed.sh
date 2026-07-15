#!/bin/sh
set -eu

OLLAMA_URL="${OLLAMA_URL:-http://ollama:11434}"
MODEL="qwen2:0.5b"

attempt=0
until curl --connect-timeout 2 --max-time 5 --fail --silent --show-error \
	"${OLLAMA_URL}/api/version" >/dev/null 2>&1; do
	attempt=$((attempt + 1))
	if [ "${attempt}" -ge 60 ]; then
		echo "Ollama did not become ready at ${OLLAMA_URL}" >&2
		exit 1
	fi
	sleep 2
done

curl --fail --silent --show-error --max-time 1800 \
	--header 'Content-Type: application/json' \
	--data '{"model":"qwen2:0.5b","stream":false}' \
	"${OLLAMA_URL}/api/pull" >/dev/null

curl --fail --silent --show-error "${OLLAMA_URL}/api/tags" |
	grep --fixed-strings "\"model\":\"${MODEL}\"" >/dev/null

echo "Seeded Ollama model ${MODEL}"
