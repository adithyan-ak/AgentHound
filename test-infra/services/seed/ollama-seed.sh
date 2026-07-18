#!/bin/sh
set -eu

OLLAMA_URL="${OLLAMA_URL:-http://ollama:11434}"
MODEL="qwen2:0.5b"
MODEL_DIGEST="6f48b936a09f7743c7dd30e72fdb14cba296bc5861902e4d0c387e8fb5050b39"

if [ "${OLLAMA_URL}" != "http://ollama:11434" ]; then
	echo "refusing destructive fixture reconciliation outside the compose Ollama target" >&2
	exit 1
fi

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

# The named volume can survive a --keep debugging run. Reconcile it to the
# exact truth set through Ollama's real delete API before asserting inventory.
curl --fail --silent --show-error "${OLLAMA_URL}/api/tags" |
	jq -r '.models[].name' |
	while IFS= read -r installed; do
		if [ "${installed}" != "${MODEL}" ]; then
			curl --fail --silent --show-error --request DELETE \
				--header 'Content-Type: application/json' \
				--data "$(jq -nc --arg model "${installed}" '{model:$model}')" \
				"${OLLAMA_URL}/api/delete" >/dev/null
		fi
	done

curl --fail --silent --show-error "${OLLAMA_URL}/api/tags" |
	jq -e --arg model "${MODEL}" --arg digest "${MODEL_DIGEST}" '
		[.models[] | {model,digest}] == [{model:$model,digest:$digest}]
	' >/dev/null || {
		echo "Ollama registry content for ${MODEL} does not match the reviewed digest" >&2
		exit 1
	}

echo "Seeded Ollama model ${MODEL}"
