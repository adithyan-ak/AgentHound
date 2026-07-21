#!/usr/bin/env bash
set -Eeuo pipefail

VERIFY_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=assertions.sh
source "${VERIFY_SCRIPT_DIR}/assertions.sh"

COMPOSE_FILE="$1"
TRUTH_PATH="$2"

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

ws() {
  compose exec -T workstation "$@"
}

expect_jq() {
  local name="$1"
  local filter="$2"
  local body
  body="$(ws curl -fsS "$3")" || fail "upstream truth: ${name} request failed"
  printf '%s' "${body}" | jq -e "${filter}" >/dev/null ||
    fail "upstream truth: ${name} returned unexpected real data"
  if (($# == 4)); then
    printf -v "$4" '%s' "${body}"
  fi
  pass "upstream:${name}"
}

expect_jq ollama \
  '[.models[] | {model,digest}] == [{
    model:"qwen2:0.5b",
    digest:"6f48b936a09f7743c7dd30e72fdb14cba296bc5861902e4d0c387e8fb5050b39"
  }]' \
  http://ollama:11434/api/tags
expect_jq vllm \
  '.object == "list" and [.data[].id] == ["agenthound-vllm-fixture"]' \
  http://vllm:8000/v1/models
expect_jq openai-decoy \
  '.object == "list" and [.data[].id] == ["agenthound-openai-compatible-decoy"]' \
  http://openai-decoy:8000/v1/models
expect_jq qdrant \
  '([.result.collections[].name] | sort) == ["chat-history","docs"]' \
  http://qdrant:6333/collections

for collection in docs chat-history; do
  qdrant_collection="$(ws curl -fsS "http://qdrant:6333/collections/${collection}")"
  printf '%s' "${qdrant_collection}" | jq -e '.result.points_count == 2' >/dev/null ||
    fail "upstream truth: Qdrant ${collection} point count drifted"
done
qdrant_docs="$(ws curl -fsS -X POST \
  -H 'Content-Type: application/json' \
  --data '{"limit":100,"with_payload":true,"with_vector":false}' \
  http://qdrant:6333/collections/docs/points/scroll)"
printf '%s' "${qdrant_docs}" | jq -e '
  [.result.points[].id] == [1,2] and
  [.result.points[].payload.title] == [
    "Agent security runbook",
    "Collector notes"
  ]
' >/dev/null || fail 'upstream truth: Qdrant docs point inventory drifted'
qdrant_chat="$(ws curl -fsS -X POST \
  -H 'Content-Type: application/json' \
  --data '{"limit":100,"with_payload":true,"with_vector":false}' \
  http://qdrant:6333/collections/chat-history/points/scroll)"
printf '%s' "${qdrant_chat}" | jq -e '
  [.result.points[].id] == [101,102] and
  [.result.points[].payload.role] == ["user","assistant"]
' >/dev/null || fail 'upstream truth: Qdrant chat-history point inventory drifted'
pass upstream:qdrant-points

mlflow_experiments="$(ws curl -fsS \
  'http://mlflow:5000/api/2.0/mlflow/experiments/search?max_results=100')"
printf '%s' "${mlflow_experiments}" | jq -e '
  ([.experiments[].name] | sort) == ["Default","agenthound-offline-qa"]
' >/dev/null || fail 'upstream truth: MLflow experiment inventory drifted'
mlflow_experiment_ids="$(printf '%s' "${mlflow_experiments}" | jq -c \
  '[.experiments[].experiment_id]')"
mlflow_runs="$(ws curl -fsS -X POST \
  -H 'Content-Type: application/json' \
  --data "$(jq -nc --argjson ids "${mlflow_experiment_ids}" \
    '{experiment_ids:$ids,max_results:100}')" \
  http://mlflow:5000/api/2.0/mlflow/runs/search)"
printf '%s' "${mlflow_runs}" | jq -e '
  ((.next_page_token // "") == "") and
  (.runs | length) == 1 and
  ([.runs[0].data.tags[]? | select(
    .key == "agenthound.fixture_id" and .value == "agenthound-seed-v1"
  )] | length) == 1
' >/dev/null || fail 'upstream truth: MLflow run inventory drifted'
mlflow_models="$(ws curl -fsS \
  'http://mlflow:5000/api/2.0/mlflow/registered-models/search?max_results=100')"
printf '%s' "${mlflow_models}" | jq -e '
  [.registered_models[] | {name,versions:(.latest_versions | length)}] == [
    {name:"agenthound-fixture-model",versions:1}
  ]
' >/dev/null || fail 'upstream truth: MLflow registered-model inventory drifted'
pass upstream:mlflow
expect_jq langserve \
  '.title == "echo_input" or .title == "RunnableLambdaInput" or (.type != null)' \
  http://langserve:8000/echo/input_schema
expect_jq openwebui-posture \
  '.version == "0.10.2" and
   .features.auth == true and
   .features.enable_signup == false and
   .features.enable_login_form == true' \
  http://openwebui:3000/api/config

litellm_models="$(ws curl -fsS \
  -H 'Authorization: Bearer sk-local-agenthound-master-key-not-production' \
  http://litellm:4000/model/info)"
printf '%s' "${litellm_models}" | jq -e '
  ([.data[].model_name] | sort) ==
  ["agenthound-anthropic-placeholder","agenthound-openai-placeholder"]
' >/dev/null || fail 'upstream truth: LiteLLM model inventory drifted'
litellm_keys="$(ws curl -fsS \
  -H 'Authorization: Bearer sk-local-agenthound-master-key-not-production' \
  'http://litellm:4000/key/list?return_full_object=true&page=1&size=100')"
printf '%s' "${litellm_keys}" | jq -e '
  [.keys[] | {
    alias:.key_alias,
    models:(.models | sort),
    token_is_hash:(.token | test("^[0-9a-f]{64}$"))
  }] == [{
    alias:"agenthound-offline-fixture",
    models:["agenthound-anthropic-placeholder","agenthound-openai-placeholder"],
    token_is_hash:true
  }]
' >/dev/null || fail 'upstream truth: LiteLLM virtual-key inventory drifted'
pass upstream:litellm

jupyter_unauth_status="$(ws curl -sS -o /dev/null -w '%{http_code}' \
  http://jupyter:8888/api/contents)"
[[ "${jupyter_unauth_status}" == 401 || "${jupyter_unauth_status}" == 403 ]] ||
  fail "upstream truth: Jupyter contents unexpectedly anonymous (${jupyter_unauth_status})"
jupyter_contents="$(ws curl -fsS \
  -H 'Authorization: token agenthound-jupyter-token' \
  http://jupyter:8888/api/contents/work/agenthound-fixtures)"
printf '%s' "${jupyter_contents}" | jq -e '
  ([.content[].name] | sort) == ["agenthound-fixture.ipynb","data"]
' >/dev/null || fail 'upstream truth: Jupyter authenticated fixture inventory drifted'
jupyter_data="$(ws curl -fsS \
  -H 'Authorization: token agenthound-jupyter-token' \
  http://jupyter:8888/api/contents/work/agenthound-fixtures/data)"
printf '%s' "${jupyter_data}" | jq -e '
  [.content[].name] == ["support-context.md"]
' >/dev/null || fail 'upstream truth: Jupyter recursive fixture inventory drifted'
pass upstream:jupyter-auth

openwebui_token="$(jq -er '.openwebui.token' "$(dirname "${TRUTH_PATH}")/runtime.json")"
openai_config="$(ws curl -fsS -H "Authorization: Bearer ${openwebui_token}" \
  http://openwebui:3000/openai/config)"
printf '%s' "${openai_config}" | jq -e '
  .OPENAI_API_BASE_URLS == ["http://litellm:4000/v1"] and
  .OPENAI_API_KEYS == ["sk-agenthound-openwebui-upstream-not-production"]
' >/dev/null || fail 'upstream truth: Open WebUI authenticated upstream config drifted'
ollama_config="$(ws curl -fsS -H "Authorization: Bearer ${openwebui_token}" \
  http://openwebui:3000/ollama/config)"
printf '%s' "${ollama_config}" | jq -e '
  .OLLAMA_BASE_URLS == ["http://ollama:11434"]
' >/dev/null || fail 'upstream truth: Open WebUI Ollama config drifted'
pass upstream:openwebui-admin

# Real Streamable HTTP handshake and feature inventory from the official MCP
# everything server. This is independent of AgentHound's parser.
ws sh -s <<'SH'
set -eu
endpoint=http://mcp-streamable:3001/mcp
curl -sS -D /tmp/mcp.headers -o /tmp/mcp.init \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"roots":{"listChanged":true}},"clientInfo":{"name":"upstream-verifier","version":"1"}}}' \
  "${endpoint}"
session="$(awk 'BEGIN{IGNORECASE=1} /^mcp-session-id:/{gsub("\r",""); print $2}' /tmp/mcp.headers)"
test -n "${session}"
grep -q 'serverInfo' /tmp/mcp.init
curl -fsS -o /dev/null \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: ${session}" \
  --data '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  "${endpoint}"
request() {
  name="$1"
  id="$2"
  method="$3"
  curl -fsS -o "/tmp/mcp.${name}" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H "Mcp-Session-Id: ${session}" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"${method}\",\"params\":{}}" \
    "${endpoint}"
  if grep -q '^data:' "/tmp/mcp.${name}"; then
    sed -n 's/^data: //p' "/tmp/mcp.${name}" | tail -n 1 >"/tmp/mcp.${name}.json"
  else
    cp "/tmp/mcp.${name}" "/tmp/mcp.${name}.json"
  fi
}
request tools 2 tools/list
request resources 3 resources/list
request templates 4 resources/templates/list
request prompts 5 prompts/list
jq -e '
  ([.result.tools[].name] | sort) == ([
    "echo",
    "get-annotated-message",
    "get-env",
    "get-resource-links",
    "get-resource-reference",
    "get-roots-list",
    "get-structured-content",
    "get-sum",
    "get-tiny-image",
    "gzip-file-as-resource",
    "simulate-research-query",
    "toggle-simulated-logging",
    "toggle-subscriber-updates",
    "trigger-long-running-operation"
  ] | sort)
' /tmp/mcp.tools.json >/dev/null
jq -e '
  [.result.resources[] | {name,uri}] == [
    {name:"architecture.md",uri:"demo://resource/static/document/architecture.md"},
    {name:"extension.md",uri:"demo://resource/static/document/extension.md"},
    {name:"features.md",uri:"demo://resource/static/document/features.md"},
    {name:"how-it-works.md",uri:"demo://resource/static/document/how-it-works.md"},
    {name:"instructions.md",uri:"demo://resource/static/document/instructions.md"},
    {name:"startup.md",uri:"demo://resource/static/document/startup.md"},
    {name:"structure.md",uri:"demo://resource/static/document/structure.md"}
  ]
' /tmp/mcp.resources.json >/dev/null
jq -e '
  [.result.resourceTemplates[] | {name,uriTemplate}] == [
    {name:"Dynamic Text Resource",uriTemplate:"demo://resource/dynamic/text/{resourceId}"},
    {name:"Dynamic Blob Resource",uriTemplate:"demo://resource/dynamic/blob/{resourceId}"}
  ]
' /tmp/mcp.templates.json >/dev/null
jq -e '
  [.result.prompts[].name] == [
    "simple-prompt",
    "args-prompt",
    "completable-prompt",
    "resource-prompt"
  ]
' /tmp/mcp.prompts.json >/dev/null
SH
pass upstream:mcp-everything-streamable

# Exercise the two other real transports independently. These checks use the
# upstream wire protocols directly and do not consume collector output.
ws sh -s <<'SH'
set -eu
initialize='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"upstream-verifier","version":"1"}}}'
printf '%s\n' "${initialize}" |
  timeout 10 mcp-server-everything stdio 2>/tmp/mcp-stdio.stderr |
  head -n 1 >/tmp/mcp-stdio.init
jq -e '.result.serverInfo.name == "mcp-servers/everything"' /tmp/mcp-stdio.init >/dev/null

rm -f /tmp/mcp-sse.events
curl -fsSN http://mcp-sse:3001/sse >/tmp/mcp-sse.events &
sse_pid=$!
trap 'kill "${sse_pid}" 2>/dev/null || true' EXIT
attempt=0
while ! grep -q '^data: /message?sessionId=' /tmp/mcp-sse.events 2>/dev/null; do
  attempt=$((attempt + 1))
  [ "${attempt}" -lt 50 ] || exit 1
  sleep 0.1
done
message_path="$(sed -n 's/^data: //p' /tmp/mcp-sse.events | head -n 1 | tr -d '\r')"
curl -fsS -o /dev/null \
  -H 'Content-Type: application/json' \
  --data "${initialize}" \
  "http://mcp-sse:3001${message_path}"
attempt=0
while ! grep -q 'serverInfo' /tmp/mcp-sse.events; do
  attempt=$((attempt + 1))
  [ "${attempt}" -lt 50 ] || exit 1
  sleep 0.1
done
kill "${sse_pid}" 2>/dev/null || true
trap - EXIT
SH
pass upstream:mcp-everything-stdio-sse

expect_jq a2a-static-current \
  '.name == "PayrollAgent" and
   ([.supportedInterfaces[].protocolVersion] == ["1.0"]) and
   (.signatures | length) == 1' \
  http://a2a-static/.well-known/agent-card.json \
  a2a_static_current_card
legacy_current_status="$(ws curl -sS -o /dev/null -w '%{http_code}' \
  http://a2a-static/legacy/.well-known/agent-card.json)"
[[ "${legacy_current_status}" == 404 ]] ||
  fail 'upstream truth: static A2A target no longer exercises legacy fallback'
expect_jq a2a-static-legacy \
  '.name == "LegacyArchiveAgent" and .protocolVersion == "0.3.0" and
   (.defaultInputModes == ["application/json"]) and
   (.defaultOutputModes == ["application/json"]) and
   (has("signatures") | not)' \
  http://a2a-static/legacy/.well-known/agent.json \
  a2a_static_legacy_card
expect_jq a2a-dynamic \
  '.name == "ClaimsTriageAgent" and ([.supportedInterfaces[].protocolVersion] | sort) == ["0.3","1.0"]' \
  http://a2a-dynamic:9000/.well-known/agent-card.json \
  a2a_dynamic_v1_card
dynamic_legacy_current_status="$(ws curl -sS -o /dev/null -w '%{http_code}' \
  http://a2a-dynamic:9000/legacy/.well-known/agent-card.json)"
[[ "${dynamic_legacy_current_status}" == 404 ]] ||
  fail 'upstream truth: SDK v0.3 A2A target no longer exercises legacy card fallback'
expect_jq a2a-dynamic-v0.3 \
  '.name == "LegacySDKAgent" and .protocolVersion == "0.3" and
   .url == "http://a2a-dynamic:9000/legacy" and
   (has("supportedInterfaces") | not)' \
  http://a2a-dynamic:9000/legacy/.well-known/agent.json \
  a2a_dynamic_v03_card
expect_jq a2a-dynamic-protected \
  '.name == "ProtectedPaymentsAgent" and
   [.supportedInterfaces[].protocolVersion] == ["1.0"] and
   (.securityRequirements | length) == 1 and
   (.securityRequirements[0].schemes | has("api_key"))' \
  http://a2a-dynamic:9000/protected/.well-known/agent-card.json \
  a2a_dynamic_protected_card
expect_jq a2a-dynamic-ambiguous \
  '.name == "VersionAmbiguousAgent" and
   [.supportedInterfaces[].protocolVersion] == ["1.9"]' \
  http://a2a-dynamic:9000/ambiguous/.well-known/agent-card.json \
  a2a_dynamic_ambiguous_card

a2a_v1_response="$(ws curl -fsS \
  -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' \
  --data '{"jsonrpc":"2.0","id":"upstream-v1","method":"GetTask","params":{"id":"missing-upstream-v1"}}' \
  http://a2a-dynamic:9000/)"
printf '%s' "${a2a_v1_response}" | jq -e '
  .id == "upstream-v1" and .error.code == -32001 and
  .error.message == "Task not found" and
  (.error.data | any(.reason == "TASK_NOT_FOUND" and .domain == "a2a-protocol.org"))
' >/dev/null || fail 'upstream truth: official A2A v1 GetTask outcome drifted'
a2a_v03_response="$(ws curl -fsS \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":"upstream-v03","method":"tasks/get","params":{"id":"missing-upstream-v03"}}' \
  http://a2a-dynamic:9000/legacy)"
printf '%s' "${a2a_v03_response}" | jq -e '
  .id == "upstream-v03" and .error.code == -32603 and
  .error.message == "Task not found" and .error.data == null
' >/dev/null || fail 'upstream truth: official A2A v0.3 GetTask outcome drifted'
a2a_protected_status="$(ws curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' \
  --data '{"jsonrpc":"2.0","id":"upstream-protected-anon","method":"GetTask","params":{"id":"missing-upstream-protected-anon"}}' \
  http://a2a-dynamic:9000/protected)"
[[ "${a2a_protected_status}" == 401 ]] ||
  fail "upstream truth: protected A2A handler did not reject anonymous GetTask (${a2a_protected_status})"
a2a_protected_control="$(ws curl -fsS \
  -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' \
  -H 'X-API-Key: agenthound-a2a-api-key-not-production' \
  --data '{"jsonrpc":"2.0","id":"upstream-protected-auth","method":"GetTask","params":{"id":"missing-upstream-protected-auth"}}' \
  http://a2a-dynamic:9000/protected)"
printf '%s' "${a2a_protected_control}" | jq -e '
  .id == "upstream-protected-auth" and .error.code == -32001 and
  (.error.data | any(.reason == "TASK_NOT_FOUND"))
' >/dev/null || fail 'upstream truth: protected A2A exact-key control did not reach the official handler'
a2a_ambiguous_response="$(ws curl -fsS \
  -H 'Content-Type: application/json' -H 'A2A-Version: 1.9' \
  --data '{"jsonrpc":"2.0","id":"upstream-ambiguous","method":"GetTask","params":{"id":"missing-upstream-ambiguous"}}' \
  http://a2a-dynamic:9000/ambiguous)"
printf '%s' "${a2a_ambiguous_response}" | jq -e '
  .id == "upstream-ambiguous" and .error.code == -32009 and
  (.error.data | any(.reason == "VERSION_NOT_SUPPORTED"))
' >/dev/null || fail 'upstream truth: A2A ambiguous version control drifted'
a2a_probe_state="$(ws curl -fsS http://a2a-dynamic:9000/probe-state)"
printf '%s' "${a2a_probe_state}" | jq -e '
  all(.[];
    .non_get_task_requests == 0 and .executor_calls == 0 and
    .task_store_saves == 0 and .task_store_deletes == 0
  )
' >/dev/null || fail 'upstream truth: read-only A2A controls reached a mutation path'
pass upstream:a2a-runtime-auth-lanes

# Verify the ES256 AgentCardSignature independently with Node's crypto module.
# The authored card contains its complete proto-JSON presence representation;
# recursively sorting its ASCII field names therefore produces its JCS bytes.
ws node <<'JS'
const crypto = require('node:crypto');

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
}

(async () => {
  const card = await fetch('http://a2a-static/.well-known/agent-card.json').then((r) => r.json());
  const jwks = await fetch('http://a2a-static/.well-known/jwks.json').then((r) => r.json());
  if (!Array.isArray(card.signatures) || card.signatures.length !== 1) process.exit(1);
  const entry = card.signatures[0];
  const header = JSON.parse(Buffer.from(entry.protected, 'base64url'));
  const key = jwks.keys.find((candidate) => candidate.kid === header.kid);
  if (header.alg !== 'ES256' || header.typ !== 'JOSE' || !key) process.exit(1);
  const unsigned = {...card};
  delete unsigned.signatures;
  const payload = Buffer.from(JSON.stringify(canonical(unsigned)));
  const signingInput = Buffer.from(`${entry.protected}.${payload.toString('base64url')}`);
  const valid = crypto.verify(
    'sha256',
    signingInput,
    {key: crypto.createPublicKey({key, format: 'jwk'}), dsaEncoding: 'ieee-p1363'},
    Buffer.from(entry.signature, 'base64url'),
  );
  if (!valid) process.exit(1);
})().catch(() => process.exit(1));
JS
pass upstream:a2a-signature

runtime="$(dirname "${TRUTH_PATH}")/runtime.json"
contextforge_token="$(jq -er '.contextforge.token' "${runtime}")"
contextforge_tool_id="$(jq -er '.contextforge.tool_id' "${runtime}")"
contextforge_resource_id="$(jq -er '.contextforge.resource_id' "${runtime}")"
contextforge_server_id="$(jq -er '.contextforge.server_id' "${runtime}")"
contextforge_mcp_url="$(jq -er '.contextforge.mcp_url' "${runtime}")"

contextforge_version="$(ws curl -fsS \
  -H "Authorization: Bearer ${contextforge_token}" \
  http://contextforge:4444/v1/version)"
printf '%s' "${contextforge_version}" | jq -e '
  .app.name == "ContextForge" and
  .app.version == "1.0.5" and
  .app.mcp_protocol_version == "2025-11-25"
' >/dev/null || fail 'upstream truth: ContextForge release/protocol drifted'
pass upstream:contextforge-version

contextforge_tool="$(ws curl -fsS \
  -H "Authorization: Bearer ${contextforge_token}" \
  "http://contextforge:4444/v1/tools/${contextforge_tool_id}")"
printf '%s' "${contextforge_tool}" | jq -e '
  .name == "support-lookup" and
  .description == "Look up a customer support case by case ID."
' >/dev/null || fail 'upstream truth: ContextForge tool drifted'

contextforge_unauth_status="$(ws curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"control","version":"1"}}}' \
  "${contextforge_mcp_url}")"
[[ "${contextforge_unauth_status}" == 401 || "${contextforge_unauth_status}" == 403 ]] ||
  fail "upstream truth: ContextForge MCP control was not denied (${contextforge_unauth_status})"

ws sh -s -- "${contextforge_mcp_url}" "${contextforge_token}" <<'SH'
set -eu
endpoint="$1"
token="$2"
curl -fsS -D /tmp/cf.headers -o /tmp/cf.init \
  -H "Authorization: Bearer ${token}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"upstream-verifier","version":"1"}}}' \
  "${endpoint}"
grep -q 'serverInfo' /tmp/cf.init
# ContextForge v1.0.5's real virtual-server transport is stateless and does
# not issue an Mcp-Session-Id. Assert that pinned behavior independently.
if grep -qi '^mcp-session-id:' /tmp/cf.headers; then
  exit 1
fi
curl -fsS -o /dev/null \
  -H "Authorization: Bearer ${token}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  "${endpoint}"
curl -fsS -o /tmp/cf.tools \
  -H "Authorization: Bearer ${token}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  "${endpoint}"
jq -e '
  [.result.tools[] | {name,description}] == [{
    name:"support-lookup",
    description:"Look up a customer support case by case ID."
  }]
' /tmp/cf.tools >/dev/null
curl -fsS -o /tmp/cf.resource \
  -H "Authorization: Bearer ${token}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///data/support-cases/case-001.json"}}' \
  "${endpoint}"
grep -q 'case-001' /tmp/cf.resource
SH
pass upstream:contextforge-auth-gate

package_version="$(ws node -p \
  "require('/opt/mcp-everything/node_modules/@modelcontextprotocol/server-everything/package.json').version")"
[[ "${package_version}" == 2026.7.4 ]] ||
  fail "upstream truth: MCP package version ${package_version} is not pinned version"

# The config corpus is authored from current client documentation. Assert the
# complete fixture inventory, parse every JSON file independently, and prove
# that the only runtime-injected authenticated entry points at the real
# ContextForge server with the real one-time API token.
ws sh -s -- "${contextforge_mcp_url}" "${contextforge_token}" <<'SH'
set -eu
contextforge_url="$1"
contextforge_token="$2"
json_configs='
/root/.augment/settings.json
/root/.aws/amazonq/default.json
/root/.claude.json
/root/.codeium/windsurf/mcp_config.json
/root/.config/Code/User/mcp.json
/root/.config/zed/settings.json
/root/.cursor/mcp.json
/root/.junie/mcp/mcp.json
/root/.kiro/settings/mcp.json
/root/projects/example/.amazonq/default.json
/root/projects/example/.cline/mcp.json
/root/projects/example/.cursor/mcp.json
/root/projects/example/.junie/mcp/mcp.json
/root/projects/example/.kiro/settings/mcp.json
/root/projects/example/.mcp.json
/root/projects/example/.vscode/mcp.json
'
printf '%s\n' "${json_configs}" | sed '/^$/d' >/tmp/client-configs.list
[ "$(wc -l </tmp/client-configs.list | tr -d ' ')" -eq 16 ]
while IFS= read -r path; do
  test -f "${path}"
  jq -e 'type == "object"' "${path}" >/dev/null
done </tmp/client-configs.list

: "${AGENTHOUND_LITELLM_MASTER_KEY:?missing shared LiteLLM master fixture}"
: "${AGENTHOUND_CROSS_SERVICE_PROOF:?missing cross-service proof fixture}"
jq -e \
  --arg url "${contextforge_url}" \
  --arg authorization "Bearer ${contextforge_token}" \
  --arg cross_authorization "Bearer ${AGENTHOUND_LITELLM_MASTER_KEY}" \
  --arg cross_proof "${AGENTHOUND_CROSS_SERVICE_PROOF}" \
  '.mcpServers["contextforge-real"] == {
    url:$url,
    headers:{Authorization:$authorization}
  } and .mcpServers["litellm-master-gated-everything"] == {
    url:"http://mcp-cross-service-gate:3003/mcp",
    headers:{
      Authorization:$cross_authorization,
      "X-AgentHound-Secret":$cross_proof
    }
  } and .mcpServers["everything-disabled"].disabled == true' \
  /root/.cursor/mcp.json >/dev/null
grep -qx 'schema: v1' /root/.continue/config.yaml
grep -qx '    command: /usr/local/bin/mcp-server-everything' /root/.continue/config.yaml
grep -qx '      - stdio' /root/.continue/config.yaml
SH
pass upstream:client-config-corpus

a2a_upstream_truth="$(jq -cn \
  --argjson static_current "${a2a_static_current_card}" \
  --argjson static_legacy "${a2a_static_legacy_card}" \
  --argjson dynamic_v1 "${a2a_dynamic_v1_card}" \
  --argjson dynamic_v03 "${a2a_dynamic_v03_card}" \
  --argjson dynamic_protected "${a2a_dynamic_protected_card}" \
  --argjson dynamic_ambiguous "${a2a_dynamic_ambiguous_card}" \
  --arg static_legacy_current_status "${legacy_current_status}" \
  --arg dynamic_legacy_current_status "${dynamic_legacy_current_status}" \
  --argjson v1_response "${a2a_v1_response}" \
  --argjson v03_response "${a2a_v03_response}" \
  --arg protected_anonymous_status "${a2a_protected_status}" \
  --argjson protected_control "${a2a_protected_control}" \
  --argjson ambiguous_response "${a2a_ambiguous_response}" \
  --argjson handler_counters "${a2a_probe_state}" \
  '{
    agents: ([
      $static_current.name,
      $static_legacy.name,
      $dynamic_v1.name,
      $dynamic_v03.name,
      $dynamic_protected.name,
      $dynamic_ambiguous.name
    ] | sort),
    cards: {
      static_current: {
        name: $static_current.name,
        protocol_versions: [$static_current.supportedInterfaces[].protocolVersion],
        signature_count: ($static_current.signatures | length)
      },
      static_legacy: {
        name: $static_legacy.name,
        protocol_version: $static_legacy.protocolVersion
      },
      sdk_v1: {
        name: $dynamic_v1.name,
        protocol_versions: ([$dynamic_v1.supportedInterfaces[].protocolVersion] | sort)
      },
      sdk_v0_3: {
        name: $dynamic_v03.name,
        protocol_version: $dynamic_v03.protocolVersion
      },
      protected: {
        name: $dynamic_protected.name,
        protocol_versions: [$dynamic_protected.supportedInterfaces[].protocolVersion],
        security_requirement_schemes: ($dynamic_protected.securityRequirements[0].schemes | keys | sort)
      },
      ambiguous: {
        name: $dynamic_ambiguous.name,
        protocol_versions: [$dynamic_ambiguous.supportedInterfaces[].protocolVersion]
      }
    },
    legacy_fallback: {
      static_current_path_status: ($static_legacy_current_status | tonumber),
      sdk_current_path_status: ($dynamic_legacy_current_status | tonumber)
    },
    protocol_controls: {
      v1_anonymous: {
        method: "GetTask",
        response_id: $v1_response.id,
        error_code: $v1_response.error.code,
        error_message: $v1_response.error.message,
        error_reason: $v1_response.error.data[0].reason,
        error_domain: $v1_response.error.data[0].domain
      },
      v0_3_anonymous: {
        method: "tasks/get",
        response_id: $v03_response.id,
        error_code: $v03_response.error.code,
        error_message: $v03_response.error.message,
        error_data: $v03_response.error.data
      },
      protected_anonymous: {
        method: "GetTask",
        http_status: ($protected_anonymous_status | tonumber)
      },
      protected_exact_key: {
        method: "GetTask",
        response_id: $protected_control.id,
        error_code: $protected_control.error.code,
        error_message: $protected_control.error.message,
        error_reason: $protected_control.error.data[0].reason
      },
      ambiguous_version: {
        method: "GetTask",
        response_id: $ambiguous_response.id,
        error_code: $ambiguous_response.error.code,
        error_message: $ambiguous_response.error.message,
        error_reason: $ambiguous_response.error.data[0].reason
      }
    },
    handler_counters_after_upstream_controls: $handler_counters,
    static_signature_independently_verified: true
  }')"

jq -n \
  --arg verified_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg contextforge_server_id "${contextforge_server_id}" \
  --arg contextforge_resource_id "${contextforge_resource_id}" \
  --arg contextforge_tool_id "${contextforge_tool_id}" \
  --argjson a2a_upstream_truth "${a2a_upstream_truth}" \
  '{
    status:"valid",
    verified_at:$verified_at,
    source:"independent upstream APIs; no AgentHound output consumed",
    services:{
      ollama:{models:[{
        name:"qwen2:0.5b",
        digest:"6f48b936a09f7743c7dd30e72fdb14cba296bc5861902e4d0c387e8fb5050b39"
      }]},
      vllm:{models:["agenthound-vllm-fixture"]},
      openai_decoy:{implementation:"LiteLLM",models:["agenthound-openai-compatible-decoy"]},
      qdrant:{collections:["chat-history","docs"],points_per_collection:2},
      mlflow:{experiment:"agenthound-offline-qa",runs:1,model:"agenthound-fixture-model"},
      jupyter:{authentication:"token",files:["work/agenthound-fixtures/agenthound-fixture.ipynb","work/agenthound-fixtures/data/support-context.md"]},
      openwebui:{authentication:"session JWT",openai_upstreams:1,ollama_upstreams:1},
      mcp_everything:{
        version:"2026.7.4",
        transports:["stdio","streamableHttp","sse"],
        enforcing_gates:["basic_query","bearer_and_proof_headers"]
      },
      a2a:$a2a_upstream_truth,
      contextforge:{version:"1.0.5",server_id:$contextforge_server_id,tool_id:$contextforge_tool_id,resource_id:$contextforge_resource_id,credential_gate:true}
    }
  }' >"${TRUTH_PATH}.tmp"
mv "${TRUTH_PATH}.tmp" "${TRUTH_PATH}"

printf 'Independent upstream truth checks passed.\n'
