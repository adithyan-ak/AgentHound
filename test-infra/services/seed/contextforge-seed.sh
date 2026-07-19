#!/bin/sh
set -eu

base=http://contextforge:4444
api=${base}/v1
runtime=/root/fixtures/runtime.json
email=admin@agenthound.invalid
password='Harness-Admin-Password-2026!'

login_response="$(curl -fsS -X POST "${base}/auth/login" \
  -H 'Content-Type: application/json' \
  --data "$(jq -nc --arg username "${email}" --arg password "${password}" \
    '{username:$username,password:$password}')")"
token="$(printf '%s' "${login_response}" | jq -er '.access_token // .token')"

api_get() {
  curl -fsS -H "Authorization: Bearer ${token}" "${api}$1"
}

api_post() {
  curl -fsS -X POST \
    -H "Authorization: Bearer ${token}" \
    -H 'Content-Type: application/json' \
    --data "$2" "${api}$1"
}

api_delete() {
  curl -fsS -X DELETE \
    -H "Authorization: Bearer ${token}" \
    "${api}$1" >/dev/null
}

tool_id="$(api_get /tools | jq -r '[.. | objects | select(.name? == "support-lookup")][0].id // empty')"
if [ -z "${tool_id}" ]; then
  tool_body="$(jq -nc '{tool:{
    name:"support_lookup",
    url:"http://langserve:8000/echo/invoke",
    description:"Look up a customer support case by case ID.",
    integration_type:"REST",
    request_type:"POST",
    input_schema:{type:"object",properties:{case_id:{type:"string"}},required:["case_id"]}
  }}')"
  tool_id="$(api_post /tools "${tool_body}" | jq -er '.id')"
fi

resource_id="$(api_get /resources | jq -r '[.. | objects | select(.uri? == "file:///data/support-cases/case-001.json")][0].id // empty')"
if [ -z "${resource_id}" ]; then
  resource_body="$(jq -nc '{resource:{
    uri:"file:///data/support-cases/case-001.json",
    name:"support-case-001",
    description:"A deterministic support case used by the compatibility harness.",
    mimeType:"application/json",
    content:"{\"case_id\":\"case-001\",\"status\":\"open\"}"
  }}')"
  resource_id="$(api_post /resources "${resource_body}" | jq -er '.id')"
fi

server_id="$(api_get /servers | jq -r '[.. | objects | select(.name? == "agenthound-harness")][0].id // empty')"
if [ -z "${server_id}" ]; then
  server_body="$(jq -nc \
    --arg tool_id "${tool_id}" \
    --arg resource_id "${resource_id}" \
    '{server:{
      name:"agenthound-harness",
      description:"Real ContextForge virtual server for collector compatibility checks.",
      associated_tools:[$tool_id],
      associated_resources:[$resource_id]
    }}')"
  server_id="$(api_post /servers "${server_body}" | jq -er '.id')"
fi

mcp_url="${base}/servers/${server_id}/mcp"
tool="$(api_get "/tools/${tool_id}")"
resource="$(api_get "/resources/${resource_id}")"
server="$(api_get "/servers/${server_id}")"

# MCP authentication in ContextForge v1.0.5 uses a catalog API token rather
# than the short-lived browser/provider session JWT. The raw token is returned
# only once, and deleted token names remain reserved. Reuse the retained raw
# token while it is active; on recovery, revoke any active fixture tokens and
# create one with a fresh name instead of inventing unsupported token rotation.
stored_mcp_token="$(jq -r '.contextforge.token // empty' "${runtime}" 2>/dev/null || true)"
stored_mcp_token_id="$(jq -r '.contextforge.token_id // empty' "${runtime}" 2>/dev/null || true)"
mcp_token=
mcp_token_id=

if [ -n "${stored_mcp_token}" ] && [ -n "${stored_mcp_token_id}" ]; then
  active_stored_id="$(api_get /tokens | jq -r --arg id "${stored_mcp_token_id}" \
    '[.. | objects | select(.id? == $id and .is_active? == true and (.is_revoked? // false) == false)][0].id // empty')"
  if [ "${active_stored_id}" = "${stored_mcp_token_id}" ] && \
    curl -fsS -H "Authorization: Bearer ${stored_mcp_token}" "${api}/version" >/dev/null; then
    mcp_token="${stored_mcp_token}"
    mcp_token_id="${stored_mcp_token_id}"
  fi
fi

if [ -z "${mcp_token}" ]; then
  for token_id in $(api_get /tokens | jq -r \
    '[.. | objects | select((.name? // "") | startswith("agenthound-harness-mcp-")) | select(.is_active? == true) | .id] | .[]'); do
    api_delete "/tokens/${token_id}"
  done

  token_suffix="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  token_body="$(jq -nc --arg name "agenthound-harness-mcp-${token_suffix}" '{
    name:$name,
    description:"Offline harness MCP and management access.",
    expires_in_days:1,
    scope:{permissions:["*"]}
  }')"
  token_response="$(api_post /tokens "${token_body}")"
  mcp_token="$(printf '%s' "${token_response}" | jq -er '.access_token')"
  mcp_token_id="$(printf '%s' "${token_response}" | jq -er '.token.id')"
fi

jq -n \
  --arg token "${mcp_token}" \
  --arg token_id "${mcp_token_id}" \
  --arg mcp_url "${mcp_url}" \
  --arg tool_id "${tool_id}" \
  --arg resource_id "${resource_id}" \
  --arg server_id "${server_id}" \
  --argjson tool "${tool}" \
  --argjson resource "${resource}" \
  --argjson server "${server}" \
  '{contextforge:{
    token:$token,
    token_id:$token_id,
    mcp_url:$mcp_url,
    tool_id:$tool_id,
    resource_id:$resource_id,
    server_id:$server_id,
    tool:$tool,
    resource:$resource,
    server:$server
  }}' >"${runtime}.tmp"
mv "${runtime}.tmp" "${runtime}"

jq --arg url "${mcp_url}" --arg token "${mcp_token}" \
  '.mcpServers["contextforge-real"] = {
    url:$url,
    headers:{Authorization:("Bearer " + $token)}
  }' /root/.cursor/mcp.json >/tmp/cursor-mcp.json
mv /tmp/cursor-mcp.json /root/.cursor/mcp.json

printf 'Seeded ContextForge server %s.\n' "${server_id}"
