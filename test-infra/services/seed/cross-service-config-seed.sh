#!/bin/sh
set -eu

: "${AGENTHOUND_LITELLM_MASTER_KEY:?missing LiteLLM master fixture}"
: "${AGENTHOUND_CROSS_SERVICE_PROOF:?missing cross-service proof fixture}"

config=/root/.cursor/mcp.json
rendered="$(mktemp)"
trap 'rm -f "${rendered}"' EXIT HUP INT TERM

# This file is the real client input under test. The values exist only in the
# disposable workstation; config collection must emit hashes and must never
# retain the raw headers in its artifact.
jq \
  --arg authorization "Bearer ${AGENTHOUND_LITELLM_MASTER_KEY}" \
  --arg proof "${AGENTHOUND_CROSS_SERVICE_PROOF}" '
  .mcpServers["litellm-master-gated-everything"] = {
    url:"http://mcp-cross-service-gate:3003/mcp",
    headers:{
      Authorization:$authorization,
      "X-AgentHound-Secret":$proof
    }
  }
' "${config}" >"${rendered}"
mv "${rendered}" "${config}"
trap - EXIT HUP INT TERM

printf 'Seeded credential-correlated MCP client configuration.\n'
